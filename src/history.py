"""
Точечная догрузка истории чата личным аккаунтом (Telethon).

В отличие от прежнего collector.py: не висит постоянным процессом и не
слушает новые сообщения. Подключается только на время одного вызова
import_history(), догружает то, чего ещё нет в базе, и отключается. Основной
(live) сбор теперь ведёт bot.py через Bot API — см. CLAUDE.md.

Session-файл должен быть уже авторизован заранее и вручную (код + 2FA в
консоли). Интерактивный логин отсюда не делаем — это дёргается из процесса
бота, где логиниться и небезопасно, и бессмысленно (Telegram блокирует коды,
пересланные в самом Telegram).
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

from telethon import TelegramClient, utils
from telethon.errors import FloodWaitError

import crypto
import db

logging.basicConfig(level=logging.INFO)

SESSION_NAME = os.getenv("TG_SESSION", "history_session")
API_ID = int(os.getenv("TG_API_ID", "0") or 0)
API_HASH = os.getenv("TG_API_HASH", "")

# Трюк, который решил проблему с блокировкой MTProto у провайдера: маскирует
# клиент под официальное приложение Telegram. См. CLAUDE.md, «костыли».
SYSTEM_VERSION = "4.16.30-vxCUSTOM"


class NeedsReauthError(RuntimeError):
    """Session-файл не авторизован — нужна ручная ре-авторизация в консоли."""


def _msg_type(message) -> str:
    # ВАЖНО: медиа проверяется раньше text — у Telethon message.text отдаёт
    # и обычный текст, и подпись к фото/видео. Тот же порядок, что в bot.py.
    if message.photo:
        return "photo"
    if message.sticker:
        return "sticker"
    if message.video:
        return "video"
    if message.voice:
        return "voice"
    if message.media:
        return "other_media"
    if message.text:
        return "text"
    return "other"


def _sender_fields(sender):
    username = getattr(sender, "username", None)
    full_name = " ".join(
        filter(None, [getattr(sender, "first_name", None), getattr(sender, "last_name", None)])
    ) or None
    return username, full_name


def _chat_title(entity) -> str:
    title = getattr(entity, "title", None)
    if title:
        return title
    name = " ".join(
        filter(None, [getattr(entity, "first_name", None), getattr(entity, "last_name", None)])
    )
    return name or str(utils.get_peer_id(entity))


def _save_message(cur, chat_id, message, sender) -> None:
    dt = message.date
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    username, full_name = _sender_fields(sender)

    raw_text = message.text or ""
    text_encrypted = crypto.encrypt(raw_text) if raw_text else ""

    db.upsert_message(
        cur,
        message_id=message.id,
        chat_id=chat_id,
        user_id=message.sender_id,
        username=username,
        full_name=full_name,
        text_encrypted=text_encrypted,
        msg_type=_msg_type(message),
        dt=dt.isoformat(),
        weekday=dt.weekday(),
        hour=dt.hour,
        source="history",
    )

    if message.reactions and message.reactions.results:
        count = sum(r.count for r in message.reactions.results)
        db.upsert_reaction(cur, chat_id=chat_id, user_id=message.sender_id,
                            timestamp=dt.isoformat(), count=count, updated_at=dt.isoformat())


async def import_history(chat_id, progress_callback=None) -> dict:
    """Догружает историю чата chat_id личным аккаунтом — только то, что старше
    самого раннего уже собранного сообщения (см. границу ниже).

    progress_callback, если задан, — async-функция, её ждут (await) с
    текущим количеством обработанных сообщений; так bot.py транслирует
    прогресс в чат по ходу импорта, не блокируя цикл.

    Возвращает {"total": ..., "with_reactions": ...}.
    Бросает NeedsReauthError, если сессия не авторизована, и RuntimeError, если
    не заданы TG_API_ID/TG_API_HASH.
    """
    if not (API_ID and API_HASH):
        raise RuntimeError("Заполни TG_API_ID и TG_API_HASH в .env — см. .env.example")

    client = TelegramClient(
        str(db.DATA_DIR / SESSION_NAME),
        API_ID,
        API_HASH,
        system_version=SYSTEM_VERSION,
    )

    await client.connect()
    try:
        if not await client.is_user_authorized():
            raise NeedsReauthError(
                "Сессия личного аккаунта не авторизована — нужна ре-авторизация "
                "в консоли (см. README). Логин через бота не делаем."
            )

        entity = await client.get_entity(chat_id)
        # Приводим id к тому же виду, в котором его видит Bot API — иначе
        # один чат раздвоится в данных между bot.py и history.py.
        normalized_chat_id = utils.get_peer_id(entity)

        with db.get_conn() as conn:
            cur = conn.cursor()
            db.upsert_chat(
                cur, chat_id=normalized_chat_id, title=_chat_title(entity),
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
            earliest_ts = db.earliest_message_timestamp(conn, normalized_chat_id)

        # AAB-17 (корневой фикс дублей): граница возобновления — timestamp
        # самого раннего уже собранного сообщения, не message_id. В базовых
        # (не супер-) группах Bot API и Telethon не делят единую нумерацию
        # message_id — одно и то же сообщение получает разные message_id в
        # двух системах, поэтому старый min_id=last_message_id() не защищал
        # от повторного импорта того же периода, что уже живьём собрал
        # bot.py (см. CLAUDE.md, инцидент AAB-17). timestamp совпадает в
        # обеих системах всегда — offset_date гарантирует, что
        # /import_history никогда не заходит в диапазон новее того, что уже
        # есть в базе, откуда бы он ни взялся (живой сбор или прошлый импорт).
        offset_date = datetime.fromisoformat(earliest_ts) if earliest_ts else None
        if offset_date:
            logging.info("В базе уже есть сообщения с %s, догружаю только то, что старше", earliest_ts)
        else:
            logging.info("Загружаю историю чата с нуля (это может занять время)...")

        total = 0
        with_reactions = 0

        with db.get_conn() as conn:
            cur = conn.cursor()
            async for message in client.iter_messages(entity, limit=None, offset_date=offset_date):
                if not message.sender_id:
                    continue  # системные сообщения без автора пропускаем

                try:
                    sender = await message.get_sender()
                except FloodWaitError as exc:
                    logging.warning("Flood wait, жду %s секунд", exc.seconds)
                    await asyncio.sleep(exc.seconds)
                    sender = await message.get_sender()

                _save_message(cur, normalized_chat_id, message, sender)
                total += 1
                if message.reactions and message.reactions.results:
                    with_reactions += 1

                if total % 500 == 0:
                    conn.commit()
                    if progress_callback:
                        await progress_callback(total)

            conn.commit()

        if progress_callback:
            await progress_callback(total)

        logging.info(
            "История актуальна, добавлено новых сообщений: %s (с реакциями: %s)",
            total, with_reactions,
        )
        return {"total": total, "with_reactions": with_reactions}
    finally:
        await client.disconnect()
