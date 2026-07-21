"""
Постоянный сбор активности через Bot API (aiogram). Основной механизм сбора —
живёт в чате и слушает апдейты. Выбор чата динамический через команды,
фиксированного TG_CHAT в .env больше нет. Долгую догрузку истории назад
делает history.py (личный аккаунт), сюда встроена только фоновая обвязка
для команды /import_history.

Long polling — фаза 1 (локальный запуск). Хендлеры не завязаны на транспорт,
переход на webhook в фазе 2 не должен требовать их переписывания.

Запуск: python bot.py
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from aiogram import Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramForbiddenError
from aiogram.filters import Command, CommandObject
from aiogram.types import (
    CallbackQuery,
    ChatMemberUpdated,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

import crypto
import db
import history

logging.basicConfig(level=logging.INFO)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
OWNER_USER_ID = int(os.getenv("OWNER_USER_ID", "0") or 0)
DASHBOARD_BASE_URL = os.getenv("DASHBOARD_BASE_URL", "https://anex-analyst-bot.fly.dev").rstrip("/")

GROUP_TYPES = {"group", "supergroup"}

router = Router()

# chat_id, для которых сейчас выполняется /import_history — защита от
# повторного запуска, пока предыдущий импорт того же чата ещё не закончился.
_imports_in_progress: set[int] = set()

# Event loop хранит на задачу только слабую ссылку — без своей сильной ссылки
# фоновая asyncio.create_task() может быть собрана сборщиком мусора прямо
# посреди выполнения (реально воспроизвелось при живом тесте /import_history).
_background_tasks: set[asyncio.Task] = set()


# ---------- Классификация сообщений ----------
# У Bot API text и caption — разные поля (в отличие от Telethon, где message.text
# отдаёт и то, и другое сразу), поэтому content_type сам по себе уже не путает
# подпись к фото с обычным текстом. Тот же принцип, что в history.py
# («медиа определяется по факту, а не по наличию текстоподобного поля»),
# просто выражен по-другому под структуру Bot API.

_DIRECT_TYPES = {"text", "photo", "sticker", "video", "voice"}
_OTHER_MEDIA_TYPES = {"document", "audio", "video_note", "animation"}


def _msg_type(message: Message) -> str:
    content_type = message.content_type
    if content_type in _DIRECT_TYPES:
        return content_type
    if content_type in _OTHER_MEDIA_TYPES:
        return "other_media"
    return "other"


def _message_text(message: Message) -> str:
    return message.text or message.caption or ""


def _sender_fields(user):
    full_name = " ".join(filter(None, [user.first_name, user.last_name])) or None
    return user.username, full_name


def _save_message(cur, message: Message) -> None:
    user = message.from_user
    if not user:
        return  # анонимные админы / служебные сообщения без автора пропускаем

    dt = message.date
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    username, full_name = _sender_fields(user)

    raw_text = _message_text(message)
    text_encrypted = crypto.encrypt(raw_text) if raw_text else ""

    db.upsert_message(
        cur,
        message_id=message.message_id,
        chat_id=message.chat.id,
        user_id=user.id,
        username=username,
        full_name=full_name,
        text_encrypted=text_encrypted,
        msg_type=_msg_type(message),
        dt=dt.isoformat(),
        weekday=dt.weekday(),
        hour=dt.hour,
    )


async def _can_manage_collection(bot: Bot, chat_id: int, user_id: int) -> bool:
    # Владелец деплоя может управлять сбором в любом чате, даже не будучи
    # там админом — иначе он не смог бы включить/выключить сбор в чужой
    # группе, где сам является рядовым участником.
    if user_id == OWNER_USER_ID:
        return True
    member = await bot.get_chat_member(chat_id, user_id)
    return member.status in ("administrator", "creator")


async def _send_dashboard_token_message(
    bot: Bot, user_id: int, chat_id: int, chat_title, token: str, *, reissued: bool
) -> bool:
    # AAB-12: ссылка идёт в личку — токен персональный (пара чат+пользователь),
    # показывать его в групповом чате бессмысленно и небезопасно, его должен
    # видеть только тот, кому он принадлежит. Возвращает False, если бот не
    # может написать первым (пользователь не начинал диалог с ним).
    # URL несёт только токен, без chat_id/user_id (AAB-10 — не светить лишние
    # идентификаторы в адресной строке/логах); дашборд находит чат сам по
    # токену (db.get_chat_id_by_dashboard_token).
    link = f"{DASHBOARD_BASE_URL}/?token={token}"
    title = chat_title or str(chat_id)
    verb = "Новая ссылка на дашборд" if reissued else "Ссылка на дашборд"
    text = (
        f"🔗 {verb} чата «{title}»:\n{link}\n\n"
        "Ссылка персональная — она открывает только данные этого чата, только "
        "для тебя. Никому её не пересылай. Если она потеряется или будет "
        "кем-то расшарена — перевыпусти командой:\n/dashboard\n"
        "Старая сразу перестанет работать."
    )
    try:
        await bot.send_message(user_id, text)
        return True
    except TelegramForbiddenError:
        return False


# ---------- Команды в группе ----------

@router.message(Command("activate"), F.chat.type.in_(GROUP_TYPES))
async def cmd_activate(message: Message, bot: Bot) -> None:
    if not await _can_manage_collection(bot, message.chat.id, message.from_user.id):
        await message.reply("Включить сбор активности может только админ этого чата.")
        return

    with db.get_conn() as conn:
        already_active = db.is_chat_active(conn, message.chat.id)
    if already_active:
        # Повторный /activate — типичная путаница: без этой ветки бот молча
        # присылал бы то же самое "Запущен сбор...", как будто только что
        # включил, хотя сбор и так уже шёл.
        await message.reply(
            "Бот уже запущен и собирает статистику в этом чате. Чтобы отключить:\n/deactivate"
        )
        return

    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        db.activate_chat(
            conn, chat_id=message.chat.id, title=message.chat.title,
            activated_by=message.from_user.id, activated_at=now,
        )
        token = db.get_or_create_dashboard_token(
            conn, message.chat.id, message.from_user.id, created_at=now,
        )

    sent = await _send_dashboard_token_message(
        bot, message.from_user.id, message.chat.id, message.chat.title, token, reissued=False,
    )
    if sent:
        await message.reply("📊 Запущен сбор статистики чата. Ссылка на дашборд отправлена вам в личку.")
    else:
        await message.reply(
            "📊 Запущен сбор статистики чата.\n\n"
            "⚠️ Не получилось отправить ссылку на дашборд в личку — сначала "
            "напиши мне (боту) любое сообщение в личных сообщениях, затем повтори:\n/activate"
        )


@router.message(Command("deactivate"), F.chat.type.in_(GROUP_TYPES))
async def cmd_deactivate(message: Message, bot: Bot) -> None:
    if not await _can_manage_collection(bot, message.chat.id, message.from_user.id):
        await message.reply("Выключить сбор активности может только админ этого чата.")
        return
    with db.get_conn() as conn:
        db.deactivate_chat(
            conn, chat_id=message.chat.id,
            deactivated_at=datetime.now(timezone.utc).isoformat(),
        )
        # Отклонение от исходного AAB-12 («на токены не влияет») — по
        # запросу пользователя: /deactivate теперь ещё и отзывает все ссылки
        # на дашборд этого чата, чтобы дать быстрый контроль в критичной
        # ситуации (например, подозрение на утечку) без отдельного
        # /revoke_token для каждого. Данные messages/reactions не трогает.
        affected = db.revoke_dashboard_tokens_for_chat(conn, message.chat.id)

    label = message.chat.title or str(message.chat.id)
    for uid in affected:
        try:
            await bot.send_message(
                uid,
                f"🚫 Сбор активности в чате «{label}» остановлен — доступ к дашборду тоже "
                "отозван. Если сбор снова включат — ссылку нужно будет получить заново, командой:\n/dashboard"
            )
        except TelegramForbiddenError:
            pass  # не удалось уведомить — не критично, сама ссылка всё равно уже не работает

    await message.reply("Сбор статистики чата завершён — бот в чате отключён.")


@router.message(Command("status"), F.chat.type.in_(GROUP_TYPES))
async def cmd_status(message: Message) -> None:
    with db.get_conn() as conn:
        active = db.is_chat_active(conn, message.chat.id)
    await message.reply("✅ Сбор активности сейчас идёт." if active else "⏸ Сбор активности сейчас не идёт.")


# ---------- Команды в личке (любой пользователь) ----------

_DASHBOARD_CALLBACK_PREFIX = "dashboard_chat:"


async def _issue_and_send_dashboard_token(bot: Bot, user_id: int, chat_id: int) -> bool:
    # AAB-12: первый вызов /dashboard создаёт токен, повторный — перевыпускает
    # (старый сразу недействителен). Отличаем по факту, был ли уже токен.
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        title = db.chat_title(conn, chat_id)
        is_first = db.get_dashboard_token(conn, chat_id, user_id) is None
        if is_first:
            token = db.get_or_create_dashboard_token(conn, chat_id, user_id, created_at=now)
        else:
            token = db.reissue_dashboard_token(conn, chat_id, user_id, created_at=now)
    return await _send_dashboard_token_message(bot, user_id, chat_id, title, token, reissued=not is_first)


@router.message(Command("dashboard"), F.chat.type == "private")
async def cmd_dashboard(message: Message, bot: Bot) -> None:
    user_id = message.from_user.id
    with db.get_conn() as conn:
        chats = db.chats_for_user(conn, user_id)

    if not chats:
        await message.answer(
            "Не нашёл чатов, где ты участвуешь и идёт (или шёл) сбор активности."
        )
        return

    if len(chats) == 1:
        chat_id, _ = chats[0]
        sent = await _issue_and_send_dashboard_token(bot, user_id, chat_id)
        if not sent:
            await message.answer(
                "⚠️ Не получилось отправить ссылку — но ты уже пишешь мне в личку, "
                "так что просто повтори:\n/dashboard"
            )
        return

    buttons = [
        [InlineKeyboardButton(text=title or str(chat_id), callback_data=f"{_DASHBOARD_CALLBACK_PREFIX}{chat_id}")]
        for chat_id, title in chats
    ]
    await message.answer(
        "Ты участвуешь в нескольких чатах со сбором активности — выбери, для какого нужна ссылка:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


@router.callback_query(F.data.startswith(_DASHBOARD_CALLBACK_PREFIX))
async def on_dashboard_chat_chosen(callback: CallbackQuery, bot: Bot) -> None:
    user_id = callback.from_user.id
    chat_id = int(callback.data[len(_DASHBOARD_CALLBACK_PREFIX):])

    # Перепроверяем принадлежность на момент клика, а не доверяем callback_data
    # как таковой — данные в кнопке в принципе может подменить нестандартный клиент.
    with db.get_conn() as conn:
        allowed_chat_ids = {cid for cid, _ in db.chats_for_user(conn, user_id)}
    if chat_id not in allowed_chat_ids:
        await callback.answer("Этот чат тебе недоступен.", show_alert=True)
        return

    sent = await _issue_and_send_dashboard_token(bot, user_id, chat_id)
    await callback.answer()
    if sent:
        await callback.message.edit_text("🔗 Ссылка отправлена тебе в личку.")
    else:
        await callback.message.edit_text("⚠️ Не получилось отправить сообщение — попробуй ещё раз чуть позже.")


# ---------- Команды в личке владельца ----------

@router.message(Command("chats"), F.chat.type == "private")
async def cmd_chats(message: Message) -> None:
    if message.from_user.id != OWNER_USER_ID:
        return
    with db.get_conn() as conn:
        chats = db.list_chats(conn)
        rows = [(chat_id, title, db.is_chat_active(conn, chat_id)) for chat_id, title in chats]
    if not rows:
        await message.answer("Пока нет ни одного чата в базе.")
        return
    lines = [
        f"{'🟢' if active else '⚪️'} {title or chat_id} — {chat_id}"
        for chat_id, title, active in rows
    ]
    await message.answer("\n".join(lines))


def _parse_chat_user_args(args):
    """`<chat_id> [user_id]` — используется /revoke_token и /access_token.
    Возвращает (chat_id, user_id|None) или None при ошибке разбора."""
    if not args:
        return None
    parts = args.split()
    if len(parts) not in (1, 2):
        return None
    try:
        chat_id = int(parts[0])
        user_id = int(parts[1]) if len(parts) == 2 else None
    except ValueError:
        return None
    return chat_id, user_id


async def _grant_and_send_dashboard_token(bot: Bot, user_id: int, chat_id: int) -> bool:
    # /access_token — выдача доступа владельцем: создаёт токен, только если
    # его ещё нет, не перевыпускает уже выданный. Повторный массовый грант
    # не должен молча ломать уже разосланные ссылки тем, у кого доступ уже был.
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        title = db.chat_title(conn, chat_id)
        token = db.get_or_create_dashboard_token(conn, chat_id, user_id, created_at=now)
    return await _send_dashboard_token_message(bot, user_id, chat_id, title, token, reissued=False)


@router.message(Command("revoke_token"), F.chat.type == "private")
async def cmd_revoke_token(message: Message, bot: Bot, command: CommandObject) -> None:
    if message.from_user.id != OWNER_USER_ID:
        return
    parsed = _parse_chat_user_args(command.args)
    if parsed is None:
        await message.answer("Укажи:\n/revoke_token <chat_id> [user_id]\n\nСписок чатов:\n/chats")
        return
    chat_id, user_id = parsed

    with db.get_conn() as conn:
        title = db.chat_title(conn, chat_id)
        if user_id is None:
            affected = db.revoke_dashboard_tokens_for_chat(conn, chat_id)
        else:
            affected = [user_id] if db.revoke_dashboard_token_for_user(conn, chat_id, user_id) else []

    if not affected:
        await message.answer("Не нашёл токенов для отзыва — доступ уже не выдан никому из указанных.")
        return

    label = title or str(chat_id)
    notified, failed = [], []
    for uid in affected:
        try:
            await bot.send_message(uid, f"🚫 Владелец отозвал твой доступ к дашборду чата «{label}».")
            notified.append(uid)
        except TelegramForbiddenError:
            failed.append(uid)

    report = f"Отозвано токенов: {len(affected)}. Уведомлены в личке: {len(notified)}."
    if failed:
        report += f"\nНе удалось уведомить (нет диалога в личке с ботом): {', '.join(map(str, failed))}."
    await message.answer(report)


@router.message(Command("access_token"), F.chat.type == "private")
async def cmd_access_token(message: Message, bot: Bot, command: CommandObject) -> None:
    if message.from_user.id != OWNER_USER_ID:
        return
    parsed = _parse_chat_user_args(command.args)
    if parsed is None:
        await message.answer("Укажи:\n/access_token <chat_id> [user_id]\n\nСписок чатов:\n/chats")
        return
    chat_id, user_id = parsed

    with db.get_conn() as conn:
        title = db.chat_title(conn, chat_id)
        target_user_ids = [user_id] if user_id is not None else db.chat_participant_user_ids(conn, chat_id)

    if not target_user_ids:
        await message.answer("Не нашёл ни одного участника этого чата в собранных данных.")
        return

    sent, failed = [], []
    for uid in target_user_ids:
        ok = await _grant_and_send_dashboard_token(bot, uid, chat_id)
        (sent if ok else failed).append(uid)

    label = title or str(chat_id)
    report = f"Чат «{label}»: ссылку получили {len(sent)} из {len(target_user_ids)}."
    if failed:
        report += f"\nНе удалось отправить (нет диалога в личке с ботом): {', '.join(map(str, failed))}."
    await message.answer(report)


@router.message(Command("import_history"), F.chat.type == "private")
async def cmd_import_history(message: Message, command: CommandObject) -> None:
    if message.from_user.id != OWNER_USER_ID:
        return
    if not command.args:
        await message.answer("Укажи chat_id:\n/import_history <chat_id>\n\nСписок чатов:\n/chats")
        return
    try:
        chat_id = int(command.args.strip())
    except ValueError:
        await message.answer("chat_id должен быть числом. Список чатов:\n/chats")
        return

    if chat_id in _imports_in_progress:
        await message.answer("Импорт для этого чата уже идёт.")
        return

    _imports_in_progress.add(chat_id)
    status_msg = await message.answer(f"⏳ Импорт истории чата {chat_id} начат...")

    async def progress(total: int) -> None:
        try:
            await status_msg.edit_text(f"⏳ Импортировано сообщений: {total}")
        except Exception:
            pass  # например, "message is not modified" — не критично

    async def run() -> None:
        try:
            result = await history.import_history(chat_id, progress_callback=progress)
            await status_msg.edit_text(
                f"✅ Импорт истории чата {chat_id} завершён.\n"
                f"\n"
                f"📨 Новых сообщений: {result['total']}\n"
                f"   └ с реакциями: {result['with_reactions']}\n"
                f"\n"
                f"❤️ Реакции за последние {history.REACTION_RESYNC_LOOKBACK_DAYS} дн.: "
                f"{result['reactions_resynced']} сообщений с реакциями сейчас в базе\n"
                f"   └ это снимок на текущий момент, а не «сколько изменилось» с прошлого запуска"
            )
        except history.NeedsReauthError as exc:
            await message.answer(f"❌ {exc}")
        except Exception as exc:
            logging.exception("Ошибка импорта истории чата %s", chat_id)
            await message.answer(f"❌ Импорт истории упал: {exc}")
        finally:
            _imports_in_progress.discard(chat_id)

    task = asyncio.create_task(run())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


# ---------- Служебные апдейты и сбор ----------

@router.my_chat_member()
async def on_my_chat_member(event: ChatMemberUpdated) -> None:
    if event.new_chat_member.status in ("left", "kicked"):
        with db.get_conn() as conn:
            db.deactivate_chat(
                conn, chat_id=event.chat.id,
                deactivated_at=datetime.now(timezone.utc).isoformat(),
            )


@router.message(F.chat.type.in_(GROUP_TYPES))
async def collect_message(message: Message) -> None:
    with db.get_conn() as conn:
        if not db.is_chat_active(conn, message.chat.id):
            return
        cur = conn.cursor()
        _save_message(cur, message)


async def main() -> None:
    if not crypto.has_key():
        raise SystemExit(
            "DB_ENCRYPTION_KEY не задан. Бот — долгоживущий процесс без stdin, "
            "поэтому DB_ENCRYPTION_SALT (пароль через getpass) здесь не работает. "
            "Сгенерируй ключ: python generate_key.py — и пропиши в .env."
        )
    if not BOT_TOKEN:
        raise SystemExit("Заполни BOT_TOKEN в .env (получить у @BotFather).")
    if not OWNER_USER_ID:
        raise SystemExit("Заполни OWNER_USER_ID в .env — твой numeric Telegram user id.")

    db.init_db()
    logging.info("База данных: %s", db.DB_PATH)

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    logging.info("Бот запущен, жду апдейтов (long polling)...")
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Остановлено пользователем")
