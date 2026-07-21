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
from aiogram.filters import Command, CommandObject
from aiogram.types import ChatMemberUpdated, Message

import crypto
import db
import history

logging.basicConfig(level=logging.INFO)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
OWNER_USER_ID = int(os.getenv("OWNER_USER_ID", "0") or 0)

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


# ---------- Команды в группе ----------

@router.message(Command("activate"), F.chat.type.in_(GROUP_TYPES))
async def cmd_activate(message: Message, bot: Bot) -> None:
    if not await _can_manage_collection(bot, message.chat.id, message.from_user.id):
        await message.reply("Включить сбор активности может только админ этого чата.")
        return
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        db.activate_chat(
            conn, chat_id=message.chat.id, title=message.chat.title,
            activated_by=message.from_user.id, activated_at=now,
        )
    await message.reply(
        "📊 Сбор активности в этом чате включён. Любой участник может проверить "
        "статус командой /status; выключить сбор — /deactivate."
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
    await message.reply("⏸ Сбор активности остановлен. Уже собранные данные никуда не делись.")


@router.message(Command("status"), F.chat.type.in_(GROUP_TYPES))
async def cmd_status(message: Message) -> None:
    with db.get_conn() as conn:
        active = db.is_chat_active(conn, message.chat.id)
    await message.reply("✅ Сбор активности сейчас идёт." if active else "⏸ Сбор активности сейчас не идёт.")


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


@router.message(Command("import_history"), F.chat.type == "private")
async def cmd_import_history(message: Message, command: CommandObject) -> None:
    if message.from_user.id != OWNER_USER_ID:
        return
    if not command.args:
        await message.answer("Укажи chat_id: /import_history <chat_id>\nСписок чатов — /chats.")
        return
    try:
        chat_id = int(command.args.strip())
    except ValueError:
        await message.answer("chat_id должен быть числом. Список чатов — /chats.")
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
