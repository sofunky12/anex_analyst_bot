"""
Общая схема SQLite и аналитические запросы.

Текст сообщений хранится зашифрованным (text_encrypted, см. crypto.py). Эта
функция умышленно НЕ расшифровывает его за вызывающий код — кроме
letter_frequency, которой без расшифровки просто нечего анализировать.
top_messages_by_reactions отдаёт шифротекст как есть: показывать ли
расшифрованный фрагмент, решает вызывающий код (dashboard.py) в зависимости
от того, настроен ли у него ключ в данный момент.
"""

import os
import sqlite3
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import crypto

REPO_ROOT = Path(__file__).resolve().parent.parent
# Фаза 2: DATA_DIR указывает на persistent volume на Fly.io (activity.db и
# Telethon session должны переживать редеплой). Локально не задан — по
# умолчанию data/ в корне репозитория (ANEX-005; db.py теперь лежит в src/,
# поэтому дефолт считается от REPO_ROOT, а не от директории самого файла).
DATA_DIR = Path(os.getenv("DATA_DIR", str(REPO_ROOT / "data")))
DB_PATH = DATA_DIR / "activity.db"


def init_db(db_path: Path = DB_PATH) -> None:
    conn = sqlite3.connect(str(db_path))
    # WAL позволяет читать базу (дашборду) одновременно с тем, как bot.py/history.py
    # в неё пишут, без блокировок "database is locked".
    conn.execute("PRAGMA journal_mode = WAL")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            chat_id        INTEGER PRIMARY KEY,
            title          TEXT,
            updated_at     TEXT,
            active         INTEGER NOT NULL DEFAULT 0,
            activated_by   INTEGER,
            activated_at   TEXT,
            deactivated_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            message_id     INTEGER,
            chat_id        INTEGER,
            user_id        INTEGER,
            username       TEXT,
            full_name      TEXT,
            text_encrypted TEXT,    -- зашифровано через crypto.py
            msg_type       TEXT,
            timestamp      TEXT,    -- ISO 8601, UTC
            weekday        INTEGER, -- 0 = понедельник ... 6 = воскресенье
            hour           INTEGER,
            PRIMARY KEY (message_id, chat_id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            chat_id        INTEGER,
            message_id     INTEGER,
            reaction_count INTEGER,
            updated_at     TEXT,
            PRIMARY KEY (chat_id, message_id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(chat_id, user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(chat_id, timestamp)")
    conn.commit()
    _run_migrations(conn)
    conn.close()


# ---------- Миграции ----------
# Схема версионируется через PRAGMA user_version — без Alembic. Каждый шаг
# обязан быть идемпотентным (проверять table_info перед ALTER), потому что
# init_db() дергается при каждом запуске, а не только один раз.

def _migration_001_chat_activation(conn) -> None:
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(chats)")
    existing_columns = {row[1] for row in cur.fetchall()}
    for column, ddl in (
        ("active", "ALTER TABLE chats ADD COLUMN active INTEGER NOT NULL DEFAULT 0"),
        ("activated_by", "ALTER TABLE chats ADD COLUMN activated_by INTEGER"),
        ("activated_at", "ALTER TABLE chats ADD COLUMN activated_at TEXT"),
        ("deactivated_at", "ALTER TABLE chats ADD COLUMN deactivated_at TEXT"),
    ):
        if column not in existing_columns:
            cur.execute(ddl)


MIGRATIONS = [
    _migration_001_chat_activation,
]


def _run_migrations(conn) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    for step in MIGRATIONS[version:]:
        step(conn)
    conn.commit()
    conn.execute(f"PRAGMA user_version = {len(MIGRATIONS)}")


@contextmanager
def get_conn(db_path: Path = DB_PATH):
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------- Запись данных ----------

def upsert_message(cur, *, message_id, chat_id, user_id, username, full_name,
                    text_encrypted, msg_type, dt, weekday, hour) -> None:
    cur.execute("""
        INSERT OR IGNORE INTO messages
        (message_id, chat_id, user_id, username, full_name, text_encrypted, msg_type, timestamp, weekday, hour)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (message_id, chat_id, user_id, username, full_name, text_encrypted, msg_type, dt, weekday, hour))


def upsert_reaction(cur, *, chat_id, message_id, count, updated_at) -> None:
    cur.execute("""
        INSERT INTO reactions (chat_id, message_id, reaction_count, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(chat_id, message_id) DO UPDATE SET
            reaction_count = excluded.reaction_count,
            updated_at = excluded.updated_at
    """, (chat_id, message_id, count, updated_at))


def upsert_chat(cur, *, chat_id, title, updated_at) -> None:
    cur.execute("""
        INSERT INTO chats (chat_id, title, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(chat_id) DO UPDATE SET
            title = excluded.title,
            updated_at = excluded.updated_at
    """, (chat_id, title, updated_at))


def activate_chat(conn, *, chat_id, title, activated_by, activated_at) -> None:
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO chats (chat_id, title, updated_at, active, activated_by, activated_at, deactivated_at)
        VALUES (?, ?, ?, 1, ?, ?, NULL)
        ON CONFLICT(chat_id) DO UPDATE SET
            title = excluded.title,
            updated_at = excluded.updated_at,
            active = 1,
            activated_by = excluded.activated_by,
            activated_at = excluded.activated_at,
            deactivated_at = NULL
    """, (chat_id, title, activated_at, activated_by, activated_at))


def deactivate_chat(conn, *, chat_id, deactivated_at) -> None:
    # Данные messages/reactions не трогаем — деактивация только останавливает сбор.
    cur = conn.cursor()
    cur.execute(
        "UPDATE chats SET active = 0, deactivated_at = ? WHERE chat_id = ?",
        (deactivated_at, chat_id),
    )


def is_chat_active(conn, chat_id) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT active FROM chats WHERE chat_id = ?", (chat_id,))
    row = cur.fetchone()
    return bool(row and row[0])


def list_chats(conn):
    """Список чатов для селектора в дашборде: (chat_id, title).
    Если таблицы chats ещё нет (старая база) — берём chat_id прямо из messages."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT chat_id, title FROM chats ORDER BY title")
        rows = cur.fetchall()
        if rows:
            return rows
    except sqlite3.OperationalError:
        pass
    cur.execute("SELECT DISTINCT chat_id FROM messages")
    return [(chat_id, None) for (chat_id,) in cur.fetchall()]


def last_message_id(conn, chat_id) -> int:
    """Максимальный message_id, уже сохранённый для чата. Используется для
    дозагрузки только новых сообщений при повторном запуске history.py."""
    cur = conn.cursor()
    cur.execute("SELECT MAX(message_id) FROM messages WHERE chat_id = ?", (chat_id,))
    row = cur.fetchone()
    return row[0] if row and row[0] else 0


def date_bounds(conn, chat_id):
    """(самая ранняя дата, самая поздняя дата) сообщений — 'YYYY-MM-DD' либо (None, None)."""
    cur = conn.cursor()
    cur.execute(
        "SELECT MIN(date(timestamp)), MAX(date(timestamp)) FROM messages WHERE chat_id = ?",
        (chat_id,),
    )
    row = cur.fetchone()
    return row if row and row[0] else (None, None)


# ---------- Аналитика ----------
# msg_type по умолчанию "text" — иначе стикеры/фото/голосовые раздувают
# счётчики активности. since/until — необязательные границы по timestamp
# (ISO-строки; since включительно, until исключительно).

def _where(chat_id, msg_type=None, since=None, until=None):
    clauses = ["chat_id = ?"]
    params = [chat_id]
    if msg_type:
        clauses.append("msg_type = ?")
        params.append(msg_type)
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("timestamp < ?")
        params.append(until)
    return " AND ".join(clauses), params


def total_messages(conn, chat_id, msg_type="text", since=None, until=None) -> int:
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM messages WHERE {clause}", params)
    return cur.fetchone()[0]


def activity_by_weekday(conn, chat_id, msg_type="text", since=None, until=None) -> dict:
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT weekday, COUNT(*) FROM messages
        WHERE {clause}
        GROUP BY weekday
        ORDER BY weekday
    """, params)
    return dict(cur.fetchall())


def activity_by_hour(conn, chat_id, msg_type="text", since=None, until=None) -> dict:
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT hour, COUNT(*) FROM messages
        WHERE {clause}
        GROUP BY hour
        ORDER BY hour
    """, params)
    return dict(cur.fetchall())


def activity_heatmap(conn, chat_id, msg_type="text", since=None, until=None) -> dict:
    """{(weekday, hour): count} — основа для тепловой карты активности."""
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT weekday, hour, COUNT(*) FROM messages
        WHERE {clause}
        GROUP BY weekday, hour
    """, params)
    return {(w, h): c for w, h, c in cur.fetchall()}


def daily_message_counts(conn, chat_id, msg_type="text", since=None, until=None) -> dict:
    """{'YYYY-MM-DD': count} — тренд сообщений по дням в выбранном периоде."""
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT date(timestamp) AS day, COUNT(*) FROM messages
        WHERE {clause}
        GROUP BY day
        ORDER BY day
    """, params)
    return dict(cur.fetchall())


def top_users(conn, chat_id, limit=10, msg_type="text", since=None, until=None):
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT COALESCE(username, full_name, 'ID' || user_id) AS name, COUNT(*) AS cnt
        FROM messages
        WHERE {clause}
        GROUP BY user_id
        ORDER BY cnt DESC
        LIMIT ?
    """, params + [limit])
    return cur.fetchall()


def top_messages_by_reactions(conn, chat_id, limit=5, since=None, until=None):
    # Реакции — по всем типам сразу (фото/стикер вполне может быть самым
    # "залайканным" сообщением). text_encrypted отдаётся шифротекстом как есть.
    clauses = ["r.chat_id = ?"]
    params = [chat_id]
    if since:
        clauses.append("m.timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("m.timestamp < ?")
        params.append(until)
    where = " AND ".join(clauses)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT m.message_id, m.text_encrypted, m.username, m.full_name, r.reaction_count
        FROM reactions r
        JOIN messages m ON m.chat_id = r.chat_id AND m.message_id = r.message_id
        WHERE {where}
        ORDER BY r.reaction_count DESC
        LIMIT ?
    """, params + [limit])
    return cur.fetchall()


def daily_counts_by_type(conn, chat_id, since=None, until=None) -> dict:
    """{msg_type: {'YYYY-MM-DD': count}} — основа для спарклайнов по типам.
    Всегда по всем типам сразу — это и есть весь смысл разбивки."""
    clause, params = _where(chat_id, None, since, until)
    cur = conn.cursor()
    cur.execute(f"""
        SELECT msg_type, date(timestamp) AS day, COUNT(*) AS cnt
        FROM messages
        WHERE {clause}
        GROUP BY msg_type, day
        ORDER BY day
    """, params)
    result: dict = {}
    for msg_type, day, cnt in cur.fetchall():
        result.setdefault(msg_type, {})[day] = cnt
    return result


def letter_frequency(conn, chat_id, msg_type="text", top_n=15, since=None, until=None):
    """Частота букв — требует расшифровки. Возвращает None (не пустой список),
    если ключ не настроен — так вызывающий код отличит "нет ключа" от
    "нет текстовых сообщений за период"."""
    if not crypto.has_key():
        return None
    clause, params = _where(chat_id, msg_type, since, until)
    cur = conn.cursor()
    cur.execute(f"SELECT text_encrypted FROM messages WHERE {clause} AND text_encrypted != ''", params)
    counter: Counter = Counter()
    for (ciphertext,) in cur.fetchall():
        plain = crypto.decrypt(ciphertext)
        if plain:
            counter.update(ch for ch in plain.lower() if ch.isalpha())
    return counter.most_common(top_n)
