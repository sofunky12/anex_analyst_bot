"""
Общая схема SQLite и аналитические запросы.

Текст сообщений хранится зашифрованным (text_encrypted, см. crypto.py). Эта
функция умышленно НЕ расшифровывает его за вызывающий код — кроме
letter_frequency, которой без расшифровки просто нечего анализировать.
top_messages_by_reactions отдаёт шифротекст как есть: показывать ли
расшифрованный фрагмент, решает вызывающий код (dashboard.py) в зависимости
от того, настроен ли у него ключ в данный момент.
"""

import hmac
import os
import secrets
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
    # AAB-17: живой трекинг реакций через message_reaction (Bot API) даёт
    # изменение только ОДНОГО автора за раз (старый набор → новый набор), не
    # текущий общий счётчик сообщения — в отличие от message_reaction_count
    # (уже агрегировано) и от history.py (Telethon видит готовый снимок).
    # Поэтому здесь копится состояние по каждому автору отдельно (actor_id —
    # user_id или id анонимного actor_chat, пространства не пересекаются:
    # user_id всегда положительный, chat_id — всегда отрицательный), а
    # reactions.reaction_count пересчитывается как сумма по всем авторам при
    # каждом апдейте. Не история — текущий живой снимок, старые записи не
    # накапливаются, только upsert/delete по актуальному состоянию.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS message_reactions_by_actor (
            chat_id        INTEGER,
            message_id     INTEGER,
            actor_id       INTEGER,
            reaction_count INTEGER NOT NULL,
            PRIMARY KEY (chat_id, message_id, actor_id)
        )
    """)
    # AAB-12: токен доступа к дашборду — на пару (chat_id, user_id), не на
    # чат целиком (AAB-10). Каждый участник получает свою ссылку; владелец
    # может отозвать доступ конкретному человеку, не трогая остальных.
    # Заменяет chats.chat_access_token из AAB-10 (колонка остаётся в схеме
    # неиспользуемой — миграции здесь не переписываются задним числом, см.
    # _migration_002_chat_access_token).
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dashboard_tokens (
            chat_id    INTEGER,
            user_id    INTEGER,
            token      TEXT,
            created_at TEXT,
            PRIMARY KEY (chat_id, user_id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(chat_id, user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(chat_id, timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_tokens_chat ON dashboard_tokens(chat_id)")
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


def _migration_002_chat_access_token(conn) -> None:
    # AAB-10: персональная ссылка на дашборд чата — токен генерируется лениво
    # (при /activate или /dashboard_link), поэтому колонка допускает NULL для
    # уже существующих строк, а не бэкфиллится тут же.
    # СУПЕРСЕДЕНО AAB-12: токен теперь на пару (chat_id, user_id), см.
    # таблицу dashboard_tokens. Колонка оставлена как есть (не удаляется
    # задним числом, см. принцип миграций выше) — просто больше нигде не
    # читается и не пишется кодом.
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(chats)")
    existing_columns = {row[1] for row in cur.fetchall()}
    if "chat_access_token" not in existing_columns:
        cur.execute("ALTER TABLE chats ADD COLUMN chat_access_token TEXT")


MIGRATIONS = [
    _migration_001_chat_activation,
    _migration_002_chat_access_token,
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


def set_actor_reaction_count(cur, *, chat_id, message_id, actor_id, count) -> None:
    """Текущее число реакций одного автора (пользователя или анонимного
    actor_chat) на сообщение — живой трекинг message_reaction (AAB-17).
    count=0 (набор реакций этого автора стал пустым) удаляет строку, а не
    хранит ноль — иначе таблица росла бы мусорными нулевыми строками."""
    if count <= 0:
        cur.execute(
            "DELETE FROM message_reactions_by_actor WHERE chat_id = ? AND message_id = ? AND actor_id = ?",
            (chat_id, message_id, actor_id),
        )
        return
    cur.execute("""
        INSERT INTO message_reactions_by_actor (chat_id, message_id, actor_id, reaction_count)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(chat_id, message_id, actor_id) DO UPDATE SET
            reaction_count = excluded.reaction_count
    """, (chat_id, message_id, actor_id, count))


def total_actor_reactions(cur, chat_id, message_id) -> int:
    """Сумма реакций всех авторов на сообщение — пересчитывается заново при
    каждом message_reaction апдейте (AAB-17), не хранится отдельно нигде,
    кроме итогового upsert в reactions.reaction_count."""
    cur.execute(
        "SELECT COALESCE(SUM(reaction_count), 0) FROM message_reactions_by_actor "
        "WHERE chat_id = ? AND message_id = ?",
        (chat_id, message_id),
    )
    return cur.fetchone()[0]


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


def get_dashboard_token(conn, chat_id, user_id):
    """Текущий токен пары (chat_id, user_id), если уже выпущен, иначе None —
    вызывающий код сам решает, создавать новый или это первый запрос."""
    cur = conn.cursor()
    cur.execute(
        "SELECT token FROM dashboard_tokens WHERE chat_id = ? AND user_id = ?",
        (chat_id, user_id),
    )
    row = cur.fetchone()
    return row[0] if row else None


def get_or_create_dashboard_token(conn, chat_id, user_id, created_at) -> str:
    """Персональный токен доступа к дашборду для пары чат+пользователь
    (AAB-12). Идемпотентно — повторный вызов (например, повторный /activate)
    не меняет уже выданный токен; перевыпуск — только явным reissue."""
    existing = get_dashboard_token(conn, chat_id, user_id)
    if existing:
        return existing
    token = secrets.token_urlsafe(32)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO dashboard_tokens (chat_id, user_id, token, created_at) VALUES (?, ?, ?, ?)",
        (chat_id, user_id, token, created_at),
    )
    return token


def reissue_dashboard_token(conn, chat_id, user_id, created_at) -> str:
    """Перевыпуск токена этой пары (/dashboard) — старый сразу перестаёт
    работать, т.к. заменяется на месте, старое значение нигде не хранится."""
    token = secrets.token_urlsafe(32)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO dashboard_tokens (chat_id, user_id, token, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(chat_id, user_id) DO UPDATE SET
            token = excluded.token,
            created_at = excluded.created_at
    """, (chat_id, user_id, token, created_at))
    return token


def get_chat_id_by_dashboard_token(conn, token):
    """Обратный поиск: URL несёт только токен, без chat_id/user_id (AAB-10 —
    chat_id в адресной строке сам по себе не секрет и не даёт доступа без
    токена, но незачем светить его лишний раз в URL и логах). Сравнение
    каждой строки — через hmac.compare_digest. Токенов немного (личный
    проект, не тысячи), линейный перебор не проблема по производительности."""
    if not token:
        return None
    cur = conn.cursor()
    cur.execute("SELECT chat_id, token FROM dashboard_tokens")
    for chat_id, stored in cur.fetchall():
        if hmac.compare_digest(stored, token):
            return chat_id
    return None


def revoke_dashboard_tokens_for_chat(conn, chat_id) -> list:
    """Отзыв всех токенов чата (/revoke_token без user_id). Возвращает
    затронутые user_id — вызывающий код рассылает им уведомление в личку."""
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM dashboard_tokens WHERE chat_id = ?", (chat_id,))
    affected = [row[0] for row in cur.fetchall()]
    cur.execute("DELETE FROM dashboard_tokens WHERE chat_id = ?", (chat_id,))
    return affected


def revoke_dashboard_token_for_user(conn, chat_id, user_id) -> bool:
    """Отзыв токена конкретной пары (/revoke_token с user_id). Возвращает
    True, если токен существовал (и был удалён) — чтобы не слать уведомление
    тому, у кого доступа и так не было."""
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM dashboard_tokens WHERE chat_id = ? AND user_id = ?",
        (chat_id, user_id),
    )
    existed = cur.fetchone() is not None
    if existed:
        cur.execute(
            "DELETE FROM dashboard_tokens WHERE chat_id = ? AND user_id = ?",
            (chat_id, user_id),
        )
    return existed


def active_chat_ids(conn) -> list:
    """chat_id всех чатов с активным сбором — используется /help (AAB-16)
    для определения роли: "админ хотя бы одного активного чата"."""
    cur = conn.cursor()
    cur.execute("SELECT chat_id FROM chats WHERE active = 1")
    return [row[0] for row in cur.fetchall()]


def chat_participant_user_ids(conn, chat_id) -> list:
    """Уникальные user_id, встречающиеся в уже собранных сообщениях этого
    чата (AAB-12) — Bot API не даёт списка участников напрямую для
    больших/анонимных групп, это практическая замена для /access_token без
    user_id («выдать всем участникам»)."""
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT user_id FROM messages WHERE chat_id = ?", (chat_id,))
    return [row[0] for row in cur.fetchall()]


def chats_for_user(conn, user_id) -> list:
    """Чаты, в которых у этого user_id есть хотя бы одно собранное сообщение
    (AAB-12, /dashboard) — та же логика данных, что и chat_participant_user_ids,
    просто с другой стороны отношения. (chat_id, title)."""
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT m.chat_id, c.title
        FROM messages m
        LEFT JOIN chats c ON c.chat_id = m.chat_id
        WHERE m.user_id = ?
        ORDER BY c.title
    """, (user_id,))
    return cur.fetchall()


def chat_title(conn, chat_id):
    cur = conn.cursor()
    cur.execute("SELECT title FROM chats WHERE chat_id = ?", (chat_id,))
    row = cur.fetchone()
    return row[0] if row else None


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


def earliest_message_timestamp(conn, chat_id):
    """Самый ранний timestamp, уже сохранённый для чата, либо None, если
    сообщений ещё нет вообще. AAB-17 (корневой фикс): точка возобновления
    /import_history теперь именно timestamp, не message_id — в базовых
    (не супер-) группах Bot API и Telethon не делят единую нумерацию
    message_id (одно и то же сообщение может иметь два разных message_id в
    двух системах), а вот timestamp (момент отправки) у них совпадает
    всегда, это подтверждено на реальных данных. Использование timestamp как
    границы гарантирует, что history.py никогда не полезет в диапазон,
    который уже мог быть живьём собран bot.py — то есть дублей на стыке
    просто не может возникнуть по построению, а не за счёт сверки задним
    числом."""
    cur = conn.cursor()
    cur.execute("SELECT MIN(timestamp) FROM messages WHERE chat_id = ?", (chat_id,))
    row = cur.fetchone()
    return row[0] if row and row[0] else None


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
    #
    # AAB-17: в базовых (не супер-) группах Bot API и Telethon исторически не
    # делили единую нумерацию message_id — одно и то же сообщение могло лежать
    # в messages под двумя message_id (живой сбор bot.py и /import_history).
    # Корневой фикс — history.py теперь строго ограничивает довозку истории по
    # timestamp и не заходит в диапазон, уже покрытый живым сбором (см.
    # CLAUDE.md, «Решения»/«Платформенные ограничения»), так что новых таких
    # дублей появиться не должно. Группировка ниже — страховка для СТАРЫХ
    # данных, собранных до этого фикса (найдено 122+ задвоенных сообщений):
    # у обеих копий совпадают chat_id/timestamp/user_id, этим и опознаются.
    # MAX(reaction_count), не SUM — обе копии независимо хранят ПОЛНЫЙ текущий
    # счётчик реакций на одно и то же сообщение, а не отдельные слагаемые;
    # сложение задвоило бы счётчик, а не поправило.
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
        SELECT MIN(m.message_id), MIN(m.text_encrypted), MIN(m.username), MIN(m.full_name),
               MAX(r.reaction_count) AS reaction_count
        FROM reactions r
        JOIN messages m ON m.chat_id = r.chat_id AND m.message_id = r.message_id
        WHERE {where}
        GROUP BY m.chat_id, m.timestamp, m.user_id
        ORDER BY reaction_count DESC
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
