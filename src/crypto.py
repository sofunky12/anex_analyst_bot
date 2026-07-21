"""
Шифрование текста сообщений (поле text_encrypted в messages).

Режимы работы (выбираются переменными окружения в .env):

1. DB_ENCRYPTION_KEY задан — используется напрямую как Fernet-ключ.
   Просто и удобно для фонового запуска (bot.py как сервис — единственный
   режим, который он поддерживает, см. bot.py), но сам ключ лежит в файле
   рядом с остальными секретами — тот, у кого есть .env, может расшифровать
   всё.

2. DB_ENCRYPTION_KEY не задан, но задан DB_ENCRYPTION_SALT — ключ выводится
   из пароля через PBKDF2. Пароль нигде не сохраняется: в терминальных
   скриптах — через getpass при старте (prompt_passphrase_if_needed), в
   dashboard.py — вводится в сайдбаре. Безопаснее (сам ключ никогда не
   лежит на диске), но пароль нужно вводить при каждом запуске. Для bot.py
   нежизнеспособен — у долгоживущего процесса без stdin запросить пароль
   через getpass физически негде.

3. Ничего не задано — шифрование не настроено. encrypt() в этом случае
   осознанно бросает исключение, а не молча пишет открытый текст.

Генерация ключа для режима 1: python generate_key.py
Генерация соли для режима 2:  python -c "import secrets; print(secrets.token_hex(16))"
"""

import base64
import getpass
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_fernet_instance = None


def _derive_key(passphrase: str, salt: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt.encode("utf-8"), iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _try_env_key() -> bool:
    """Пытается взять готовый ключ из DB_ENCRYPTION_KEY. Не интерактивно —
    безопасно вызывать откуда угодно, без риска неожиданно повиснуть на вводе."""
    global _fernet_instance
    if _fernet_instance is not None:
        return True
    raw_key = os.getenv("DB_ENCRYPTION_KEY", "").strip()
    if not raw_key:
        return False
    try:
        _fernet_instance = Fernet(raw_key.encode("utf-8"))
        return True
    except Exception:
        logging.error(
            "DB_ENCRYPTION_KEY задан, но не является валидным Fernet-ключом "
            "(сгенерируй новый: python generate_key.py)"
        )
        return False


def has_key() -> bool:
    return _fernet_instance is not None or _try_env_key()


def set_passphrase(passphrase: str, salt: str) -> bool:
    """Явно задаёт ключ из пароля, введённого в UI (dashboard.py) — в отличие
    от prompt_passphrase_if_needed(), не трогает терминал/stdin."""
    global _fernet_instance
    if not passphrase or not salt:
        return False
    _fernet_instance = Fernet(_derive_key(passphrase, salt))
    return True


def prompt_passphrase_if_needed() -> bool:
    """Для терминальных скриптов: если ключ ещё не настроен через .env,
    спрашивает пароль в консоли (ввод скрыт, getpass). Возвращает True,
    если после вызова ключ так или иначе настроен."""
    if has_key():
        return True
    salt = os.getenv("DB_ENCRYPTION_SALT", "").strip()
    if not salt:
        return False
    passphrase = getpass.getpass("Пароль для шифрования сообщений: ")
    return set_passphrase(passphrase, salt)


def encrypt(plaintext: str) -> str:
    """Без настроенного ключа осознанно бросает исключение — записать
    "как бы зашифрованные" данные в открытом виде было бы хуже, чем явно
    остановиться и попросить настроить шифрование."""
    if not has_key():
        raise RuntimeError(
            "Шифрование не настроено: задай DB_ENCRYPTION_KEY или DB_ENCRYPTION_SALT "
            "в .env — см. README, раздел «Шифрование»."
        )
    return _fernet_instance.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str):
    """Возвращает None, если ключа нет или расшифровать не удалось (например,
    дашборд запущен без доступа к содержимому) — вызывающий код сам решает,
    как показать это в интерфейсе, вместо падения с исключением."""
    if not ciphertext:
        return ""
    if not has_key():
        return None
    try:
        return _fernet_instance.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
