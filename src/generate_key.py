"""Генерирует случайный ключ для DB_ENCRYPTION_KEY.

Запуск: python generate_key.py
Скопируй вывод в .env как значение DB_ENCRYPTION_KEY.
"""

from cryptography.fernet import Fernet

if __name__ == "__main__":
    print(Fernet.generate_key().decode())
