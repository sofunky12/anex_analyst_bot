FROM python:3.9-slim

WORKDIR /app

# Отдельный слой для зависимостей — кеш сборки не сбрасывается при правках кода.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY deploy/start.sh ./
RUN chmod +x start.sh

# bot и dashboard запускаются в одной Fly Machine через start.sh (фаза 2,
# скорректировано — им нужен общий persistent volume, см. CLAUDE.md). Оба
# процесса — fail-fast: падение любого роняет весь контейнер, см. start.sh.
# activity.db, Telethon session и .env НЕ копируются в образ: первые два живут
# на persistent volume (DATA_DIR), .env — только для локальной разработки.
CMD ["./start.sh"]
