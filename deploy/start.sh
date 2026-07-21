#!/bin/bash
# Обёрточный скрипт запуска для Fly.io (фаза 2, скорректировано — см. CLAUDE.md,
# костыль «вся машина не может автостопиться, пока жив bot»).
#
# bot.py и dashboard.py запускаются в одной Fly Machine, чтобы им обоим был
# физически доступен один и тот же persistent volume. Fail-fast: если любой
# из двух процессов завершается, скрипт сразу завершает себя вместе с ним —
# контейнер падает целиком, и Fly перезапускает машину. Никогда не остаётся
# состояния "один процесс мёртв, скрипт висит со вторым".
set -u

term_handler() {
    kill -TERM "$bot_pid" "$dash_pid" 2>/dev/null
    wait "$bot_pid" "$dash_pid" 2>/dev/null
    exit 0
}
trap term_handler TERM INT

python src/bot.py &
bot_pid=$!

streamlit run src/dashboard.py --server.port 8080 --server.address 0.0.0.0 &
dash_pid=$!

wait -n "$bot_pid" "$dash_pid"
exit_code=$?

kill -TERM "$bot_pid" "$dash_pid" 2>/dev/null
wait "$bot_pid" "$dash_pid" 2>/dev/null

exit "$exit_code"
