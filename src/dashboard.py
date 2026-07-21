"""
Дашборд активности чата. Только читает activity.db — сбор данных делает bot.py
(live) и history.py (догрузка истории).

Запуск: streamlit run dashboard.py
"""

import hmac
import os
from datetime import date, timedelta

import altair as alt
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

import crypto
import db

st.set_page_config(page_title="Активность чата", page_icon="📊", layout="wide")

WEEKDAYS_RU = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"]

MSG_TYPE_LABELS = {
    "text": "Текст",
    "photo": "Фото",
    "sticker": "Стикеры",
    "video": "Видео",
    "voice": "Голосовые",
    "other_media": "Другое медиа",
    "other": "Другое",
}

PRIMARY = "#3B6E8F"
SECONDARY = "#5FA8A0"
ACCENT = "#E0A458"


# ---------- Данные ----------

@st.cache_data(ttl=30)
def load_chats():
    with db.get_conn() as conn:
        return db.list_chats(conn)


@st.cache_data(ttl=30)
def load_date_bounds(chat_id):
    with db.get_conn() as conn:
        return db.date_bounds(conn, chat_id)


@st.cache_data(ttl=30)
def load_stats(chat_id, msg_type, since, until):
    with db.get_conn() as conn:
        return {
            "total": db.total_messages(conn, chat_id, msg_type=msg_type, since=since, until=until),
            "by_weekday": db.activity_by_weekday(conn, chat_id, msg_type=msg_type, since=since, until=until),
            "by_hour": db.activity_by_hour(conn, chat_id, msg_type=msg_type, since=since, until=until),
            "heatmap": db.activity_heatmap(conn, chat_id, msg_type=msg_type, since=since, until=until),
            "trend": db.daily_message_counts(conn, chat_id, msg_type=msg_type, since=since, until=until),
            "top_users": db.top_users(conn, chat_id, limit=10, msg_type=msg_type, since=since, until=until),
            "top_messages": db.top_messages_by_reactions(conn, chat_id, limit=10, since=since, until=until),
            "by_type": db.daily_counts_by_type(conn, chat_id, since=since, until=until),
            "letters": db.letter_frequency(conn, chat_id, top_n=15, since=since, until=until),
        }


def snippet(text, limit: int = 90) -> str:
    if text is None:
        return "🔒 нет ключа для расшифровки"
    raw = text or "[без текста / медиа]"
    return (raw[:limit] + "…") if len(raw) > limit else raw


def build_type_breakdown(by_type: dict) -> pd.DataFrame:
    if not by_type:
        return pd.DataFrame(columns=["Тип", "Всего", "Тренд по дням"])
    all_days = sorted({day for days in by_type.values() for day in days})
    rows = []
    for msg_type, days in by_type.items():
        series = [days.get(day, 0) for day in all_days]
        rows.append({"Тип": MSG_TYPE_LABELS.get(msg_type, msg_type), "Всего": sum(series), "Тренд по дням": series})
    rows.sort(key=lambda r: -r["Всего"])
    return pd.DataFrame(rows)


# ---------- Графики ----------

def weekday_chart(by_weekday: dict):
    df = pd.DataFrame({"День": WEEKDAYS_RU, "Сообщений": [by_weekday.get(i, 0) for i in range(7)]})
    return alt.Chart(df).mark_bar(color=PRIMARY, cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X("День", sort=WEEKDAYS_RU, title=None),
        y=alt.Y("Сообщений", title="Сообщений"),
        tooltip=["День", "Сообщений"],
    ).properties(height=280)


def hour_chart(by_hour: dict):
    df = pd.DataFrame({"Час": list(range(24)), "Сообщений": [by_hour.get(h, 0) for h in range(24)]})
    return alt.Chart(df).mark_bar(color=SECONDARY, cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X("Час:O", title="Час"),
        y=alt.Y("Сообщений", title="Сообщений"),
        tooltip=["Час", "Сообщений"],
    ).properties(height=280)


def heatmap_chart(heatmap: dict):
    rows = [
        {"День": WEEKDAYS_RU[w], "Час": h, "Сообщений": heatmap.get((w, h), 0)}
        for w in range(7) for h in range(24)
    ]
    df = pd.DataFrame(rows)
    return alt.Chart(df).mark_rect().encode(
        x=alt.X("Час:O", title="Час"),
        y=alt.Y("День:O", sort=WEEKDAYS_RU, title=None),
        color=alt.Color("Сообщений:Q", scale=alt.Scale(scheme="blues"), legend=alt.Legend(title="Сообщений")),
        tooltip=["День", "Час", "Сообщений"],
    ).properties(height=280)


def trend_chart(trend: dict):
    if not trend:
        return None
    df = pd.DataFrame({"Дата": list(trend.keys()), "Сообщений": list(trend.values())})
    df["Дата"] = pd.to_datetime(df["Дата"])
    return alt.Chart(df).mark_line(color=PRIMARY, point=alt.OverlayMarkDef(color=PRIMARY, size=25)).encode(
        x=alt.X("Дата:T", title=None),
        y=alt.Y("Сообщений:Q", title="Сообщений"),
        tooltip=[alt.Tooltip("Дата:T", title="Дата", format="%d.%m.%Y"), "Сообщений"],
    ).properties(height=240)


# ---------- Авторизация (AAB-10) ----------
# Без персональной ссылки чата (?token=) и без мастер-пароля дашборд не
# показывает вообще ничего, включая метаданные (см. AAB-8 — до этой задачи
# дашборд был публично доступен без пароля). Два независимых входа: ссылка на
# конкретный чат (для админа этого чата) и мастер-пароль владельца (видит все
# чаты со селектором). При совпадении обоих сразу — мастер-режим приоритетнее.

MASTER_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()


def _try_chat_token_auth():
    # Проверка отсутствия файла БД — здесь, а не после логина: sqlite3.connect
    # молча создаёт пустой файл при первом обращении, а неавторизованные
    # запросы с произвольными токенами не должны иметь такой побочный эффект.
    if not db.DB_PATH.exists():
        return None
    # URL несёт только ?token= (без chat_id/user_id — по итогам живого теста
    # решили не светить лишние идентификаторы в адресной строке/логах). Чат
    # находится обратным поиском по самому токену, см.
    # db.get_chat_id_by_dashboard_token (AAB-12: токен теперь на пару
    # чат+пользователь, но самому дашборду это не важно — фильтрация вкладок
    # всё так же строго по chat_id).
    token = st.query_params.get("token")
    if not token:
        return None
    with db.get_conn() as conn:
        return db.get_chat_id_by_dashboard_token(conn, token)


def _master_login_widget() -> None:
    if not MASTER_PASSWORD:
        return
    with st.expander("Мастер-доступ"):
        pwd = st.text_input("Мастер-пароль", type="password", key="master_pwd_input")
        if st.button("Войти", key="master_pwd_submit") and pwd:
            if hmac.compare_digest(pwd, MASTER_PASSWORD):
                st.session_state["dashboard_master_authed"] = True
                st.rerun()
            else:
                st.error("Неверный пароль.")


master_authed = st.session_state.get("dashboard_master_authed", False)
single_chat_id = None if master_authed else _try_chat_token_auth()

if not master_authed and single_chat_id is None:
    st.title("📊 Активность чата")
    st.error("Нет доступа.")
    _master_login_widget()
    st.stop()


# ---------- Страница ----------

st.title("📊 Активность чата")

if not db.DB_PATH.exists():
    st.warning("База данных не найдена. Запусти `bot.py` и активируй чат командой `/activate`.")
    st.stop()

with st.sidebar:
    st.header("Фильтры")

    if master_authed:
        chats = load_chats()
        if not chats:
            st.warning("В базе пока нет сообщений. Дай боту немного поработать после `/activate`.")
            st.stop()
        if len(chats) == 1:
            chat_id, chat_title = chats[0]
            st.caption(f"Чат: {chat_title or chat_id}")
        else:
            labels = {(title or f"Чат {cid}"): cid for cid, title in chats}
            selected_label = st.selectbox("Чат", list(labels.keys()))
            chat_id = labels[selected_label]
    else:
        chat_id = single_chat_id
        with db.get_conn() as conn:
            chat_title = db.chat_title(conn, chat_id)
        st.caption(f"Чат: {chat_title or chat_id}")
        _master_login_widget()

    min_date_str, max_date_str = load_date_bounds(chat_id)
    if min_date_str:
        min_date, max_date = date.fromisoformat(min_date_str), date.fromisoformat(max_date_str)
    else:
        min_date = max_date = date.today()

    period = st.selectbox(
        "Период",
        ["Последние 7 дней", "Последние 30 дней", "Последние 90 дней", "Всё время", "Свой период"],
        index=3,
    )

    if period == "Последние 7 дней":
        start_date, end_date = max(min_date, max_date - timedelta(days=6)), max_date
    elif period == "Последние 30 дней":
        start_date, end_date = max(min_date, max_date - timedelta(days=29)), max_date
    elif period == "Последние 90 дней":
        start_date, end_date = max(min_date, max_date - timedelta(days=89)), max_date
    elif period == "Всё время":
        start_date, end_date = min_date, max_date
    else:
        picked = st.date_input(
            "Диапазон дат", value=(min_date, max_date),
            min_value=min_date, max_value=max_date,
        )
        # date_input в режиме диапазона может на секунду вернуть только одну
        # дату, пока не выбрана вторая, — не даём этому уронить страницу.
        if isinstance(picked, tuple) and len(picked) == 2:
            start_date, end_date = picked
        else:
            start_date, end_date = min_date, max_date
            st.caption("Выбери обе даты диапазона.")

    only_text = st.checkbox(
        "Только текстовые сообщения", value=True,
        help="Влияет на сводку, графики и топ участников. Реакции и разбивка по типам всегда учитывают всё.",
    )

    st.divider()
    if crypto.has_key():
        st.caption("🔓 Ключ активен — текст сообщений доступен в этой сессии.")
    else:
        salt = os.getenv("DB_ENCRYPTION_SALT", "").strip()
        st.caption("🔒 Текст сообщений скрыт в этой сессии.")
        if salt:
            with st.expander("Ввести пароль"):
                pwd = st.text_input("Пароль шифрования", type="password", key="pwd_input")
                if st.button("Применить") and pwd:
                    crypto.set_passphrase(pwd, salt)
                    st.cache_data.clear()
                    st.rerun()
        else:
            st.caption("Задай DB_ENCRYPTION_KEY или DB_ENCRYPTION_SALT в .env, чтобы открыть доступ к тексту.")

    st.divider()
    if st.button("🔄 Обновить данные"):
        st.cache_data.clear()
        st.rerun()

since = start_date.isoformat()
until = (end_date + timedelta(days=1)).isoformat()
msg_type_filter = "text" if only_text else None

stats = load_stats(chat_id, msg_type_filter, since, until)

if stats["total"] == 0 and not stats["top_messages"]:
    st.info("За выбранный период нет данных.")
    st.stop()

tab_overview, tab_users, tab_messages, tab_text = st.tabs(["Обзор", "Участники", "Сообщения", "Текст"])

with tab_overview:
    col1, col2, col3 = st.columns(3)
    col1.metric("Сообщений за период", stats["total"])
    if stats["top_users"]:
        name, cnt = stats["top_users"][0]
        col2.metric("Самый активный", name, f"{cnt} сообщ.")
    if stats["top_messages"]:
        _, _, u, fn, count = stats["top_messages"][0]
        col3.metric("Реакций у топ-сообщения", count, u or fn or "")

    st.subheader("Тепловая карта активности")
    st.caption("День недели × час — чем темнее, тем больше сообщений.")
    st.altair_chart(heatmap_chart(stats["heatmap"]), use_container_width=True)

    st.subheader("Тренд по дням")
    trend = trend_chart(stats["trend"])
    if trend is not None:
        st.altair_chart(trend, use_container_width=True)
    else:
        st.write("Недостаточно данных для тренда.")

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("По дням недели")
        st.altair_chart(weekday_chart(stats["by_weekday"]), use_container_width=True)
    with chart_col2:
        st.subheader("По часам")
        st.altair_chart(hour_chart(stats["by_hour"]), use_container_width=True)

with tab_users:
    st.subheader("Топ активных участников")
    if stats["top_users"]:
        users_df = pd.DataFrame(stats["top_users"], columns=["Участник", "Сообщений"])
        users_df.index = range(1, len(users_df) + 1)

        col_a, col_b = st.columns([2, 3])
        with col_a:
            st.dataframe(users_df, width="stretch")
        with col_b:
            chart = alt.Chart(users_df.reset_index(drop=True)).mark_bar(color=PRIMARY).encode(
                x=alt.X("Сообщений:Q"),
                y=alt.Y("Участник:N", sort="-x", title=None),
                tooltip=["Участник", "Сообщений"],
            ).properties(height=min(35 * len(users_df) + 40, 400))
            st.altair_chart(chart, use_container_width=True)
    else:
        st.write("Пока нет данных.")

with tab_messages:
    st.subheader("По типам сообщений")
    type_df = build_type_breakdown(stats["by_type"])
    if not type_df.empty:
        st.dataframe(
            type_df,
            column_config={"Тренд по дням": st.column_config.LineChartColumn("Тренд по дням", width="medium")},
            hide_index=True,
            width="stretch",
        )
    else:
        st.write("Пока нет данных.")

    st.subheader("Топ сообщений по реакциям")
    if stats["top_messages"]:
        rows = []
        for _, ciphertext, u, fn, count in stats["top_messages"]:
            plain = crypto.decrypt(ciphertext)
            rows.append({"Автор": u or fn or "?", "Сообщение": snippet(plain), "Реакций": count})
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    else:
        st.write("Реакций пока не зафиксировано.")

with tab_text:
    st.subheader("Анализ текста")
    letters = stats["letters"]
    if letters is None:
        st.info("🔒 Нужен ключ шифрования, чтобы анализировать текст — введи пароль в сайдбаре слева.")
    elif letters:
        top_letter, top_count = letters[0]
        st.metric("Самая частая буква", top_letter.upper(), f"{top_count} раз")
        letters_df = pd.DataFrame(letters, columns=["Буква", "Количество"])
        chart = alt.Chart(letters_df).mark_bar(color=ACCENT).encode(
            x=alt.X("Буква:N", sort="-y", title=None),
            y=alt.Y("Количество:Q"),
            tooltip=["Буква", "Количество"],
        ).properties(height=280)
        st.altair_chart(chart, use_container_width=True)
    else:
        st.write("Пока нет текстовых сообщений для анализа за этот период.")

st.caption("Данные кешируются на 30 секунд — кнопка «Обновить данные» в сайдбаре сбрасывает кеш сразу.")
