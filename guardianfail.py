#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import requests
from datetime import datetime
from pathlib import Path


DEFAULT_CONFIG = "config.json"


BAN_REGEX = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+Ban\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"No existe {config_path}. Copia config.example.json como config.json y ajusta los valores."
        )

    with open(config_path, "r", encoding="utf-8") as file:
        return json.load(file)


def ensure_directories(config: dict) -> None:
    db_path = Path(config["database_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    Path("reports").mkdir(exist_ok=True)


def connect_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            jail TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            total_events INTEGER NOT NULL DEFAULT 1,
            UNIQUE(ip, jail)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            jail TEXT NOT NULL,
            event_datetime TEXT NOT NULL,
            raw_line TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn


def parse_fail2ban_log(log_path: str) -> list[dict]:
    events = []

    if not os.path.exists(log_path):
        raise FileNotFoundError(f"No existe el log de Fail2Ban: {log_path}")

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = BAN_REGEX.search(line)
            if not match:
                continue

            event_datetime = f"{match.group('date')} {match.group('time')}"

            events.append({
                "ip": match.group("ip"),
                "jail": match.group("jail"),
                "event_datetime": event_datetime,
                "raw_line": line.strip()
            })

    return events


def save_events(conn: sqlite3.Connection, events: list[dict]) -> dict:
    new_ips = []
    repeated_ips = []

    for event in events:
        ip = event["ip"]
        jail = event["jail"]
        event_datetime = event["event_datetime"]

        exists = conn.execute(
            "SELECT id, total_events FROM banned_ips WHERE ip = ? AND jail = ?",
            (ip, jail)
        ).fetchone()

        conn.execute(
            """
            INSERT INTO events (ip, jail, event_datetime, raw_line)
            VALUES (?, ?, ?, ?)
            """,
            (ip, jail, event_datetime, event["raw_line"])
        )

        if exists:
            record_id, total_events = exists
            conn.execute(
                """
                UPDATE banned_ips
                SET last_seen = ?, total_events = ?
                WHERE id = ?
                """,
                (event_datetime, total_events + 1, record_id)
            )
            repeated_ips.append(ip)
        else:
            conn.execute(
                """
                INSERT INTO banned_ips (ip, jail, first_seen, last_seen, total_events)
                VALUES (?, ?, ?, ?, 1)
                """,
                (ip, jail, event_datetime, event_datetime)
            )
            new_ips.append(ip)

    conn.commit()

    return {
        "new_ips": sorted(set(new_ips)),
        "repeated_ips": sorted(set(repeated_ips)),
        "total_events": len(events)
    }


def calculate_risk(total_events: int, new_ips_count: int, repeated_ips_count: int) -> str:
    score = 0

    if total_events >= 10:
        score += 1
    if total_events >= 30:
        score += 1
    if new_ips_count >= 5:
        score += 1
    if repeated_ips_count >= 3:
        score += 1

    if score <= 1:
        return "Bajo"
    if score == 2:
        return "Medio"
    if score == 3:
        return "Alto"

    return "Crítico"


def get_top_ips(conn: sqlite3.Connection, limit: int = 5) -> list[tuple]:
    return conn.execute(
        """
        SELECT ip, jail, total_events, first_seen, last_seen
        FROM banned_ips
        ORDER BY total_events DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()


def generate_report(conn: sqlite3.Connection, stats: dict) -> str:
    top_ips = get_top_ips(conn)

    risk = calculate_risk(
        total_events=stats["total_events"],
        new_ips_count=len(stats["new_ips"]),
        repeated_ips_count=len(stats["repeated_ips"])
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "🛡️ GuardianFail - Reporte defensivo",
        "",
        f"Fecha de análisis: {now}",
        "",
        f"Eventos analizados: {stats['total_events']}",
        f"IPs nuevas detectadas: {len(stats['new_ips'])}",
        f"IPs reincidentes detectadas: {len(stats['repeated_ips'])}",
        f"Nivel de riesgo general: {risk}",
        "",
        "Top IPs registradas:"
    ]

    if top_ips:
        for ip, jail, total_events, first_seen, last_seen in top_ips:
            lines.append(
                f"- {ip} | Jail: {jail} | Eventos: {total_events} | "
                f"Primera vez: {first_seen} | Última vez: {last_seen}"
            )
    else:
        lines.append("- No hay IPs registradas todavía.")

    lines.extend([
        "",
        "Recomendaciones:",
        "- Mantener Fail2Ban activo.",
        "- Usar autenticación SSH por llave pública.",
        "- Deshabilitar login SSH para root.",
        "- Revisar puertos expuestos periódicamente.",
        "- Mantener sistema y servicios actualizados.",
        "",
        "Nota ética:",
        "Este sistema analiza eventos registrados en infraestructura propia. "
        "No realiza escaneos ni acciones activas contra terceros."
    ])

    return "\n".join(lines)


def save_report(report: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/guardianfail_report_{timestamp}.txt"

    with open(report_path, "w", encoding="utf-8") as file:
        file.write(report)

    return report_path


def send_telegram_message(bot_token: str, chat_id: str, message: str) -> None:
    if not bot_token or not chat_id:
        print("Telegram no configurado. Se omite envío.")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    response = requests.post(url, data={
        "chat_id": chat_id,
        "text": message
    }, timeout=15)

    response.raise_for_status()


def main() -> None:
    config = load_config(DEFAULT_CONFIG)
    ensure_directories(config)

    conn = connect_db(config["database_path"])

    events = parse_fail2ban_log(config["fail2ban_log"])
    stats = save_events(conn, events)

    report = generate_report(conn, stats)
    report_path = save_report(report)

    print(report)
    print()
    print(f"Reporte guardado en: {report_path}")

    send_telegram_message(
        bot_token=config.get("telegram_bot_token", ""),
        chat_id=config.get("telegram_chat_id", ""),
        message=report
    )

    conn.close()


if __name__ == "__main__":
    main()