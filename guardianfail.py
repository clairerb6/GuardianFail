#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import sqlite3
import requests
from json import JSONDecodeError
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # pragma: no cover
    geoip2 = None
    AddressNotFoundError = Exception


DEFAULT_CONFIG = "config.json"
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


logger = logging.getLogger("guardianfail")


BAN_REGEX = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+Ban\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def log_event(event: str, **fields: object) -> None:
    payload = {"event": event, **fields}
    logger.info(json.dumps(payload, ensure_ascii=False))


def load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"No existe {config_path}. Copia config.example.json como config.json y ajusta los valores."
        )

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)
    except JSONDecodeError as exc:
        raise ValueError(
            f"El archivo {config_path} no tiene JSON válido: {exc.msg} (línea {exc.lineno}, columna {exc.colno})."
        ) from exc

    validate_config(config)
    return config


def validate_config(config: dict) -> None:
    required_str_fields = ["fail2ban_log", "database_path"]
    optional_str_fields = ["telegram_bot_token", "telegram_chat_id", "own_server_ip", "geoip_city_db_path"]
    optional_bool_fields = ["enable_own_server_audit"]

    if not isinstance(config, dict):
        raise ValueError("La configuración debe ser un objeto JSON (diccionario).")

    missing = [field for field in required_str_fields if field not in config]
    if missing:
        raise ValueError(
            f"Faltan claves requeridas en config.json: {', '.join(missing)}."
        )

    for field in required_str_fields:
        value = config.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"'{field}' debe ser un texto no vacío.")

    for field in optional_str_fields:
        value = config.get(field, "")
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"'{field}' debe ser texto.")

    for field in optional_bool_fields:
        value = config.get(field, False)
        if value is None:
            continue
        if not isinstance(value, bool):
            raise ValueError(f"'{field}' debe ser true o false.")

    retention_days = config.get("event_retention_days", 90)
    if not isinstance(retention_days, int) or retention_days < 1:
        raise ValueError("'event_retention_days' debe ser un entero mayor o igual a 1.")

    log_level = config.get("log_level", "INFO")
    if not isinstance(log_level, str) or log_level.upper() not in VALID_LOG_LEVELS:
        valid = ", ".join(sorted(VALID_LOG_LEVELS))
        raise ValueError(f"'log_level' debe ser uno de: {valid}.")


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
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_event_datetime ON events(event_datetime)"
    )

    conn.commit()
    return conn


def discover_geoip_city_db_path(base_dir: str = "GeoIP") -> str:
    root = Path(base_dir)
    if not root.exists():
        return ""

    direct = root / "GeoLite2-City.mmdb"
    if direct.exists():
        return str(direct)

    for candidate in sorted(root.glob("**/GeoLite2-City.mmdb")):
        return str(candidate)
    return ""


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


def prune_old_events(conn: sqlite3.Connection, retention_days: int) -> int:
    cutoff = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.execute(
        "DELETE FROM events WHERE event_datetime < ?",
        (cutoff,)
    )
    conn.commit()
    return cursor.rowcount


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


def build_geoip_lookup(city_db_path: str) -> Callable[[str], str] | None:
    if not city_db_path:
        return None
    if not os.path.exists(city_db_path):
        log_event("geoip_skipped", reason="db_not_found", path=city_db_path)
        return None
    if geoip2 is None:
        log_event("geoip_skipped", reason="geoip2_not_installed")
        return None

    reader = geoip2.database.Reader(city_db_path)

    def lookup(ip: str) -> str:
        try:
            response = reader.city(ip)
            country = response.country.name or "Desconocido"
            city = response.city.name or ""
            return f"{country}, {city}" if city else country
        except AddressNotFoundError:
            return "Sin datos"
        except Exception:
            return "Sin datos"

    return lookup


def generate_report(conn: sqlite3.Connection, stats: dict, geoip_lookup: Callable[[str], str] | None = None) -> str:
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
            location = geoip_lookup(ip) if geoip_lookup else None
            location_text = f" | GeoIP: {location}" if location else ""
            lines.append(
                f"- {ip} | Jail: {jail} | Eventos: {total_events} | "
                f"Primera vez: {first_seen} | Última vez: {last_seen}{location_text}"
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
        log_event("telegram_skipped", reason="not_configured")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    response = requests.post(url, data={
        "chat_id": chat_id,
        "text": message
    }, timeout=15)

    response.raise_for_status()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GuardianFail - Inteligencia defensiva para logs de Fail2Ban")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Ruta al archivo de configuración JSON.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Ejecuta análisis sin persistir datos ni guardar reportes en disco.",
    )
    parser.add_argument(
        "--no-telegram",
        action="store_true",
        help="Desactiva el envío de reportes por Telegram en esta ejecución.",
    )
    parser.add_argument(
        "--log-level",
        choices=sorted(VALID_LOG_LEVELS),
        help="Nivel de logging para esta ejecución (sobrescribe config.json).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    effective_log_level = args.log_level or config.get("log_level", "INFO")
    setup_logging(effective_log_level)
    ensure_directories(config)
    retention_days = config.get("event_retention_days", 90)
    geoip_city_db_path = config.get("geoip_city_db_path", "") or discover_geoip_city_db_path()
    db_path = ":memory:" if args.dry_run else config["database_path"]
    conn = connect_db(db_path)

    try:
        events = parse_fail2ban_log(config["fail2ban_log"])
        log_event("events_parsed", total=len(events), dry_run=args.dry_run)
        stats = save_events(conn, events)

        pruned_count = 0
        if not args.dry_run:
            pruned_count = prune_old_events(conn, retention_days)
            log_event("events_pruned", deleted=pruned_count, retention_days=retention_days)

        geoip_lookup = build_geoip_lookup(geoip_city_db_path)
        report = generate_report(conn, stats, geoip_lookup=geoip_lookup)
        print(report)

        if args.dry_run:
            log_event("dry_run_completed", note="No se guardó reporte ni se envió Telegram.")
            return

        report_path = save_report(report)
        print()
        print(f"Reporte guardado en: {report_path}")
        print(f"Eventos antiguos eliminados por retención ({retention_days} días): {pruned_count}")

        if args.no_telegram:
            log_event("telegram_skipped", reason="disabled_by_flag")
        else:
            send_telegram_message(
                bot_token=config.get("telegram_bot_token", ""),
                chat_id=config.get("telegram_chat_id", ""),
                message=report
            )
            log_event("telegram_sent", chat_id=config.get("telegram_chat_id", ""))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
