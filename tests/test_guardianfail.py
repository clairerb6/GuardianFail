import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from guardianfail import (
    calculate_risk,
    connect_db,
    load_config,
    parse_args,
    parse_fail2ban_log,
    prune_old_events,
)


class GuardianFailTests(unittest.TestCase):
    def test_parse_fail2ban_log_extracts_ban_events(self):
        log_content = (
            "2026-05-27 12:00:00,123 fail2ban.actions [1111]: NOTICE [sshd] Ban 192.168.1.10\n"
            "2026-05-27 12:01:00,123 fail2ban.actions [1111]: NOTICE [nginx-http-auth] Ban 10.0.0.2\n"
            "linea invalida\n"
        )

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write(log_content)
            log_path = f.name

        events = parse_fail2ban_log(log_path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["ip"], "192.168.1.10")
        self.assertEqual(events[0]["jail"], "sshd")
        self.assertEqual(events[0]["event_datetime"], "2026-05-27 12:00:00")

    def test_parse_fail2ban_log_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            parse_fail2ban_log("/tmp/no-existe.log")

    def test_calculate_risk_levels(self):
        self.assertEqual(calculate_risk(5, 1, 0), "Bajo")
        self.assertEqual(calculate_risk(12, 1, 0), "Bajo")
        self.assertEqual(calculate_risk(35, 1, 0), "Medio")
        self.assertEqual(calculate_risk(35, 6, 0), "Alto")
        self.assertEqual(calculate_risk(35, 6, 3), "Crítico")

    def test_load_config_validates_required_fields(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            json.dump({"database_path": "data/a.db"}, f)
            config_path = f.name

        with self.assertRaises(ValueError):
            load_config(config_path)

    def test_load_config_rejects_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write("{ invalid json }")
            config_path = f.name

        with self.assertRaises(ValueError):
            load_config(config_path)

    def test_load_config_accepts_valid_config(self):
        config_data = {
            "fail2ban_log": "sample/fail2ban-sample.log",
            "database_path": "data/guardianfail.db",
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "own_server_ip": "",
            "enable_own_server_audit": False,
            "event_retention_days": 90,
            "log_level": "INFO",
        }

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            json.dump(config_data, f)
            config_path = f.name

        loaded = load_config(config_path)
        self.assertEqual(loaded["database_path"], "data/guardianfail.db")

    def test_load_config_rejects_invalid_retention_days(self):
        config_data = {
            "fail2ban_log": "sample/fail2ban-sample.log",
            "database_path": "data/guardianfail.db",
            "event_retention_days": 0,
        }
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            json.dump(config_data, f)
            config_path = f.name

        with self.assertRaises(ValueError):
            load_config(config_path)

    def test_load_config_rejects_invalid_log_level(self):
        config_data = {
            "fail2ban_log": "sample/fail2ban-sample.log",
            "database_path": "data/guardianfail.db",
            "log_level": "TRACE",
        }
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            json.dump(config_data, f)
            config_path = f.name

        with self.assertRaises(ValueError):
            load_config(config_path)

    def test_prune_old_events_deletes_only_older_than_cutoff(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                jail TEXT NOT NULL,
                event_datetime TEXT NOT NULL,
                raw_line TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO events (ip, jail, event_datetime, raw_line) VALUES (?, ?, ?, ?)",
            ("1.1.1.1", "sshd", "2000-01-01 00:00:00", "old"),
        )
        conn.execute(
            "INSERT INTO events (ip, jail, event_datetime, raw_line) VALUES (?, ?, ?, ?)",
            ("2.2.2.2", "sshd", "2099-01-01 00:00:00", "new"),
        )
        conn.commit()

        deleted = prune_old_events(conn, retention_days=30)

        remaining = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(deleted, 1)
        self.assertEqual(remaining, 1)

    def test_connect_db_creates_retention_index(self):
        conn = connect_db(":memory:")
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_events_event_datetime'"
            ).fetchone()
            self.assertIsNotNone(row)
        finally:
            conn.close()

    def test_parse_args_flags(self):
        with patch.object(
            sys,
            "argv",
            ["guardianfail.py", "--config", "x.json", "--dry-run", "--no-telegram", "--log-level", "DEBUG"],
        ):
            args = parse_args()
        self.assertEqual(args.config, "x.json")
        self.assertTrue(args.dry_run)
        self.assertTrue(args.no_telegram)
        self.assertEqual(args.log_level, "DEBUG")


if __name__ == "__main__":
    unittest.main()
