#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import importlib.util
import tempfile
import unittest
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "collector.py"
spec = importlib.util.spec_from_file_location("argent_collector_guardrails", MODULE_PATH)
assert spec and spec.loader
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)

UTC = dt.timezone.utc
FIXED_NOW = dt.datetime(2026, 7, 23, 20, 30, 0, tzinfo=UTC)


class ReportingGuardrailTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_utc_now = collector_module.utc_now
        collector_module.utc_now = lambda: FIXED_NOW
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "state_db": str(root / "state.sqlite3"),
                "lock_file": str(root / "collector.lock"),
                "incoming_globs": [str(root / "incoming" / "*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "crowdsec": {"enabled": False},
                "enrichment": {"enabled": False},
                "abuse_reporting": {
                    "enabled": True,
                    "test_mode": True,
                    "from": "postmaster@argentwolf.org",
                    "recipient_override": "goshawk066@gmail.com",
                    "max_reports_per_run": 3,
                    "max_report_age_hours": 24,
                    "recipient_cooldown_minutes": 0,
                    "max_reports_per_recipient_per_day": 10,
                    "retry_backoff_minutes": 60,
                },
            },
        )
        self.collector = collector_module.Collector(self.config)

    def tearDown(self) -> None:
        self.collector.close()
        self.temp.cleanup()
        collector_module.utc_now = self.original_utc_now

    def add_incident(
        self,
        *,
        source_ip: str,
        last_seen_epoch: int | None = None,
        report_status: str = "disabled",
    ) -> str:
        epoch = int(last_seen_epoch if last_seen_epoch is not None else FIXED_NOW.timestamp() - 10)
        incident_uuid = str(uuid.uuid4())
        now_text = collector_module.utc_text(FIXED_NOW)
        with self.collector.db.conn:
            self.collector.db.conn.execute(
                """INSERT INTO incidents
                (incident_uuid, source_ip, rule_id, first_seen_epoch, last_seen_epoch,
                 first_seen, last_seen, event_count, distinct_accounts, site_count,
                 network_cidr, decision_status, report_status, created_at, updated_at)
                VALUES (?, ?, 'wordpress-credential-spray', ?, ?, ?, ?, 11, 4, 1,
                        ?, 'applied', ?, ?, ?)""",
                (
                    incident_uuid,
                    source_ip,
                    epoch,
                    epoch,
                    collector_module.epoch_text(epoch),
                    collector_module.epoch_text(epoch),
                    collector_module.candidate_network(source_ip),
                    report_status,
                    now_text,
                    now_text,
                ),
            )
        return incident_uuid

    def test_production_reporting_requires_cutoff(self) -> None:
        config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "abuse_reporting": {
                    "enabled": True,
                    "test_mode": False,
                    "from": "postmaster@argentwolf.org",
                    "report_not_before_utc": "",
                }
            },
        )
        with self.assertRaisesRegex(collector_module.CollectorError, "report_not_before_utc"):
            collector_module.validate_config(config)

    def test_recipient_override_requires_test_mode(self) -> None:
        config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "abuse_reporting": {
                    "enabled": False,
                    "test_mode": False,
                    "recipient_override": "goshawk066@gmail.com",
                }
            },
        )
        with self.assertRaisesRegex(collector_module.CollectorError, "recipient_override"):
            collector_module.validate_config(config)

    def test_cutoff_suppresses_historical_backlog_without_enrichment(self) -> None:
        self.collector.config["abuse_reporting"].update(
            {
                "test_mode": False,
                "recipient_override": "",
                "report_not_before_utc": "2026-07-23T20:00:00Z",
            }
        )
        incident_uuid = self.add_incident(
            source_ip="198.199.90.202",
            last_seen_epoch=int(dt.datetime(2026, 7, 23, 19, 59, tzinfo=UTC).timestamp()),
        )
        self.collector.enrich = lambda source_ip: self.fail("cutoff should run before enrichment")

        self.collector.retry_pending_incidents()

        row = self.collector.db.incident(incident_uuid)
        self.assertEqual("suppressed", row["report_status"])
        self.assertIn("predates report_not_before_utc", row["report_detail"])
        attempts = self.collector.db.conn.execute(
            "SELECT status FROM report_attempts WHERE incident_uuid = ?", (incident_uuid,)
        ).fetchall()
        self.assertEqual(["suppressed"], [item["status"] for item in attempts])

    def test_max_reports_per_run_caps_processing(self) -> None:
        self.collector.config["abuse_reporting"]["max_reports_per_run"] = 2
        incident_ids = [
            self.add_incident(source_ip=f"198.51.100.{index}")
            for index in (10, 11, 12)
        ]
        self.collector.enrich = lambda source_ip: {
            "abuse_emails": ["abuse@example.net"],
            "network_class": "hosting",
        }
        sent: list[str] = []

        def fake_send(incident, enrichment, recipients):
            sent.append(str(incident["incident_uuid"]))
            return "sent", "unit-test sent", f"<{incident['incident_uuid']}@argentwolf.org>"

        self.collector.send_abuse_report = fake_send
        self.collector.retry_pending_incidents()

        self.assertEqual(2, len(sent))
        statuses = {
            incident_uuid: self.collector.db.incident(incident_uuid)["report_status"]
            for incident_uuid in incident_ids
        }
        self.assertEqual(2, list(statuses.values()).count("sent"))
        self.assertEqual(1, list(statuses.values()).count("disabled"))

    def test_recipient_cooldown_defers_report(self) -> None:
        self.collector.config["abuse_reporting"]["recipient_cooldown_minutes"] = 15
        incident_uuid = self.add_incident(source_ip="203.0.113.50")
        self.collector.db.record_report_attempt(
            incident_uuid,
            ["goshawk066@gmail.com"],
            "sent",
            "prior report",
            test_mode=True,
            attempted_epoch=int(FIXED_NOW.timestamp()) - 60,
        )
        result = self.collector.report_recipient_gate(["goshawk066@gmail.com"])
        self.assertIsNotNone(result)
        status, detail, next_epoch = result
        self.assertEqual("deferred", status)
        self.assertIn("cooldown", detail)
        self.assertGreater(next_epoch, int(FIXED_NOW.timestamp()))

    def test_daily_recipient_limit_defers_report(self) -> None:
        self.collector.config["abuse_reporting"].update(
            {
                "recipient_cooldown_minutes": 0,
                "max_reports_per_recipient_per_day": 2,
            }
        )
        incident_uuid = self.add_incident(source_ip="203.0.113.51")
        for offset in (3600, 1800):
            self.collector.db.record_report_attempt(
                incident_uuid,
                ["goshawk066@gmail.com"],
                "sent",
                "prior report",
                test_mode=True,
                attempted_epoch=int(FIXED_NOW.timestamp()) - offset,
            )
        result = self.collector.report_recipient_gate(["goshawk066@gmail.com"])
        self.assertIsNotNone(result)
        status, detail, next_epoch = result
        self.assertEqual("deferred", status)
        self.assertIn("rolling 24-hour limit", detail)
        self.assertGreater(next_epoch, int(FIXED_NOW.timestamp()))

    def test_failed_send_sets_retry_backoff_and_audit(self) -> None:
        incident_uuid = self.add_incident(source_ip="198.51.100.99")
        self.collector.enrich = lambda source_ip: {
            "abuse_emails": ["abuse@example.net"],
            "network_class": "hosting",
        }
        self.collector.send_abuse_report = lambda incident, enrichment, recipients: (
            "failed",
            "unit-test send failure",
            "<failed@argentwolf.org>",
        )

        self.collector.retry_pending_incidents()

        row = self.collector.db.incident(incident_uuid)
        self.assertEqual("failed", row["report_status"])
        self.assertEqual(int(FIXED_NOW.timestamp()) + 3600, row["next_report_after_epoch"])
        attempt = self.collector.db.conn.execute(
            "SELECT status, detail FROM report_attempts WHERE incident_uuid = ?",
            (incident_uuid,),
        ).fetchone()
        self.assertEqual("failed", attempt["status"])
        self.assertEqual("unit-test send failure", attempt["detail"])


if __name__ == "__main__":
    unittest.main()
