#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import importlib.util
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/collector.py"
spec = importlib.util.spec_from_file_location("argent_collector_v042", MODULE_PATH)
assert spec and spec.loader
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)

UTC = dt.timezone.utc
FIXED_NOW = dt.datetime(2026, 7, 24, 20, 45, 0, tzinfo=UTC)


class CompletedSendmail:
    returncode = 0
    stdout = b""
    stderr = b""


class V042Test(unittest.TestCase):
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
                "incoming_globs": [str(root / "incoming/*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "crowdsec": {"enabled": True},
                "abuse_reporting": {
                    "enabled": True,
                    "test_mode": True,
                    "from": "postmaster@argentwolf.org",
                    "admin_copy": "postmaster@argentwolf.org",
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

    def add_incident(self, source_ip: str, report_status: str = "pending") -> str:
        incident_uuid = str(uuid.uuid4())
        epoch = int(FIXED_NOW.timestamp()) - 10
        now_text = collector_module.utc_text(FIXED_NOW)
        with self.collector.db.conn:
            self.collector.db.conn.execute(
                """INSERT INTO incidents
                (incident_uuid, source_ip, rule_id, first_seen_epoch, last_seen_epoch,
                 first_seen, last_seen, event_count, distinct_accounts, site_count,
                 network_cidr, decision_status, report_status, created_at, updated_at)
                VALUES (?, ?, 'nginx-hostile-web-probing', ?, ?, ?, ?, 3, 3, 1,
                        ?, 'refused', ?, ?, ?)""",
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

    def test_test_mode_bypasses_allowlist_and_uses_only_override(self) -> None:
        incident_uuid = self.add_incident("2001:4860:4860::8888")
        incident = self.collector.db.incident(incident_uuid)
        self.collector.source_protection_status = lambda source_ip: (
            "protected",
            "CrowdSec reports address is allowlisted",
        )
        enrichment = {
            "network_cidr": "2001:4860::/32",
            "network_name": "controlled test",
            "asn": 15169,
            "asn_holder": "controlled test",
            "abuse_emails": ["abuse@example.net"],
            "network_class": "hosting",
        }
        with mock.patch.object(
            collector_module.subprocess,
            "run",
            return_value=CompletedSendmail(),
        ) as sendmail:
            status, detail, message_id = self.collector.send_abuse_report(
                incident,
                enrichment,
                ["goshawk066@gmail.com"],
            )
        self.assertEqual("sent", status)
        self.assertIsNotNone(message_id)
        self.assertIn("test bypass", detail)
        payload = sendmail.call_args.kwargs["input"].decode("utf-8", "replace")
        self.assertIn("To: goshawk066@gmail.com", payload)
        self.assertNotIn("Bcc:", payload)
        self.assertIn("TEST MODE", payload)
        from email import policy
        from email.parser import Parser

        message = Parser(policy=policy.default).parsestr(payload)
        decoded_body = message.get_body(
            preferencelist=("plain",)
        ).get_content()

        self.assertIn(
            "Report would normally be suppressed: CrowdSec reports address is allowlisted",
            decoded_body,
        )
        from email import policy as email_policy
        from email.parser import Parser as EmailParser

        parsed_message = EmailParser(
            policy=email_policy.default
        ).parsestr(payload)

        recipient_headers = "\n".join(
            str(parsed_message.get(name, ""))
            for name in ("To", "Cc", "Bcc")
        )

        self.assertEqual(
            "goshawk066@gmail.com",
            str(parsed_message["To"]),
        )
        self.assertIsNone(parsed_message["Cc"])
        self.assertIsNone(parsed_message["Bcc"])
        self.assertNotIn(
            "abuse@example.net",
            recipient_headers,
        )

    def test_production_mode_still_suppresses_protected_source(self) -> None:
        incident_uuid = self.add_incident("2001:4860:4860::8844")
        incident = self.collector.db.incident(incident_uuid)
        self.collector.config["abuse_reporting"].update(
            {"test_mode": False, "recipient_override": ""}
        )
        self.collector.source_protection_status = lambda source_ip: (
            "protected",
            "CrowdSec reports address is allowlisted",
        )
        with mock.patch.object(collector_module.subprocess, "run") as sendmail:
            status, detail, message_id = self.collector.send_abuse_report(
                incident,
                {"abuse_emails": ["abuse@example.net"]},
                ["abuse@example.net"],
            )
        self.assertEqual("suppressed", status)
        self.assertEqual("CrowdSec reports address is allowlisted", detail)
        self.assertIsNone(message_id)
        sendmail.assert_not_called()

    def test_test_mode_continues_after_enrichment_failure(self) -> None:
        incident_uuid = self.add_incident("2001:4860:4860::8822")

        def fail_enrichment(source_ip: str):
            raise collector_module.CollectorError("unit-test RDAP timeout")

        captured: dict[str, object] = {}

        def fake_send(incident, enrichment, recipients):
            captured.update(enrichment)
            self.assertEqual(["goshawk066@gmail.com"], list(recipients))
            return "sent", "unit-test sent", "<v042-test@argentwolf.org>"

        self.collector.enrich = fail_enrichment
        self.collector.send_abuse_report = fake_send
        self.collector.retry_pending_incidents()

        row = self.collector.db.incident(incident_uuid)
        self.assertEqual("sent", row["report_status"])
        self.assertEqual("goshawk066@gmail.com", row["report_recipient"])
        self.assertIn("_test_enrichment_error", captured)
        self.assertIn("unit-test RDAP timeout", str(captured["_test_enrichment_error"]))

    def test_release_versions_are_consistent(self) -> None:
        self.assertEqual("0.5.3.1", (ROOT / "VERSION").read_text().strip())
        for name in ("agent.py", "collector.py", "server_api.py"):
            self.assertIn('APP_VERSION = "0.5.3.1"', (ROOT / "src" / name).read_text())
        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('if upstream != "0.5.3.1":', builder)
        self.assertIn('"test_v042.py"', builder)


if __name__ == "__main__":
    unittest.main()
