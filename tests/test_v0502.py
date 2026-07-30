#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import tempfile
import unittest
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "collector.py"
spec = importlib.util.spec_from_file_location(
    "argent_collector_v0502",
    MODULE_PATH,
)
assert spec and spec.loader
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)


class PersistentWordPressPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.incoming = root / "incoming"
        self.incoming.mkdir(parents=True)
        self.config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "state_db": str(root / "state.sqlite3"),
                "lock_file": str(root / "collector.lock"),
                "incoming_globs": [str(self.incoming / "*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "abuse_context": {"enabled": False},
                "crowdsec": {"enabled": False},
                "enrichment": {"enabled": False},
                "abuse_reporting": {"enabled": False},
            },
        )
        self.collector = collector_module.Collector(self.config)
        self.base = (
            collector_module.utc_now()
            - dt.timedelta(hours=23)
        ).replace(microsecond=0)

    def tearDown(self) -> None:
        self.collector.close()
        self.temp.cleanup()

    def write_batch(
        self,
        *,
        offsets_hours: list[float],
        user_ids: list[int],
        source_ip: str = "198.51.100.77",
        site_id: str = "wolfandraven-blog",
    ) -> Path:
        self.assertEqual(len(offsets_hours), len(user_ids))
        events = []
        for offset, user_id in zip(offsets_hours, user_ids):
            timestamp = self.base + dt.timedelta(hours=offset)
            timestamp_text = collector_module.utc_text(timestamp)
            events.append(
                {
                    "event_uuid": str(uuid.uuid4()),
                    "occurred_at": timestamp_text,
                    "recorded_at": timestamp_text,
                    "event_type": "login_failed",
                    "severity": "warning",
                    "outcome": "denied",
                    "source_ip": source_ip,
                    "source_ip_version": 4,
                    "username": f"user{user_id}",
                    "wordpress_user_id": user_id,
                    "email_domain": None,
                    "email_identifier": None,
                    "user_agent": "Persistent Policy Test",
                    "request": {
                        "method": "POST",
                        "path": "/wp-login.php",
                    },
                    "metadata": {"account_resolution": "found"},
                }
            )
        batch_uuid = str(uuid.uuid4())
        batch = {
            "schema_version": 1,
            "batch_uuid": batch_uuid,
            "created_at": collector_module.utc_text(
                max(
                    self.base + dt.timedelta(hours=value)
                    for value in offsets_hours
                )
            ),
            "source": {
                "host": "nidhoggur",
                "site_id": site_id,
                "site_url": f"https://{site_id}.example/",
                "service": "wordpress",
                "plugin_version": "0.2.0",
            },
            "events": events,
        }
        path = self.incoming / f"batch-{batch_uuid}.json"
        path.write_text(json.dumps(batch), encoding="utf-8")
        return path

    def incidents(self):
        return list(
            self.collector.db.conn.execute(
                "SELECT * FROM incidents ORDER BY rule_id, site_id"
            )
        )

    def test_six_failures_two_accounts_triggers_persistent_spray(self) -> None:
        self.write_batch(
            offsets_hours=[0, 4, 8, 12, 16, 20],
            user_ids=[1, 2, 1, 2, 1, 2],
        )
        self.collector.run()
        rows = self.incidents()
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual(
            "wordpress-persistent-credential-spray",
            row["rule_id"],
        )
        self.assertEqual("wolfandraven-blog", row["site_id"])
        self.assertEqual(6, row["event_count"])
        self.assertEqual(2, row["distinct_accounts"])
        self.assertEqual("dry-run", row["decision_status"])
        self.assertEqual("suppressed", row["report_status"])
        self.assertEqual(
            "Persistent WordPress policy reporting disabled "
            "pending production review",
            row["report_detail"],
        )

    def test_five_failures_do_not_trigger_persistent_spray(self) -> None:
        self.write_batch(
            offsets_hours=[0, 4, 8, 12, 16],
            user_ids=[1, 2, 1, 2, 1],
        )
        self.collector.run()
        self.assertEqual([], self.incidents())

    def test_twelve_single_account_failures_trigger(self) -> None:
        self.write_batch(
            offsets_hours=[float(value) for value in range(0, 24, 2)],
            user_ids=[1] * 12,
        )
        self.collector.run()
        row = self.incidents()[0]
        self.assertEqual(
            "wordpress-persistent-single-account-bruteforce",
            row["rule_id"],
        )
        self.assertEqual(12, row["event_count"])
        self.assertEqual(1, row["distinct_accounts"])

    def test_eleven_single_account_failures_do_not_trigger(self) -> None:
        self.write_batch(
            offsets_hours=[float(value) for value in range(0, 22, 2)],
            user_ids=[1] * 11,
        )
        self.collector.run()
        self.assertEqual([], self.incidents())

    def test_separate_sites_do_not_combine_to_reach_threshold(self) -> None:
        source_ip = "198.51.100.88"
        self.write_batch(
            offsets_hours=[0, 8, 16],
            user_ids=[1, 2, 1],
            source_ip=source_ip,
            site_id="site-a",
        )
        self.collector.run()
        self.write_batch(
            offsets_hours=[4, 12, 20],
            user_ids=[1, 2, 1],
            source_ip=source_ip,
            site_id="site-b",
        )
        self.collector.run()
        self.assertEqual([], self.incidents())

    def test_two_qualifying_sites_create_separate_incidents(self) -> None:
        source_ip = "198.51.100.89"
        offsets = [0, 4, 8, 12, 16, 20]
        users = [1, 2, 1, 2, 1, 2]
        self.write_batch(
            offsets_hours=offsets,
            user_ids=users,
            source_ip=source_ip,
            site_id="site-a",
        )
        self.collector.run()
        self.write_batch(
            offsets_hours=offsets,
            user_ids=users,
            source_ip=source_ip,
            site_id="site-b",
        )
        self.collector.run()
        rows = self.incidents()
        self.assertEqual(2, len(rows))
        self.assertEqual({"site-a", "site-b"}, {row["site_id"] for row in rows})

    def test_short_window_evidence_does_not_duplicate_persistent(self) -> None:
        self.write_batch(
            offsets_hours=[0, 0.001, 0.002, 0.003, 0.004, 0.005],
            user_ids=[1, 2, 1, 2, 1, 2],
        )
        self.collector.run()
        rows = self.incidents()
        self.assertEqual(1, len(rows))
        self.assertEqual("wordpress-credential-spray", rows[0]["rule_id"])
        self.assertIsNone(rows[0]["site_id"])

    def test_repeat_scans_and_new_evidence_merge(self) -> None:
        self.write_batch(
            offsets_hours=[0, 4, 8, 12, 16, 20],
            user_ids=[1, 2, 1, 2, 1, 2],
        )
        self.collector.run()
        original = self.incidents()[0]["incident_uuid"]

        self.collector.run()
        self.assertEqual(1, len(self.incidents()))

        self.write_batch(
            offsets_hours=[22],
            user_ids=[1],
        )
        self.collector.run()
        rows = self.incidents()
        self.assertEqual(1, len(rows))
        self.assertEqual(original, rows[0]["incident_uuid"])
        self.assertEqual(7, rows[0]["event_count"])

    def test_normal_decision_flow_runs_while_report_is_suppressed(self) -> None:
        self.collector.config["crowdsec"]["enabled"] = True
        self.collector.apply_decision = lambda incident: (
            "applied",
            "unit-test persistent decision",
        )
        self.write_batch(
            offsets_hours=[0, 4, 8, 12, 16, 20],
            user_ids=[1, 2, 1, 2, 1, 2],
        )
        self.collector.run()
        row = self.incidents()[0]
        self.assertEqual("applied", row["decision_status"])
        self.assertEqual(
            "unit-test persistent decision",
            row["decision_detail"],
        )
        self.assertEqual("suppressed", row["report_status"])

    def test_disabling_persistent_policy_leaves_spaced_events_unmatched(self) -> None:
        self.collector.config["persistent_wordpress_policy"]["enabled"] = False
        self.write_batch(
            offsets_hours=[0, 4, 8, 12, 16, 20],
            user_ids=[1, 2, 1, 2, 1, 2],
        )
        self.collector.run()
        self.assertEqual([], self.incidents())

    def test_trusted_source_is_excluded(self) -> None:
        self.write_batch(
            offsets_hours=[0, 4, 8, 12, 16, 20],
            user_ids=[1, 2, 1, 2, 1, 2],
            source_ip="192.168.1.50",
        )
        self.collector.run()
        self.assertEqual([], self.incidents())

    def test_sshd_report_connection_uses_ssh_scheme(self) -> None:
        occurred_at = collector_module.utc_text(self.base)
        evidence = [
            {
                "occurred_at": occurred_at,
                "source_ip": "122.180.242.27",
                "source_port": 48586,
                "destination_ip": "108.226.59.220",
                "destination_port": 22,
                "transport_protocol": "TCP",
                "application_protocol": "SSH",
                "service": "sshd",
                "metadata_json": "{}",
            }
        ]
        connections = self.collector._report_connections(
            {"source_ip": "122.180.242.27"},
            evidence,
            [],
            {"*": {"A": ["108.226.59.220"], "AAAA": []}},
            ["108.226.59.220"],
        )
        self.assertEqual(1, len(connections))
        self.assertEqual("ssh", connections[0]["scheme"])
        line = self.collector._normalized_evidence_line(connections[0])
        self.assertIn('scheme="ssh"', line)
        self.assertNotIn('scheme="http"', line)

    def test_schema_migration_exposes_site_id(self) -> None:
        columns = {
            row["name"]
            for row in self.collector.db.conn.execute(
                "PRAGMA table_info(incidents)"
            )
        }
        self.assertIn("site_id", columns)
        row = self.collector.db.conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        self.assertEqual("9", row["value"])


if __name__ == "__main__":
    unittest.main()
