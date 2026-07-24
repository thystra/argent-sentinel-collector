#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "collector.py"
spec = importlib.util.spec_from_file_location("argent_collector_network", MODULE_PATH)
assert spec and spec.loader
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)


class NetworkContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.wp_incoming = root / "drop" / "wordpress" / "test" / "incoming"
        self.context_incoming = root / "drop" / "nginx" / "abuse-context" / "incoming"
        self.wp_incoming.mkdir(parents=True)
        self.context_incoming.mkdir(parents=True)
        self.config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "state_db": str(root / "state.sqlite3"),
                "lock_file": str(root / "collector.lock"),
                "incoming_globs": [str(self.wp_incoming / "*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "crowdsec": {"enabled": False},
                "enrichment": {"enabled": False},
                "abuse_reporting": {"enabled": False},
                "abuse_context": {
                    "enabled": True,
                    "incoming_globs": [str(self.context_incoming / "*.jsonl")],
                    "processing_dir": str(root / "context-processing"),
                    "archive_dir": str(root / "context-archive"),
                    "rejected_dir": str(root / "context-rejected"),
                },
            },
        )
        self.collector = collector_module.Collector(self.config)

    def tearDown(self) -> None:
        self.collector.close()
        self.temp.cleanup()

    def write_wordpress_batch(self, request_id: str = "0123456789abcdef") -> None:
        events = []
        for index in range(5):
            events.append(
                {
                    "event_uuid": str(uuid.uuid4()),
                    "occurred_at": f"2026-07-24T03:10:{10 + index:02d}Z",
                    "recorded_at": f"2026-07-24T03:10:{10 + index:02d}Z",
                    "event_type": "login_failed",
                    "outcome": "denied",
                    "source_ip": "198.51.100.20",
                    "wordpress_user_id": (index % 2) + 1,
                    "user_agent": "Unit Test",
                    "request": {
                        "method": "POST",
                        "path": "/wp-login.php",
                        "request_id": request_id if index == 0 else f"{request_id}{index}",
                    },
                    "metadata": {},
                }
            )
        batch = {
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": "2026-07-24T03:11:00Z",
            "source": {
                "host": "nidhoggur",
                "site_id": "example-site",
                "site_url": "https://example.test/",
                "service": "wordpress",
                "plugin_version": "0.2.1",
            },
            "events": events,
        }
        (self.wp_incoming / "batch.json").write_text(json.dumps(batch), encoding="utf-8")

    def write_context(self, request_id: str = "0123456789abcdef") -> None:
        row = {
            "time_iso8601": "2026-07-24T03:10:10Z",
            "request_id": request_id,
            "remote_addr": "198.51.100.20",
            "remote_port": "53142",
            "server_addr": "203.0.113.10",
            "server_port": "443",
            "transport_protocol": "tcp",
            "server_protocol": "HTTP/2.0",
            "ssl_protocol": "TLSv1.3",
            "host": "example.test",
            "request_method": "POST",
            "request_uri": "/wp-login.php",
            "status": 200,
            "http_user_agent": "Unit Test",
        }
        (self.context_incoming / "access.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")

    def test_jsonl_import_and_request_id_correlation(self) -> None:
        self.write_wordpress_batch()
        self.write_context()
        self.collector.run()
        observation = self.collector.db.conn.execute(
            "SELECT * FROM network_observations"
        ).fetchone()
        self.assertEqual(53142, observation["source_port"])
        self.assertEqual("203.0.113.10", observation["destination_ip"])
        self.assertEqual(443, observation["destination_port"])
        self.assertEqual("TCP", observation["transport_protocol"])
        link = self.collector.db.conn.execute(
            "SELECT correlation_method FROM incident_network_observations"
        ).fetchone()
        self.assertIsNotNone(link)
        self.assertEqual("request-id", link["correlation_method"])

    def test_normalizer_accepts_abuse_context_aliases(self) -> None:
        item = collector_module.normalize_network_observation(
            {
                "@timestamp": "2026-07-24T03:10:10Z",
                "client_ip": "2001:db8::20",
                "client_port": 55000,
                "local_addr": "2001:db8::10",
                "local_port": 443,
                "method": "POST",
                "uri": "/wp-login.php",
                "protocol": "HTTP/2.0",
            },
            "hermod",
        )
        self.assertEqual("2001:db8::20", item["source_ip"])
        self.assertEqual("2001:db8::10", item["destination_ip"])
        self.assertEqual("hermod", item["source_host"])

    def test_cidr_context_uses_qualifying_incidents_only(self) -> None:
        now = collector_module.utc_now()
        epoch = int(now.timestamp())
        with self.collector.db.conn:
            for index in range(3):
                ip = f"198.51.100.{20 + index}"
                self.collector.db.conn.execute(
                    """INSERT INTO incidents
                    (incident_uuid, source_ip, rule_id, first_seen_epoch, last_seen_epoch,
                     first_seen, last_seen, event_count, distinct_accounts, site_count,
                     network_cidr, decision_status, report_status, created_at, updated_at)
                    VALUES (?, ?, 'wordpress-credential-spray', ?, ?, ?, ?, 5, 2, 1,
                            '198.51.100.0/24', 'applied', 'sent', ?, ?)""",
                    (
                        str(uuid.uuid4()), ip, epoch, epoch,
                        collector_module.epoch_text(epoch), collector_module.epoch_text(epoch),
                        collector_module.utc_text(now), collector_module.utc_text(now),
                    ),
                )
        context = self.collector.db.network_context("198.51.100.0/24", self.config["policy"])
        self.assertEqual(3, context["hostile_ips"])
        self.assertEqual(3, context["incident_count"])
        self.assertEqual(15, context["event_count"])
        self.assertEqual("review", context["status"])
        self.collector.db.sync_network_cases(self.config["policy"])
        case = self.collector.db.conn.execute(
            "SELECT status FROM network_cases WHERE network_cidr='198.51.100.0/24'"
        ).fetchone()
        self.assertEqual("review", case["status"])

    def test_manual_block_records_status_without_enforcement(self) -> None:
        self.collector.db.set_network_case("198.51.100.0/24", "blocked", "operator approved")
        row = self.collector.db.conn.execute(
            "SELECT status, operator_note FROM network_cases WHERE network_cidr='198.51.100.0/24'"
        ).fetchone()
        self.assertEqual("blocked", row["status"])
        self.assertEqual("operator approved", row["operator_note"])


if __name__ == "__main__":
    unittest.main()
