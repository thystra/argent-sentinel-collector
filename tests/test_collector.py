#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import contextlib
import datetime as dt
import errno
import io
import json
import sqlite3
import tempfile
import unittest
from unittest import mock
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "collector.py"
spec = importlib.util.spec_from_file_location("argent_collector", MODULE_PATH)
assert spec and spec.loader
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)


class CollectorPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.incoming = root / "drop" / "wordpress" / "test" / "incoming"
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
                "crowdsec": {"enabled": False},
                "enrichment": {"enabled": False},
                "abuse_reporting": {"enabled": False},
            },
        )
        self.collector = collector_module.Collector(self.config)

    def tearDown(self) -> None:
        self.collector.close()
        self.temp.cleanup()

    def write_batch(
        self,
        event_count: int = 5,
        distinct_users: int = 2,
        source_ip: str = "198.199.90.202",
    ) -> Path:
        events = []
        for index in range(event_count):
            user_id = (index % distinct_users) + 1
            events.append(
                {
                    "event_uuid": str(uuid.uuid4()),
                    "occurred_at": f"2026-07-23T17:15:{15 + index:02d}Z",
                    "recorded_at": f"2026-07-23T17:15:{15 + index:02d}Z",
                    "event_type": "login_failed",
                    "severity": "warning",
                    "outcome": "denied",
                    "source_ip": source_ip,
                    "source_ip_version": 4,
                    "username": f"user{user_id}",
                    "wordpress_user_id": user_id,
                    "email_domain": None,
                    "email_identifier": None,
                    "user_agent": "Unit Test",
                    "request": {"method": "POST", "path": "/wp-login.php"},
                    "metadata": {"account_resolution": "found"},
                }
            )
        batch = {
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": "2026-07-23T17:16:00Z",
            "source": {
                "host": "nidhoggur",
                "site_id": "wolfandraven-blog",
                "site_url": "https://www.wolfandraven.blog/",
                "service": "wordpress",
                "plugin_version": "0.2.0",
            },
            "events": events,
        }
        path = self.incoming / f"batch-{batch['batch_uuid']}.json"
        path.write_text(json.dumps(batch), encoding="utf-8")
        return path

    def test_cross_filesystem_claim_falls_back_to_copy_and_unlink(self) -> None:
        source = self.write_batch(5, 2)
        processing = Path(self.config["processing_dir"])
        real_replace = collector_module.os.replace
        forced = False

        def replace_with_exdev(old, new):
            nonlocal forced
            old_path = Path(old)
            new_path = Path(new)
            if not forced and old_path == source and new_path.parent == processing:
                forced = True
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real_replace(old, new)

        with mock.patch.object(collector_module.os, "replace", side_effect=replace_with_exdev):
            imported = self.collector.run()

        self.assertTrue(forced)
        self.assertEqual(1, imported)
        self.assertFalse(source.exists())
        event_count = self.collector.db.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(5, event_count)
        archived = list(Path(self.config["archive_dir"]).rglob("*.json"))
        self.assertEqual(1, len(archived))

    def test_five_failures_two_accounts_creates_dry_run_incident(self) -> None:
        source = self.write_batch(5, 2)
        self.collector.run()
        self.assertFalse(source.exists())
        row = self.collector.db.conn.execute("SELECT * FROM incidents").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual("wordpress-credential-spray", row["rule_id"])
        self.assertEqual(5, row["event_count"])
        self.assertEqual(2, row["distinct_accounts"])
        self.assertEqual("dry-run", row["decision_status"])
        self.assertEqual("disabled", row["report_status"])

    def test_four_failures_do_not_trigger(self) -> None:
        self.write_batch(4, 2)
        self.collector.run()
        count = self.collector.db.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        self.assertEqual(0, count)

    def test_ten_failures_one_account_triggers_secondary_rule(self) -> None:
        self.write_batch(10, 1)
        self.collector.run()
        row = self.collector.db.conn.execute("SELECT * FROM incidents").fetchone()
        self.assertEqual("wordpress-single-account-bruteforce", row["rule_id"])
        self.assertEqual(10, row["event_count"])
        self.assertEqual(1, row["distinct_accounts"])


    def test_dry_run_incident_retries_after_enforcement_is_enabled(self) -> None:
        self.write_batch(5, 2)
        self.collector.run()
        row = self.collector.db.conn.execute("SELECT * FROM incidents").fetchone()
        self.assertEqual("dry-run", row["decision_status"])

        self.collector.config["crowdsec"]["enabled"] = True
        self.collector.apply_decision = lambda incident: ("applied", "unit-test decision")
        self.collector.retry_pending_incidents()

        row = self.collector.db.conn.execute("SELECT * FROM incidents").fetchone()
        self.assertEqual("applied", row["decision_status"])
        self.assertEqual("unit-test decision", row["decision_detail"])


    def test_dry_run_skips_external_enrichment_by_default(self) -> None:
        self.collector.config["enrichment"]["enabled"] = True
        self.collector.enrich = lambda source_ip: self.fail("dry-run should not enrich")
        self.write_batch(5, 2)
        self.collector.run()
        row = self.collector.db.conn.execute("SELECT * FROM incidents").fetchone()
        self.assertEqual("dry-run", row["decision_status"])
        self.assertEqual("disabled", row["report_status"])

    def test_ripe_asn_details_accepts_object_shape(self) -> None:
        payload = {
            "data": {
                "asns": [
                    {"asn": 14061, "holder": "DIGITALOCEAN-ASN"}
                ]
            }
        }
        self.assertEqual(
            (14061, "DIGITALOCEAN-ASN"),
            collector_module.ripe_asn_details(payload),
        )

    def test_ripe_asn_details_accepts_scalar_shape(self) -> None:
        payload = {"data": {"asns": ["8075"], "holder": "MICROSOFT"}}
        self.assertEqual((8075, "MICROSOFT"), collector_module.ripe_asn_details(payload))

    def test_ipv6_rdap_url_preserves_colons(self) -> None:
        self.collector.config["enrichment"]["enabled"] = True
        seen: list[str] = []

        def fake_fetch(url: str, optional: bool = False):
            seen.append(url)
            if "rdap.org" in url:
                return {
                    "startAddress": "2a01:4ff:f0:974f::",
                    "endAddress": "2a01:4ff:f0:974f:ffff:ffff:ffff:ffff",
                }
            return {"data": {"asns": [{"asn": 24940, "holder": "HETZNER-AS"}]}}

        self.collector.fetch_json = fake_fetch
        result = self.collector.enrich("2a01:4ff:f0:974f::1")
        self.assertIn("2a01:4ff:f0:974f::1", seen[0])
        self.assertNotIn("%3A", seen[0])
        self.assertEqual(24940, result["asn"])

    def test_status_does_not_contend_on_run_lock(self) -> None:
        root = Path(self.temp.name)
        config_path = root / "collector.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        output = io.StringIO()
        with collector_module.process_lock(Path(self.config["lock_file"])):
            with contextlib.redirect_stdout(output):
                result = collector_module.main(["--config", str(config_path), "status"])
        self.assertEqual(0, result)
        self.assertIn('"counts"', output.getvalue())

    def test_network_candidate_requires_three_independently_hostile_ips(self) -> None:
        for suffix in (202, 203, 204):
            self.write_batch(5, 2, source_ip=f"198.199.90.{suffix}")
            self.collector.run()

        with mock.patch.object(
            collector_module,
            "utc_now",
            return_value=dt.datetime(2026, 7, 24, tzinfo=dt.timezone.utc),
        ):
            candidates = self.collector.db.network_candidates(
                self.collector.config["policy"]
            )
        self.assertEqual(1, len(candidates))
        self.assertEqual("198.199.90.0/24", candidates[0]["network_cidr"])
        self.assertEqual(3, candidates[0]["hostile_ips"])
        self.assertEqual("review", candidates[0]["recommendation"])
        self.assertFalse(candidates[0]["automatic_block"])

    def test_registered_allocation_does_not_replace_candidate_cidr(self) -> None:
        self.write_batch(5, 2)
        self.collector.run()
        row = self.collector.db.conn.execute("SELECT * FROM incidents").fetchone()
        self.collector.db.update_incident(
            row["incident_uuid"],
            registered_cidr="198.199.64.0/18",
            asn=14061,
            network_class="hosting",
        )
        updated = self.collector.db.incident(row["incident_uuid"])
        self.assertEqual("198.199.90.0/24", updated["network_cidr"])
        self.assertEqual("198.199.64.0/18", updated["registered_cidr"])

    def test_event_uuid_deduplication_across_batches(self) -> None:
        first = self.write_batch(5, 2)
        original = json.loads(first.read_text(encoding="utf-8"))
        self.collector.run()
        duplicate_batch = dict(original)
        duplicate_batch["batch_uuid"] = str(uuid.uuid4())
        path = self.incoming / "duplicate-events.json"
        path.write_text(json.dumps(duplicate_batch), encoding="utf-8")
        self.collector.run()
        count = self.collector.db.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(5, count)


if __name__ == "__main__":
    unittest.main()
