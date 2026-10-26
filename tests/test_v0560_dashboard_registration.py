#!/usr/bin/env python3
# tests/test_v0560_dashboard_registration.py
"""Dashboard snapshot/UI and daily digest surface registration_abuse (0.5.6.0).

The collector computes Access Guard registration-abuse fingerprint campaigns
on demand (``status``); the read-only dashboard snapshot and daily review
digest must show the same review-only view. Fixtures are synthetic: arbitrary
site IDs, fabricated Access Guard metadata, documentation-range addresses.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402
import dashboard  # noqa: E402
import dashboard_snapshot  # noqa: E402
import review_digest  # noqa: E402

SIGNATURE = "b" * 64


def registration_event(source_ip: str, minutes_ago: int, *, signature: str = SIGNATURE) -> dict:
    occurred = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
    stamp = occurred.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "event_uuid": str(uuid.uuid4()),
        "occurred_at": stamp,
        "recorded_at": stamp,
        "event_type": "registration_abuse",
        "severity": "notice",
        "outcome": "denied",
        "source_ip": source_ip,
        "user_agent": "Mozilla/5.0 (synthetic)",
        "request": {"method": "POST", "path": "/wp-login.php"},
        "metadata": {
            "producer": "argentwolf-access-guard",
            "producer_schema": "argentwolf.access_guard.abuse.v1",
            "score": 6.5,
            "confidence": "medium",
            "rule_ids": ["AWAG_FORM_LT_2S", "AWAG_HONEYPOT"],
            "policy_action": "reject",
            "fingerprint_signature": signature,
            "handoff": "argentwolf_access_guard_sentinel_external_event_v1",
        },
    }


def no_subprocess(command, **kwargs):
    if command[1:3] == ["allowlists", "check"]:
        return subprocess.CompletedProcess(command, 1, stdout="not allowlisted", stderr="")
    raise AssertionError(f"unexpected subprocess call: {command}")


class DashboardRegistrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.instances: list[collector.Collector] = []

    def tearDown(self) -> None:
        for instance in self.instances:
            instance.close()
        self.temp.cleanup()

    def config(self, **policy) -> dict:
        settings = {"enabled": True}
        settings.update(policy)
        supplied = {
            "state_db": str(self.root / "state.sqlite3"),
            "lock_file": str(self.root / "collector.lock"),
            "incoming_globs": [str(self.root / "drop/wordpress/*/incoming/*.json")],
            "processing_dir": str(self.root / "processing"),
            "archive_dir": str(self.root / "archive"),
            "rejected_dir": str(self.root / "rejected"),
            "crowdsec": {"enabled": True, "cscli_path": "/usr/bin/cscli"},
            "enrichment": {"enabled": False},
            "abuse_reporting": {"enabled": False},
            "persistent_wordpress_policy": {"enabled": False},
            "registration_abuse_policy": settings,
        }
        config = collector.deep_merge(collector.DEFAULTS, supplied)
        collector.validate_config(config)
        (self.root / "collector.json").write_text(json.dumps(supplied))
        return config

    def deliver(self, site_id: str, events: list[dict]) -> None:
        incoming = self.root / "drop" / "wordpress" / site_id / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        batch = {
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": {
                "host": "example-host",
                "site_id": site_id,
                "site_url": f"https://{site_id}.example.test/",
                "service": "wordpress",
                "plugin_version": "0.2.6",
            },
            "events": events,
        }
        (incoming / f"{uuid.uuid4()}.json").write_text(json.dumps(batch))

    def run_collector(self, config: dict) -> collector.Collector:
        instance = collector.Collector(config)
        self.instances.append(instance)
        with mock.patch.object(collector.subprocess, "run", side_effect=no_subprocess):
            instance.run()
        return instance

    def snapshot(self) -> dict:
        return dashboard_snapshot.build_snapshot(dashboard_snapshot.deep_merge(dashboard_snapshot.DEFAULTS, {
            "state_db": str(self.root / "state.sqlite3"),
            "collector_config": str(self.root / "collector.json"),
            "report_batch_state_file": str(self.root / "batch.json"),
            "lock_file": str(self.root / "snapshot.lock"),
            "traffic_sites_config": str(self.root / "sites.json"),
            "awstats_root": str(self.root / "awstats"),
            "watchdog_state_dir": str(self.root / "watchdogs"),
        }))

    def digest(self) -> str:
        supplied = json.loads((self.root / "collector.json").read_text())
        supplied["daily_review"] = {"max_rows": 20, "max_network_rows": 20}
        connection = sqlite3.connect(f"file:{self.root / 'state.sqlite3'}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            now = int(time.time())
            return review_digest.render_digest(supplied, connection, now - 86400, now + 60)
        finally:
            connection.close()

    def two_site_campaign(self) -> None:
        # One event per IP (below per-IP thresholds), five IPs, two sites.
        self.deliver("site-alpha", [registration_event(f"203.0.113.{10 + i}", 10 + i) for i in range(3)])
        self.deliver("site-beta", [registration_event(f"203.0.113.{20 + i}", 20 + i) for i in range(2)])
        # Trusted source with the same signature must never appear.
        self.deliver("site-beta", [registration_event("192.168.10.5", 5)])

    def test_snapshot_matches_status_campaigns(self) -> None:
        self.two_site_campaign()
        instance = self.run_collector(self.config())
        expected = collector.status_output(instance)["registration_abuse_campaigns"]
        self.assertEqual(1, len(expected))

        snapshot = self.snapshot()
        campaigns = snapshot["registration_abuse_campaigns"]
        self.assertEqual(1, len(campaigns))
        [campaign] = campaigns
        self.assertFalse(campaign.pop("automatic_block"))
        self.assertEqual(expected[0], campaign)
        self.assertEqual(SIGNATURE, campaign["fingerprint_signature"])
        self.assertEqual(["site-alpha", "site-beta"], campaign["sites"])
        self.assertEqual(5, campaign["distinct_source_ips"])
        self.assertNotIn("192.168.10.5", campaign["sample_source_ips"])
        self.assertTrue(all(item["review_only"] for item in campaign["prefix_proposals"]))
        self.assertEqual(
            {"enabled": True, "crowdsec_enforcement": False, "window_seconds": 86400},
            snapshot["registration_abuse_policy"],
        )
        overview = snapshot["overview"]
        self.assertEqual(1, overview["registration_abuse_campaigns"])
        self.assertEqual(6, overview["registration_abuse_events"])
        self.assertEqual(0, overview["mail_auth_failures"])
        self.assertIn("mail_account_campaigns", snapshot)

        html = dashboard.render_incidents(snapshot)
        self.assertIn("Access Guard registration-abuse campaigns", html)
        self.assertIn("Mail account slow-burn campaigns", html)
        self.assertIn(SIGNATURE[:16], html)
        self.assertIn("site-alpha, site-beta", html)
        self.assertIn("203.0.113.0/27 (5)", html)
        self.assertIn("review-only", html)
        self.assertIn("no range, ASN, or country ban is automatic", html)
        self.assertIn("dry-run", html)
        self.assertNotIn("192.168.10.5", html)

        overview_html = dashboard.render_overview(snapshot)
        self.assertIn("Registration abuse events", overview_html)
        self.assertIn("Mail auth failures", overview_html)

        body = self.digest()
        self.assertIn("Access Guard registration-abuse campaigns", body)
        self.assertIn(f"Fingerprint: {SIGNATURE[:16]} on site-alpha, site-beta", body)
        self.assertIn("Events / denied / distinct source IPs: 5 / 5 / 5", body)
        self.assertIn("Prefix proposals (review-only): 203.0.113.0/27 (5 IPs)", body)
        self.assertNotIn("192.168.10.5", body)

    def test_disabled_policy_shows_state_but_no_campaigns(self) -> None:
        self.two_site_campaign()
        self.run_collector(self.config(enabled=False))
        snapshot = self.snapshot()
        self.assertEqual([], snapshot["registration_abuse_campaigns"])
        self.assertFalse(snapshot["registration_abuse_policy"]["enabled"])
        self.assertEqual(6, snapshot["overview"]["registration_abuse_events"])
        html = dashboard.render_incidents(snapshot)
        self.assertIn("registration_abuse_policy is disabled", html)
        self.assertIn("policy disabled", self.digest())

    def test_mail_auth_failures_counted_in_overview(self) -> None:
        self.deliver("site-alpha", [registration_event("203.0.113.40", 3)])
        instance = self.run_collector(self.config())
        row = instance.db.conn.execute("SELECT batch_uuid FROM events LIMIT 1").fetchone()
        now = int(time.time())
        for index in range(3):
            instance.db.conn.execute(
                """INSERT INTO events (event_uuid, batch_uuid, occurred_epoch, occurred_at,
                       site_id, source_host, service, event_type, outcome, source_ip,
                       account_key, metadata_json)
                   VALUES (?, ?, ?, ?, 'mail-node', 'node', 'mail', 'mail_auth_failed',
                           'denied', ?, ?, '{}')""",
                (str(uuid.uuid4()), row[0], now - 60 * index, collector.epoch_text(now - 60 * index),
                 f"198.51.100.{index + 1}", "mail-node:account:" + "c" * 64),
            )
        instance.db.conn.commit()
        snapshot = self.snapshot()
        self.assertEqual(3, snapshot["overview"]["mail_auth_failures"])
        self.assertEqual(1, snapshot["overview"]["registration_abuse_events"])
        self.assertEqual([], snapshot["registration_abuse_campaigns"])

    def test_snapshot_tolerates_missing_policy_and_legacy_config(self) -> None:
        self.deliver("site-alpha", [registration_event("203.0.113.50", 3)])
        self.run_collector(self.config())
        (self.root / "collector.json").write_text("{}")
        snapshot = self.snapshot()
        self.assertEqual([], snapshot["registration_abuse_campaigns"])
        self.assertFalse(snapshot["registration_abuse_policy"]["enabled"])
        html = dashboard.render_incidents({"recent_incidents": []})
        self.assertIn("Policy state not present", html)


if __name__ == "__main__":
    unittest.main()
