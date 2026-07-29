#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/tests/test_v0510.py
"""Regression tests for Argent Sentinel 0.5.1.0."""

from __future__ import annotations

import datetime as dt
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collector import Collector, StateDB  # noqa: E402
from report_batcher import (  # noqa: E402
    ban_only_reason,
    chunked,
    group_candidates,
    report_family,
)
from wordpress_sites import inventory, parse_expected  # noqa: E402


class ReportingBatchTest(unittest.TestCase):
    def test_meta_cidr_and_asn_are_ban_only(self) -> None:
        policy = {
            "asns": [32934],
            "cidrs": ["2a03:2880::/32"],
            "user_agent_tokens": ["meta-externalagent"],
            "allow_user_agent_only": False,
        }
        self.assertIn(
            "2a03:2880::/32",
            ban_only_reason(
                "2a03:2880:f812::1",
                None,
                [],
                policy,
            )
            or "",
        )
        self.assertIn(
            "AS32934",
            ban_only_reason(
                "8.8.8.8",
                32934,
                [],
                policy,
            )
            or "",
        )
        self.assertIsNone(
            ban_only_reason(
                "8.8.8.8",
                None,
                ["Meta-ExternalAgent/1.1"],
                policy,
            )
        )

    def test_grouping_is_by_cidr_family_and_recipient_set(self) -> None:
        candidates = [
            {
                "batch_cidr": "198.51.100.0/24",
                "family": "web",
                "recipients": ("abuse@example.net",),
            },
            {
                "batch_cidr": "198.51.100.0/24",
                "family": "web",
                "recipients": ("abuse@example.net",),
            },
            {
                "batch_cidr": "198.51.100.0/24",
                "family": "sshd",
                "recipients": ("abuse@example.net",),
            },
        ]
        groups = group_candidates(candidates)
        self.assertEqual(2, len(groups))
        self.assertEqual(
            2,
            len(
                groups[
                    (
                        "198.51.100.0/24",
                        "web",
                        ("abuse@example.net",),
                    )
                ]
            ),
        )

    def test_chunking_and_rule_families(self) -> None:
        self.assertEqual(
            [2, 2, 1],
            [len(item) for item in chunked([{}, {}, {}, {}, {}], 2)],
        )
        self.assertEqual("sshd", report_family("sshd-credential-spray"))
        self.assertEqual("web", report_family("nginx-hostile-web-probing"))
        self.assertEqual(
            "wordpress",
            report_family("wordpress-credential-spray"),
        )

    def test_authentication_xarf_uses_login_attack(self) -> None:
        collector = object.__new__(Collector)
        collector.config = {
            "abuse_reporting": {
                "from": "postmaster@example.org",
                "operator_contact": "postmaster@example.org",
                "reporter_org_domain": "example.org",
                "message_id_domain": "example.org",
                "reporter_org": "Example",
                "reporter_contact_name": "Operator",
                "xarf_version": "4.2.0",
                "xarf_max_evidence_lines": 20,
            },
            "node": {"fqdn": "sentinel.example.org"},
        }
        incident = {
            "incident_uuid": "12345678-1234-4234-8234-123456789abc",
            "source_ip": "198.51.100.10",
            "rule_id": "sshd-credential-spray",
            "first_seen": "2026-07-26T10:00:00Z",
            "last_seen": "2026-07-26T10:01:00Z",
            "event_count": 8,
            "registered_cidr": "198.51.100.0/24",
            "asn": 64500,
            "asn_holder": "Example",
        }
        report = collector._xarf_attachment(
            incident,
            {},
            "OpenSSH authentication attacks",
            [
                {
                    "occurred_at": "2026-07-26T10:00:00Z",
                    "source_ip": "198.51.100.10",
                    "source_port": 50000,
                    "public_destination_ip": "203.0.113.5",
                    "observed_destination_ip": "203.0.113.5",
                    "destination_port": 22,
                    "host": "server.example.org",
                    "transport_protocol": "tcp",
                    "application_protocol": "ssh",
                    "scheme": "ssh",
                    "request_uri": "-",
                }
            ],
            ["server.example.org"],
            dt.datetime.now(dt.timezone.utc),
            ["normalized ssh evidence"],
            ["203.0.113.5"],
        )
        self.assertEqual("connection", report["category"])
        self.assertEqual("login_attack", report["type"])
        self.assertEqual("credential_attack", report["scan_type"])
        self.assertEqual("ssh", report["service"])

    def test_minute_path_can_skip_report_only_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            from collector import StateDB

            state = StateDB(database)
            try:
                now = 1785088800
                state.conn.execute(
                    """INSERT INTO incidents
                       (incident_uuid, source_ip, rule_id, first_seen_epoch,
                        last_seen_epoch, first_seen, last_seen, event_count,
                        distinct_accounts, site_count, decision_status,
                        report_status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        "00000000-0000-4000-8000-000000000099",
                        "198.51.100.99",
                        "nginx-hostile-web-probing",
                        now,
                        now,
                        "2026-07-26T10:00:00Z",
                        "2026-07-26T10:00:00Z",
                        3,
                        0,
                        1,
                        "applied",
                        "pending",
                        "2026-07-26T10:00:00Z",
                        "2026-07-26T10:00:00Z",
                    ),
                )
                state.conn.commit()
                self.assertEqual(
                    [],
                    state.pending_incidents(
                        retry_dry_run=False,
                        retry_disabled_reports=True,
                        include_reports=False,
                    ),
                )
                self.assertEqual(
                    1,
                    len(
                        state.pending_incidents(
                            retry_dry_run=False,
                            retry_disabled_reports=True,
                            include_reports=True,
                        )
                    ),
                )
            finally:
                state.close()

    def test_recipient_limits_count_distinct_messages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = StateDB(Path(temporary) / "state.sqlite3")
            try:
                now = 1785088800
                for index in range(2):
                    incident_uuid = f"00000000-0000-4000-8000-{index:012d}"
                    state.conn.execute(
                        """INSERT INTO incidents
                           (incident_uuid, source_ip, rule_id,
                            first_seen_epoch, last_seen_epoch,
                            first_seen, last_seen, event_count,
                            distinct_accounts, site_count,
                            decision_status, report_status,
                            created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            incident_uuid,
                            f"198.51.100.{index + 1}",
                            "nginx-hostile-web-probing",
                            now,
                            now,
                            "2026-07-26T10:00:00Z",
                            "2026-07-26T10:00:00Z",
                            1,
                            0,
                            1,
                            "applied",
                            "sent",
                            "2026-07-26T10:00:00Z",
                            "2026-07-26T10:00:00Z",
                        ),
                    )
                    state.conn.commit()
                    state.record_report_attempt(
                        incident_uuid,
                        ["abuse@example.net"],
                        "sent",
                        "batch",
                        test_mode=False,
                        message_id="<same-batch@example.org>",
                        attempted_epoch=now,
                    )
                count, _last, _oldest = state.recipient_report_stats(
                    "abuse@example.net",
                    test_mode=False,
                    since_epoch=now - 60,
                )
                self.assertEqual(1, count)
            finally:
                state.close()


class WordPressInventoryTest(unittest.TestCase):
    def test_inventory_distinguishes_seen_drop_only_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "state.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE batches (
                    batch_uuid TEXT,
                    source_host TEXT,
                    site_id TEXT,
                    imported_at TEXT
                );
                CREATE TABLE events (
                    event_uuid TEXT,
                    source_host TEXT,
                    site_id TEXT,
                    service TEXT,
                    occurred_at TEXT
                );
                INSERT INTO batches VALUES
                    ('b1', 'nidhoggur', 'site-seen',
                     '2026-07-26T10:00:00Z');
                INSERT INTO events VALUES
                    ('e1', 'nidhoggur', 'site-seen', 'wordpress',
                     '2026-07-26T10:00:00Z');
                """
            )
            connection.commit()
            connection.close()
            drop_root = root / "drop"
            (drop_root / "site-drop" / "incoming").mkdir(parents=True)
            rows = inventory(
                database,
                drop_root,
                [
                    ("seen.example", "site-seen"),
                    ("drop.example", "site-drop"),
                    ("missing.example", "site-missing"),
                ],
            )
            self.assertEqual(
                ["seen", "provisioned-no-import", "missing"],
                [row["status"] for row in rows],
            )

    def test_expected_format(self) -> None:
        self.assertEqual(
            [("example.org", "example-org")],
            parse_expected(["example.org=example-org"]),
        )


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0510.py
