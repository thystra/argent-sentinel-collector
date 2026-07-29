#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/tests/test_v0511.py
"""Regression coverage for Argent Sentinel 0.5.2.1."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import dashboard  # noqa: E402
import report_batcher  # noqa: E402
import reporting_view  # noqa: E402


class V0511Test(unittest.TestCase):
    def test_broad_registered_ipv4_is_bounded_to_24(self) -> None:
        result = reporting_view.bounded_report_networks(
            "38.133.142.106",
            "38.0.0.0/8",
            "38.133.142.0/24",
            {
                "minimum_ipv4_prefix_length": 24,
                "minimum_ipv6_prefix_length": 48,
            },
        )
        self.assertEqual("38.133.142.0/24", result["batch_cidr"])
        self.assertEqual("38.0.0.0/8", result["registered_cidr"])
        self.assertTrue(result["broad_registered_allocation"])
        self.assertEqual(
            "bounded-registered",
            result["grouping_basis"],
        )

    def test_broad_registered_ipv6_is_bounded_to_48(self) -> None:
        result = reporting_view.bounded_report_networks(
            "2a03:2880:f812:39::1",
            "2a03:2880::/32",
            None,
            {
                "minimum_ipv4_prefix_length": 24,
                "minimum_ipv6_prefix_length": 48,
            },
        )
        self.assertEqual("2a03:2880:f812::/48", result["batch_cidr"])
        self.assertEqual("2a03:2880::/32", result["registered_cidr"])
        self.assertTrue(result["broad_registered_allocation"])
        self.assertEqual(
            "bounded-registered",
            result["grouping_basis"],
        )

    def test_specific_registered_allocation_is_preserved(self) -> None:
        result = reporting_view.bounded_report_networks(
            "203.0.113.17",
            "203.0.113.0/24",
            "203.0.113.0/24",
            {
                "minimum_ipv4_prefix_length": 24,
                "minimum_ipv6_prefix_length": 48,
            },
        )
        self.assertEqual("203.0.113.0/24", result["batch_cidr"])
        self.assertFalse(result["broad_registered_allocation"])
        self.assertEqual("registered", result["grouping_basis"])

    def test_report_batch_group_key_uses_batch_cidr(self) -> None:
        candidates = [
            {
                "batch_cidr": "38.133.142.0/24",
                "registered_cidr": "38.0.0.0/8",
                "family": "web",
                "recipients": ("abuse@example.net",),
            },
            {
                "batch_cidr": "38.133.142.0/24",
                "registered_cidr": "38.0.0.0/8",
                "family": "web",
                "recipients": ("abuse@example.net",),
            },
        ]
        grouped = report_batcher.group_candidates(candidates)
        self.assertEqual(1, len(grouped))
        key = next(iter(grouped))
        self.assertEqual("38.133.142.0/24", key[0])
        self.assertEqual(2, len(grouped[key]))

    def test_next_run_is_hour_five(self) -> None:
        value = dt.datetime(
            2026,
            7,
            29,
            17,
            12,
            tzinfo=dt.timezone.utc,
        )
        self.assertEqual(
            "2026-07-29T18:05:00Z",
            reporting_view.next_hourly_run(value),
        )

    def test_reporting_snapshot_contains_operational_views(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE incidents (
                incident_uuid TEXT,
                source_ip TEXT,
                rule_id TEXT,
                first_seen TEXT,
                last_seen TEXT,
                last_seen_epoch INTEGER,
                created_at TEXT,
                event_count INTEGER,
                registered_cidr TEXT,
                network_cidr TEXT,
                report_recipient TEXT,
                report_status TEXT,
                report_detail TEXT,
                next_report_after_epoch INTEGER,
                asn INTEGER,
                asn_holder TEXT
            );
            CREATE TABLE report_attempts (
                attempt_id INTEGER PRIMARY KEY,
                incident_uuid TEXT,
                attempted_at TEXT,
                attempted_epoch INTEGER,
                recipient TEXT,
                status TEXT,
                detail TEXT,
                test_mode INTEGER,
                message_id TEXT
            );
            """
        )
        now_epoch = 1785348000
        connection.execute(
            """INSERT INTO incidents VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "incident-1",
                "38.133.142.106",
                "nginx-hostile-web-probing",
                "2026-07-29T16:45:45Z",
                "2026-07-29T16:45:45Z",
                now_epoch - 600,
                "2026-07-29T16:45:45Z",
                4,
                "38.0.0.0/8",
                "38.133.142.0/24",
                "abuse@cogentco.com",
                "pending",
                None,
                0,
                174,
                "Cogent",
            ),
        )
        connection.execute(
            """INSERT INTO incidents VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "incident-meta",
                "57.141.18.10",
                "nginx-hostile-web-probing",
                "2026-07-29T16:50:00Z",
                "2026-07-29T16:50:00Z",
                now_epoch - 500,
                "2026-07-29T16:50:00Z",
                10,
                "57.141.18.0/24",
                "57.141.18.0/24",
                "",
                "suppressed",
                "ban-only reporting policy matched AS32934; "
                "local IP enforcement remains active; "
                "provider email suppressed",
                0,
                32934,
                "Meta",
            ),
        )
        connection.execute(
            """INSERT INTO report_attempts VALUES
               (1, ?, ?, ?, ?, ?, ?, 0, ?)""",
            (
                "incident-old",
                "2026-07-29T17:05:07Z",
                now_epoch - 300,
                "abuse@cogentco.com",
                "sent",
                "Hourly CIDR batch sent",
                "<message@example>",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "generated_at": "2026-07-29T17:05:07Z",
                        "next_scheduled_at": "2026-07-29T18:05:00Z",
                        "status": "ok",
                        "groups": 1,
                        "messages_sent": 1,
                        "messages_failed": 0,
                        "preparation": {
                            "eligible": 1,
                            "suppressed": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            snapshot = reporting_view.build_reporting_snapshot(
                connection,
                {
                    "abuse_reporting": {
                        "enabled": True,
                        "test_mode": False,
                        "report_not_before_utc": "2026-07-29T16:27:25Z",
                    },
                    "report_batching": {
                        "enabled": True,
                        "grace_minutes": 5,
                        "max_candidate_incidents": 1000,
                        "grouping": {
                            "minimum_ipv4_prefix_length": 24,
                            "minimum_ipv6_prefix_length": 48,
                        },
                        "ban_only": {},
                    },
                },
                state,
                50,
                now_epoch=now_epoch,
            )
        self.assertEqual("production", snapshot["mode"])
        self.assertEqual(1, len(snapshot["queued_groups"]))
        self.assertEqual(
            "38.133.142.0/24",
            snapshot["queued_groups"][0]["batch_cidr"],
        )
        self.assertTrue(
            snapshot["queued_groups"][0][
                "broad_registered_allocation"
            ]
        )
        self.assertEqual(1, len(snapshot["recent_messages"]))
        self.assertEqual(1, len(snapshot["ban_only_suppressions"]))
        rendered = dashboard.render_reports(
            {
                "reporting": snapshot,
                "report_attempts": [],
            }
        )
        self.assertIn("Queued hourly groups", rendered)
        self.assertIn("Ban-only suppressions", rendered)
        self.assertIn("Recent outbound messages", rendered)

    def test_release_versions_and_packaging(self) -> None:
        expected = "0.5.2.1"
        self.assertEqual(
            expected,
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        )
        for relative in (
            "src/collector.py",
            "src/agent.py",
            "src/server_api.py",
            "src/dashboard.py",
            "src/dashboard_snapshot.py",
        ):
            self.assertIn(
                f'APP_VERSION = "{expected}"',
                (ROOT / relative).read_text(encoding="utf-8"),
                relative,
            )
        builder = (ROOT / "packaging/build_debs.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('upstream != "0.5.2.1"', builder)
        self.assertIn('"reporting_view.py"', builder)
        self.assertIn('"test_v0511.py"', builder)


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0511.py
