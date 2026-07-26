#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402
import fail2ban_export  # noqa: E402
import review_digest  # noqa: E402


class V049Test(unittest.TestCase):
    def test_release_versions(self) -> None:
        self.assertEqual("0.5.0.3", (ROOT / "VERSION").read_text().strip())
        for module in (collector, fail2ban_export, review_digest):
            self.assertEqual("0.5.0.3", module.APP_VERSION)

    def test_fail2ban_row_parser(self) -> None:
        event = fail2ban_export.parse_ban_row(
            {
                "MESSAGE": "NOTICE [sshd-invaliduser] Ban 203.0.113.44",
                "__CURSOR": "s=test",
                "__REALTIME_TIMESTAMP": "1784950000000000",
            },
            "node-a",
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual("fail2ban_ban", event["event_type"])
        self.assertEqual("203.0.113.44", event["source_ip"])
        self.assertEqual("sshd-invaliduser", event["metadata"]["jail"])

    def test_fail2ban_batch_normalizes(self) -> None:
        event = fail2ban_export.parse_ban_row(
            {
                "MESSAGE": "NOTICE [nginx-sensitive-files] Ban 203.0.113.45",
                "__CURSOR": "s=test-2",
                "__REALTIME_TIMESTAMP": "1784950000000000",
            },
            "node-a",
        )
        assert event is not None
        batch = fail2ban_export.build_batches(
            "node-a",
            "node-a.example",
            [event],
            500,
        )[0]
        normalized, events = collector.normalize_batch(batch)
        self.assertEqual("fail2ban", normalized["source"]["service"])
        self.assertEqual("fail2ban_ban", events[0]["event_type"])

    def test_429_groups_distributed_ipv6_by_48(self) -> None:
        rows = []
        for index in range(10):
            rows.append(
                {
                    "occurred_epoch": 1000 + index,
                    "source_ip": f"2a03:2880:f812:{index:x}::",
                    "host": "photos.example",
                    "request_uri": f"/picture.php?/{index}",
                    "user_agent": "meta-externalagent/1.1",
                }
            )
        groups = review_digest.aggregate_429(rows)
        self.assertEqual(1, len(groups))
        self.assertEqual("2a03:2880:f812::/48", groups[0]["prefix"])
        self.assertEqual(10, groups[0]["distinct_ips"])

    def test_single_444_qualifies_immediately(self) -> None:
        instance = object.__new__(collector.Collector)
        instance.config = {
            "web_policy": {
                "window_seconds": 600,
                "suspicious_threshold": 3,
                "distinct_targets": 1,
                "immediate_statuses": [444],
            }
        }
        rows = [
            {
                "occurred_epoch": 100,
                "request_path": "/blocked",
                "metadata_json": json.dumps(
                    {
                        "probe_category": "nginx-denied-444",
                        "http_status": 444,
                    }
                ),
            }
        ]
        self.assertEqual(rows, instance.qualify_web_probe_segment(rows))

    def test_single_ssh_trigger_retains_complete_segment(self) -> None:
        instance = object.__new__(collector.Collector)
        instance.config = {
            "sshd_policy": {
                "window_seconds": 3600,
                "failure_threshold": 1,
                "distinct_accounts": 1,
                "single_account_threshold": 1,
            }
        }
        rows = [
            {
                "occurred_epoch": 100 + index,
                "account_key": f"sshd-node:account:{index:064x}",
            }
            for index in range(8)
        ]
        rule_id, evidence = instance.qualify_ssh_segment(rows)
        self.assertEqual("sshd-credential-spray", rule_id)
        self.assertEqual(rows, evidence)

    def test_systemd_daily_timer_is_local_0700(self) -> None:
        timer = (
            ROOT
            / "packaging/systemd/argent-sentinel-review-digest.timer"
        ).read_text()
        self.assertIn("OnCalendar=*-*-* 07:00:00", timer)
        self.assertIn("Persistent=true", timer)

    def test_roadmap_contains_wordpress_failure(self) -> None:
        todo = (ROOT / "TODO.md").read_text()
        self.assertIn("'setup' is not a registered subcommand", todo)
        self.assertIn("Future dashboard write and control workflows", todo)
        self.assertIn("Abuse-contact delivery failures", todo)
        self.assertIn("CIDR and network-prefix escalation", todo)
        self.assertIn("dedicated envelope-sender", todo)
        self.assertIn("85.203.47.0/24", todo)


if __name__ == "__main__":
    unittest.main()
