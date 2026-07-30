#!/usr/bin/env python3
# File: /home/alan/src/argent-sentinel-collector/tests/test_v0531.py
"""Regression coverage for Argent Sentinel 0.5.3.1."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402
import dashboard  # noqa: E402
import dashboard_snapshot  # noqa: E402
import review_processor  # noqa: E402
import review_queue  # noqa: E402

UTC = dt.timezone.utc


class V0531Test(unittest.TestCase):
    def test_release_and_schema_markers(self) -> None:
        self.assertEqual("0.5.3.1", (ROOT / "VERSION").read_text().strip())
        self.assertEqual("0.5.3.1", collector.APP_VERSION)
        self.assertEqual("0.5.3.1", dashboard.APP_VERSION)
        self.assertEqual("0.5.3.1", dashboard_snapshot.APP_VERSION)
        self.assertEqual("0.5.3.1", review_processor.APP_VERSION)
        self.assertEqual(8, review_queue.SCHEMA_VERSION)

    def test_collector_accepts_dedicated_protected_cidrs(self) -> None:
        config = collector.deep_merge(
            collector.DEFAULTS,
            {
                "node": {"id": "unit-test", "central_url": ""},
                "enforcement_protection": {
                    "protected_cidrs": ["2600:1702:6530:bdff::/64"],
                },
            },
        )
        collector.validate_config(config)
        config["enforcement_protection"]["protected_cidrs"] = ["not-a-cidr"]
        with self.assertRaises(collector.CollectorError):
            collector.validate_config(config)

    def test_protection_match_distinguishes_sources(self) -> None:
        trusted = review_queue.network_protection_match(
            "192.168.1.0/24",
            {"trusted_cidrs": ["192.168.0.0/16"]},
        )
        self.assertEqual("trusted-cidrs", trusted["protection_source"])
        protected = review_queue.network_protection_match(
            "2600:1702:6530:bdff::/64",
            {
                "enforcement_protection": {
                    "protected_cidrs": ["2600:1702:6530:bdff::/64"],
                }
            },
        )
        self.assertEqual("protected-cidrs", protected["protection_source"])

    def test_protected_case_suppresses_block_actions(self) -> None:
        cases = review_queue.prepare_network_cases(
            [
                {
                    "network_cidr": "2600:1700::/28",
                    "status": "escalation-review",
                    "review_status": "open",
                    "proposal_cidr": "2600:1702:6530:bdff::/64",
                    "proposal_hostile_ips": 6,
                    "proposal_active_days": 5,
                }
            ],
            {
                "enforcement_protection": {
                    "protected_cidrs": ["2600:1702:6530:bdff::/64"],
                }
            },
        )
        case = cases[0]
        self.assertEqual("protected-overlap", case["protection_status"])
        self.assertEqual(
            ["network-ack-protected", "network-note"],
            case["available_actions"],
        )
        self.assertNotIn("network-block-180", case["available_actions"])

    def test_processor_refuses_dedicated_protection(self) -> None:
        policy = {
            "trusted_cidrs": [],
            "protected_cidrs": ["2600:1702:6530:bdff::/64"],
            "minimum_ipv4_prefix_length": 24,
            "minimum_ipv6_prefix_length": 48,
        }
        with self.assertRaisesRegex(
            review_processor.ReviewError,
            "enforcement-protected network",
        ):
            review_processor.validate_network_target(
                "2600:1700::/28",
                "2600:1702:6530:bdff::/64",
                policy,
            )

    def test_acknowledge_protected_is_audited_without_crowdsec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            collector_config = root / "collector.json"
            collector_config.write_text(
                json.dumps(
                    {
                        "policy": {
                            "reason_prefix": "argent-sentinel",
                            "network_long_block_days": 180,
                            "network_severe_block_days": 365,
                            "network_block_min_ipv4_prefix_length": 24,
                            "network_block_min_ipv6_prefix_length": 48,
                        },
                        "trusted_cidrs": [],
                        "enforcement_protection": {
                            "protected_cidrs": [
                                "2600:1702:6530:bdff::/64"
                            ]
                        },
                        "crowdsec": {
                            "enabled": True,
                            "cscli_path": "/definitely/not/called",
                            "command_timeout_seconds": 1,
                        },
                    }
                )
            )
            connection = sqlite3.connect(database)
            connection.row_factory = sqlite3.Row
            connection.execute(
                "CREATE TABLE incidents (incident_uuid TEXT PRIMARY KEY)"
            )
            review_queue.install_review_schema(connection)
            connection.execute(
                """
                INSERT INTO network_cases (
                    network_cidr, status, hostile_ips, incident_count,
                    event_count, active_days, updated_at, proposal_cidr,
                    proposal_revision, proposal_hostile_ips,
                    proposal_active_days, review_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2600:1700::/28", "escalation-review", 6, 11, 794, 5,
                    "2026-07-30T00:31:52Z",
                    "2600:1702:6530:bdff::/64", "revision-one", 6, 5,
                    "open",
                ),
            )
            connection.commit()
            request = {
                "request_uuid": str(uuid.uuid4()),
                "target_type": "network",
                "network_cidr": "2600:1700::/28",
                "proposal_cidr": "2600:1702:6530:bdff::/64",
                "proposal_revision": "revision-one",
                "action": "network-ack-protected",
                "operator": "admin",
                "note": "Owned residential LAN",
                "expected_updated_at": "2026-07-30T00:31:52Z",
                "requested_at": "2026-07-30T00:40:00Z",
            }
            result = review_processor.apply_network_request(
                connection,
                request,
                {
                    "collector_config": str(collector_config),
                },
                now=dt.datetime(2026, 7, 30, 0, 41, tzinfo=UTC),
            )
            self.assertEqual("protected-network-acknowledged", result["disposition"])
            row = connection.execute(
                "SELECT status, review_status, decision_status, decision_detail "
                "FROM network_cases"
            ).fetchone()
            self.assertEqual("protected", row["status"])
            self.assertEqual("closed", row["review_status"])
            self.assertIsNone(row["decision_status"])
            self.assertIsNone(row["decision_detail"])
            audit = connection.execute(
                "SELECT action, disposition, decision_status, decision_detail "
                "FROM network_review_actions"
            ).fetchone()
            self.assertEqual("network-ack-protected", audit["action"])
            self.assertEqual("protected-network-acknowledged", audit["disposition"])
            self.assertEqual("protected", audit["decision_status"])
            self.assertIn(
                "2600:1702:6530:bdff::/64",
                audit["decision_detail"],
            )
            connection.close()

    def test_dashboard_renders_protected_state(self) -> None:
        html = dashboard.render_networks(
            {
                "network_cases": [
                    {
                        "network_cidr": "2600:1700::/28",
                        "status": "escalation-review",
                        "review_status": "open",
                        "proposal_cidr": "2600:1702:6530:bdff::/64",
                        "proposal_revision": "revision-one",
                        "proposal_hostile_ips": 6,
                        "proposal_active_days": 5,
                        "proposal_coverage_percent": 0,
                        "protection_status": "protected-overlap",
                        "protection_source": "protected-cidrs",
                        "protected_by_cidr": "2600:1702:6530:bdff::/64",
                        "available_actions": [
                            "network-ack-protected",
                            "network-note",
                        ],
                        "updated_at": "2026-07-30T00:31:52Z",
                    }
                ],
                "network_review_actions": [],
            },
            {"review_note_max_chars": 2000},
        )
        self.assertIn("Protected overlaps", html)
        self.assertIn("Acknowledge protected network", html)
        self.assertIn("protected-cidrs", html)
        self.assertNotIn("Block proposed CIDR for 180 days", html)


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0531.py
