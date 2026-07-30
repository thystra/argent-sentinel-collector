#!/usr/bin/env python3
# Source: tests/test_v0530.py
"""Regression coverage for Argent Sentinel 0.5.3.1."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402
import dashboard  # noqa: E402
import review_processor  # noqa: E402
import review_queue  # noqa: E402


class Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class V0530Test(unittest.TestCase):
    def test_release_and_schema_markers(self) -> None:
        self.assertEqual("0.5.3.1", (ROOT / "VERSION").read_text().strip())
        self.assertEqual("0.5.3.1", collector.APP_VERSION)
        self.assertEqual(8, collector.SCHEMA_VERSION)
        self.assertEqual(8, review_queue.SCHEMA_VERSION)
        self.assertEqual("0.5.3.1", review_processor.APP_VERSION)
        self.assertEqual("0.5.3.1", dashboard.APP_VERSION)
        build_script = (ROOT / "packaging/build_debs.py").read_text(encoding="utf-8")
        self.assertIn('"test_v0530.py"', build_script)

    def test_most_specific_bounded_proposal(self) -> None:
        rows = [
            {
                "incident_uuid": str(uuid.uuid4()),
                "source_ip": address,
                "event_count": 2,
                "first_seen": "2026-07-29T10:00:00Z",
                "last_seen": "2026-07-29T11:00:00Z",
                "last_seen_epoch": 200,
            }
            for address in ("198.51.100.17", "198.51.100.18", "198.51.100.19")
        ]
        proposal = collector.network_block_proposal(
            "198.51.0.0/16",
            rows,
            collector.DEFAULTS["policy"],
        )
        self.assertEqual("198.51.100.16/30", proposal["proposal_cidr"])
        self.assertEqual(3, proposal["proposal_hostile_ips"])
        self.assertEqual(3, proposal["proposal_incident_count"])
        self.assertEqual(6, proposal["proposal_event_count"])
        self.assertEqual(75.0, proposal["proposal_coverage_percent"])
        self.assertIn("bounded-/24", proposal["proposal_basis"])

    def test_strongest_bounded_scope_wins(self) -> None:
        rows = []
        for address in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            rows.append({
                "incident_uuid": str(uuid.uuid4()),
                "source_ip": address,
                "event_count": 1,
                "first_seen": "2026-07-28T10:00:00Z",
                "last_seen": "2026-07-29T10:00:00Z",
                "last_seen_epoch": 300,
            })
        for address in ("198.51.101.1", "198.51.101.2"):
            rows.append({
                "incident_uuid": str(uuid.uuid4()),
                "source_ip": address,
                "event_count": 100,
                "first_seen": "2026-07-29T10:00:00Z",
                "last_seen": "2026-07-29T11:00:00Z",
                "last_seen_epoch": 400,
            })
        proposal = collector.network_block_proposal(
            "198.51.0.0/16",
            rows,
            collector.DEFAULTS["policy"],
        )
        self.assertTrue(str(proposal["proposal_cidr"]).startswith("198.51.100."))
        self.assertEqual(3, proposal["proposal_hostile_ips"])

    def test_schema_v8_creates_network_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = collector.StateDB(Path(directory) / "state.sqlite3")
            try:
                version = state.conn.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
                self.assertEqual("8", version)
                columns = {
                    row[1]
                    for row in state.conn.execute("PRAGMA table_info(network_cases)")
                }
                self.assertIn("proposal_cidr", columns)
                self.assertIn("proposal_revision", columns)
                self.assertIn("review_status", columns)
                self.assertIn("decision_cidr", columns)
                table = state.conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name='network_review_actions'"
                ).fetchone()
                self.assertIsNotNone(table)
            finally:
                state.close()

    def test_network_actions_are_status_scoped(self) -> None:
        self.assertEqual(
            ["network-observe", "network-reject", "network-note"],
            review_queue.network_available_actions({
                "status": "review",
                "review_status": "open",
                "proposal_cidr": "198.51.100.0/24",
                "proposal_hostile_ips": 3,
                "proposal_active_days": 1,
            }),
        )
        actions = review_queue.network_available_actions({
            "status": "escalation-review",
            "review_status": "open",
            "proposal_cidr": "198.51.100.0/24",
            "proposal_hostile_ips": 3,
            "proposal_active_days": 1,
        })
        self.assertIn("network-block-180", actions)
        self.assertIn("network-block-365", actions)
        self.assertEqual(
            ["network-remove-block", "network-note"],
            review_queue.network_available_actions({
                "status": "blocked",
                "review_status": "closed",
                "proposal_cidr": "198.51.100.0/24",
                "proposal_hostile_ips": 3,
                "proposal_active_days": 1,
            }),
        )
        self.assertNotIn(
            "network-block-180",
            review_queue.network_available_actions({
                "status": "escalation-review",
                "review_status": "open",
                "proposal_cidr": "198.51.100.1/32",
                "proposal_hostile_ips": 1,
                "proposal_active_days": 1,
            }),
        )

    def network_database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE network_cases (
                network_cidr TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                hostile_ips INTEGER NOT NULL DEFAULT 0,
                incident_count INTEGER NOT NULL DEFAULT 0,
                event_count INTEGER NOT NULL DEFAULT 0,
                active_days INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                operator_note TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE incidents (
                incident_uuid TEXT PRIMARY KEY,
                review_status TEXT NOT NULL DEFAULT 'open'
            )
            """
        )
        review_queue.install_review_schema(connection)
        connection.execute(
            """
            INSERT INTO network_cases (
                network_cidr, status, hostile_ips, incident_count,
                event_count, active_days, first_seen, last_seen,
                updated_at, proposal_cidr, proposal_revision,
                proposal_hostile_ips, proposal_incident_count,
                proposal_event_count, proposal_active_days,
                proposal_coverage_percent, proposal_basis,
                review_status
            ) VALUES (
                '198.51.0.0/16', 'escalation-review', 6, 6,
                20, 3, '2026-07-27T00:00:00Z', '2026-07-29T00:00:00Z',
                '2026-07-29T20:00:00Z', '198.51.100.16/30', 'revision-1',
                3, 3, 10, 2, 75.0, 'strongest-bounded-/24', 'open'
            )
            """
        )
        connection.commit()
        self.addCleanup(connection.close)
        return connection

    def policy_config(self, directory: str, *, trusted: list[str] | None = None) -> dict[str, object]:
        collector_config = Path(directory) / "collector.json"
        collector_config.write_text(
            json.dumps({
                "trusted_cidrs": trusted or ["127.0.0.0/8", "::1/128"],
                "policy": {
                    "reason_prefix": "argent-sentinel",
                    "network_long_block_days": 180,
                    "network_severe_block_days": 365,
                    "network_block_min_ipv4_prefix_length": 24,
                    "network_block_min_ipv6_prefix_length": 48,
                },
                "crowdsec": {
                    "enabled": True,
                    "cscli_path": "/usr/bin/cscli",
                    "command_timeout_seconds": 20,
                },
            }) + "\n",
            encoding="utf-8",
        )
        return {**review_processor.DEFAULTS, "collector_config": str(collector_config)}

    def test_crowdsec_json_matches_only_the_exact_range(self) -> None:
        wrapped = {
            "decisions": [
                {"scope": "Range", "value": "198.51.100.16/30"},
                {"scope": "Ip", "value": "198.51.100.17"},
            ]
        }
        self.assertTrue(
            review_processor.crowdsec_range_exists(
                wrapped,
                "198.51.100.16/30",
            )
        )
        self.assertFalse(
            review_processor.crowdsec_range_exists(
                wrapped,
                "198.51.100.20/30",
            )
        )
        self.assertFalse(
            review_processor.crowdsec_range_exists(
                {"meta": {"count": 1}},
                "198.51.100.16/30",
            )
        )

    def test_block_action_is_audited_and_closes_on_success(self) -> None:
        connection = self.network_database()
        with tempfile.TemporaryDirectory() as directory:
            config = self.policy_config(directory)
            calls: list[list[str]] = []

            def fake_run(command: list[str], **_: object) -> Completed:
                calls.append(command)
                if "list" in command:
                    return Completed(stdout="[]")
                return Completed(stdout='level=info msg="Decision successfully added"')

            with mock.patch.object(review_processor.subprocess, "run", side_effect=fake_run):
                result = review_processor.apply_request(
                    connection,
                    {
                        "request_uuid": str(uuid.uuid4()),
                        "target_type": "network",
                        "network_cidr": "198.51.0.0/16",
                        "proposal_cidr": "198.51.100.16/30",
                        "proposal_revision": "revision-1",
                        "action": "network-block-180",
                        "operator": "alan",
                        "note": "Repeated hostile addresses across multiple days",
                        "expected_updated_at": "2026-07-29T20:00:00Z",
                        "requested_at": "2026-07-29T20:01:00Z",
                    },
                    config,
                    now=dt.datetime(2026, 7, 29, 20, 2, tzinfo=dt.timezone.utc),
                )
            self.assertEqual("applied", result["decision_status"])
            row = connection.execute(
                "SELECT status, review_status, decision_cidr, "
                "decision_duration_days FROM network_cases"
            ).fetchone()
            self.assertEqual("blocked", row["status"])
            self.assertEqual("closed", row["review_status"])
            self.assertEqual("198.51.100.16/30", row["decision_cidr"])
            self.assertEqual(180, row["decision_duration_days"])
            audit = connection.execute(
                "SELECT action, operator, decision_status, disposition "
                "FROM network_review_actions"
            ).fetchone()
            self.assertEqual("network-block-180", audit["action"])
            self.assertEqual("alan", audit["operator"])
            self.assertEqual("applied", audit["decision_status"])
            self.assertEqual("cidr-block-180d", audit["disposition"])
            self.assertIn("--range", calls[1])
            self.assertNotIn("--bypass-allowlist", calls[1])

    def test_failed_block_stays_open_and_is_audited(self) -> None:
        connection = self.network_database()
        with tempfile.TemporaryDirectory() as directory:
            config = self.policy_config(directory)
            with mock.patch.object(
                review_processor.subprocess,
                "run",
                side_effect=[
                    Completed(stdout="[]"),
                    Completed(returncode=1, stderr="LAPI unavailable"),
                ],
            ):
                result = review_processor.apply_request(
                    connection,
                    {
                        "request_uuid": str(uuid.uuid4()),
                        "target_type": "network",
                        "network_cidr": "198.51.0.0/16",
                        "proposal_cidr": "198.51.100.16/30",
                        "proposal_revision": "revision-1",
                        "action": "network-block-365",
                        "operator": "alan",
                        "note": "Escalated distributed activity",
                        "expected_updated_at": "2026-07-29T20:00:00Z",
                        "requested_at": "2026-07-29T20:01:00Z",
                    },
                    config,
                )
            self.assertEqual("failed", result["decision_status"])
            row = connection.execute(
                "SELECT status, review_status, review_disposition FROM network_cases"
            ).fetchone()
            self.assertEqual("escalation-review", row["status"])
            self.assertEqual("open", row["review_status"])
            self.assertEqual("cidr-block-failed", row["review_disposition"])

    def test_safety_refuses_broad_or_trusted_proposal(self) -> None:
        policy = {
            "minimum_ipv4_prefix_length": 24,
            "minimum_ipv6_prefix_length": 48,
            "trusted_cidrs": ["192.168.0.0/16"],
        }
        with self.assertRaises(review_processor.ReviewError):
            review_processor.validate_network_target(
                "198.51.0.0/16", "198.51.100.0/23", policy
            )
        with self.assertRaises(review_processor.ReviewError):
            review_processor.validate_network_target(
                "192.168.0.0/16", "192.168.1.0/24", policy
            )

    def test_stale_proposal_is_rejected_before_crowdsec(self) -> None:
        connection = self.network_database()
        with tempfile.TemporaryDirectory() as directory:
            config = self.policy_config(directory)
            with mock.patch.object(review_processor.subprocess, "run") as runner:
                with self.assertRaises(review_processor.ReviewError):
                    review_processor.apply_request(
                        connection,
                        {
                            "request_uuid": str(uuid.uuid4()),
                            "target_type": "network",
                            "network_cidr": "198.51.0.0/16",
                            "proposal_cidr": "198.51.100.16/30",
                            "proposal_revision": "stale-revision",
                            "action": "network-block-180",
                            "operator": "alan",
                            "note": "reviewed",
                            "expected_updated_at": "2026-07-29T20:00:00Z",
                            "requested_at": "2026-07-29T20:01:00Z",
                        },
                        config,
                    )
            runner.assert_not_called()

    def test_closed_revision_stays_closed_and_new_evidence_reopens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = collector.StateDB(Path(directory) / "state.sqlite3")
            try:
                now = int(dt.datetime.now(dt.timezone.utc).timestamp())
                policy = dict(collector.DEFAULTS["policy"])
                policy["network_review_distinct_ips"] = 2
                policy["network_escalation_distinct_ips"] = 3

                def add_incident(address: str, offset: int) -> None:
                    moment = collector.epoch_text(now - offset)
                    state.conn.execute(
                        """
                        INSERT INTO incidents (
                            incident_uuid, source_ip, rule_id,
                            first_seen_epoch, last_seen_epoch,
                            first_seen, last_seen, event_count,
                            distinct_accounts, site_count, network_cidr,
                            registered_cidr, decision_status, report_status,
                            created_at, updated_at
                        ) VALUES (?, ?, 'test-network-review', ?, ?, ?, ?, 1,
                                  0, 1, '198.51.100.0/24', '198.51.0.0/16',
                                  'applied', 'suppressed', ?, ?)
                        """,
                        (
                            str(uuid.uuid4()),
                            address,
                            now - offset,
                            now - offset,
                            moment,
                            moment,
                            moment,
                            moment,
                        ),
                    )

                for offset, address in enumerate(
                    ("198.51.100.17", "198.51.100.18", "198.51.100.19"),
                    1,
                ):
                    add_incident(address, offset)
                state.conn.commit()
                state.sync_network_cases(policy)
                first = state.conn.execute(
                    "SELECT proposal_revision FROM network_cases "
                    "WHERE network_cidr='198.51.0.0/16'"
                ).fetchone()
                first_revision = str(first["proposal_revision"])
                state.conn.execute(
                    """
                    UPDATE network_cases
                    SET status='closed', review_status='closed',
                        review_disposition='recommendation-rejected'
                    WHERE network_cidr='198.51.0.0/16'
                    """
                )
                state.conn.commit()

                unchanged = state.network_context("198.51.0.0/16", policy)
                self.assertEqual(first_revision, unchanged["proposal_revision"])
                self.assertEqual("closed", unchanged["status"])
                self.assertEqual("closed", unchanged["review_status"])

                add_incident("198.51.100.20", 0)
                state.conn.commit()
                changed = state.network_context("198.51.0.0/16", policy)
                self.assertNotEqual(first_revision, changed["proposal_revision"])
                self.assertEqual("escalation-review", changed["status"])
                self.assertEqual("open", changed["review_status"])
                self.assertEqual("proposal-updated", changed["review_disposition"])
            finally:
                state.close()

    def test_dashboard_renders_network_controls(self) -> None:
        body = dashboard.render_networks(
            {
                "network_cases": [
                    {
                        "network_cidr": "198.51.0.0/16",
                        "status": "escalation-review",
                        "review_status": "open",
                        "proposal_cidr": "198.51.100.16/30",
                        "proposal_revision": "revision-1",
                        "proposal_hostile_ips": 3,
                        "proposal_coverage_percent": 75.0,
                        "available_actions": [
                            "network-block-180",
                            "network-block-365",
                            "network-note",
                        ],
                        "updated_at": "2026-07-29T20:00:00Z",
                    }
                ],
                "network_review_actions": [],
            },
            {},
        )
        self.assertIn("Block proposed CIDR for 180 days", body)
        self.assertIn("/networks/action", body)
        self.assertIn("198.51.100.16/30", body)
        self.assertIn("never bypass allowlists", body)


if __name__ == "__main__":
    unittest.main()

# EOF: tests/test_v0530.py
