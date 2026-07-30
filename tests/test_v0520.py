#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/tests/test_v0520.py
"""Regression coverage for Argent Sentinel 0.5.4.0."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import dashboard  # noqa: E402
import review_processor  # noqa: E402
import review_queue  # noqa: E402


class V0520Test(unittest.TestCase):
    def database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE incidents (
                incident_uuid TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                first_seen_epoch INTEGER NOT NULL,
                last_seen_epoch INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                distinct_accounts INTEGER NOT NULL,
                site_count INTEGER NOT NULL,
                network_cidr TEXT,
                registered_cidr TEXT,
                asn INTEGER,
                asn_holder TEXT,
                network_class TEXT NOT NULL DEFAULT 'unknown',
                decision_status TEXT NOT NULL,
                decision_detail TEXT,
                report_status TEXT NOT NULL,
                report_detail TEXT,
                next_report_after_epoch INTEGER NOT NULL DEFAULT 0,
                report_sent_epoch INTEGER,
                report_recipient TEXT,
                report_message_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE report_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_uuid TEXT NOT NULL,
                attempted_epoch INTEGER NOT NULL,
                attempted_at TEXT NOT NULL,
                recipient TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                test_mode INTEGER NOT NULL DEFAULT 0,
                message_id TEXT
            );
            """
        )
        review_queue.install_review_schema(connection)
        connection.commit()
        return connection

    def insert_incident(
        self,
        connection: sqlite3.Connection,
        *,
        incident_uuid: str,
        report_status: str,
        report_detail: str = "",
        next_report_after_epoch: int = 0,
        updated_at: str = "2026-07-29T19:00:00Z",
    ) -> None:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_uuid, source_ip, rule_id,
                first_seen_epoch, last_seen_epoch,
                first_seen, last_seen, event_count,
                distinct_accounts, site_count,
                network_cidr, registered_cidr, asn, asn_holder,
                network_class, decision_status, decision_detail,
                report_status, report_detail, next_report_after_epoch,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_uuid,
                "203.0.113.17",
                "nginx-hostile-web-probing",
                100,
                100,
                "2026-07-29T18:00:00Z",
                "2026-07-29T18:00:00Z",
                4,
                0,
                1,
                "203.0.113.0/24",
                "203.0.113.0/24",
                64496,
                "Example",
                "hosting",
                "applied",
                "blocked",
                report_status,
                report_detail,
                next_report_after_epoch,
                updated_at,
                updated_at,
            ),
        )

    def test_review_queue_deduplicates_attempts(self) -> None:
        connection = self.database()
        incident = str(uuid.uuid4())
        self.insert_incident(
            connection,
            incident_uuid=incident,
            report_status="failed",
            report_detail="SMTP failure",
        )
        for offset in range(3):
            connection.execute(
                """
                INSERT INTO report_attempts (
                    incident_uuid, attempted_epoch, attempted_at,
                    recipient, status, detail
                ) VALUES (?, ?, ?, ?, 'failed', 'SMTP failure')
                """,
                (
                    incident,
                    100 + offset,
                    f"2026-07-29T18:0{offset}:00Z",
                    "abuse@example.net",
                ),
            )
        connection.commit()
        snapshot = review_queue.build_review_snapshot(
            connection,
            {},
            50,
            now_epoch=10_000,
        )
        self.assertEqual(1, snapshot["open_count"])
        self.assertEqual(1, len(snapshot["items"]))
        self.assertEqual(3, snapshot["items"][0]["attempt_count"])
        self.assertEqual(3, len(snapshot["items"][0]["recent_attempts"]))
        self.assertEqual(
            "delivery-failed",
            snapshot["items"][0]["review_reason"],
        )

    def test_current_single_deferral_is_not_operator_work(self) -> None:
        connection = self.database()
        incident = str(uuid.uuid4())
        self.insert_incident(
            connection,
            incident_uuid=incident,
            report_status="deferred",
            next_report_after_epoch=20_000,
        )
        connection.execute(
            """
            INSERT INTO report_attempts (
                incident_uuid, attempted_epoch, attempted_at,
                status, detail
            ) VALUES (?, 100, '2026-07-29T18:00:00Z',
                      'deferred', 'recipient cooldown')
            """,
            (incident,),
        )
        connection.commit()
        snapshot = review_queue.build_review_snapshot(
            connection,
            {
                "deferred_overdue_minutes": 60,
                "deferred_attempt_threshold": 3,
            },
            50,
            now_epoch=10_000,
        )
        self.assertEqual(0, snapshot["open_count"])

    def test_policy_review_is_visible(self) -> None:
        connection = self.database()
        incident = str(uuid.uuid4())
        self.insert_incident(
            connection,
            incident_uuid=incident,
            report_status="suppressed",
            report_detail=(
                "Persistent WordPress policy reporting disabled pending "
                "production review"
            ),
        )
        connection.commit()
        snapshot = review_queue.build_review_snapshot(
            connection,
            {},
            50,
            now_epoch=10_000,
        )
        self.assertEqual(1, snapshot["open_count"])
        self.assertEqual("policy-review", snapshot["items"][0]["review_reason"])

    def test_retry_action_is_audited_and_idempotent(self) -> None:
        connection = self.database()
        incident = str(uuid.uuid4())
        updated = "2026-07-29T19:00:00Z"
        self.insert_incident(
            connection,
            incident_uuid=incident,
            report_status="failed",
            updated_at=updated,
        )
        connection.commit()
        request = {
            "request_uuid": str(uuid.uuid4()),
            "incident_uuid": incident,
            "action": "retry",
            "operator": "alan",
            "note": "Retry after provider contact review",
            "expected_updated_at": updated,
            "requested_at": "2026-07-29T19:01:00Z",
        }
        result = review_processor.apply_request(connection, request)
        self.assertEqual("applied", result["status"])
        row = connection.execute(
            """
            SELECT report_status, next_report_after_epoch,
                   review_status, review_disposition
            FROM incidents WHERE incident_uuid = ?
            """,
            (incident,),
        ).fetchone()
        self.assertEqual("pending", row["report_status"])
        self.assertEqual(0, row["next_report_after_epoch"])
        self.assertEqual("closed", row["review_status"])
        self.assertEqual("retry-requested", row["review_disposition"])
        duplicate = review_processor.apply_request(connection, request)
        self.assertEqual("duplicate", duplicate["status"])
        count = connection.execute(
            "SELECT COUNT(*) FROM review_actions"
        ).fetchone()[0]
        self.assertEqual(1, count)

    def test_closed_review_reopens_after_a_new_failed_attempt(self) -> None:
        connection = self.database()
        incident = str(uuid.uuid4())
        updated = "2026-07-29T19:00:00Z"
        self.insert_incident(
            connection,
            incident_uuid=incident,
            report_status="failed",
            updated_at=updated,
        )
        connection.commit()
        request = {
            "request_uuid": str(uuid.uuid4()),
            "incident_uuid": incident,
            "action": "acknowledge",
            "operator": "alan",
            "note": "Reviewed current failure",
            "expected_updated_at": updated,
            "requested_at": "2026-07-29T19:01:00Z",
        }
        review_processor.apply_request(connection, request)
        closed = review_queue.build_review_snapshot(
            connection,
            {},
            50,
            now_epoch=2_000_000_000,
        )
        self.assertEqual(0, closed["open_count"])
        connection.execute(
            """
            INSERT INTO report_attempts (
                incident_uuid, attempted_epoch, attempted_at,
                recipient, status, detail
            ) VALUES (?, ?, ?, ?, 'failed', 'new SMTP failure')
            """,
            (
                incident,
                2_000_000_001,
                "2033-05-18T03:33:21Z",
                "abuse@example.net",
            ),
        )
        connection.commit()
        reopened = review_queue.build_review_snapshot(
            connection,
            {},
            50,
            now_epoch=2_000_000_100,
        )
        self.assertEqual(1, reopened["open_count"])

    def test_basic_auth_username_is_the_operator_identity(self) -> None:
        import base64

        token = base64.b64encode(b"alan:secret").decode("ascii")
        self.assertEqual(
            "alan",
            dashboard.operator_from_headers(
                {
                    "Authorization": f"Basic {token}",
                    "X-Argent-Sentinel-Operator": "spoofed",
                }
            ),
        )

    def test_dashboard_renders_local_time_and_review_actions(self) -> None:
        value = dashboard.when("2026-07-29T19:05:00Z")
        self.assertIn('<time datetime="2026-07-29T19:05:00Z"', value)
        self.assertIn("UTC: 2026-07-29T19:05:00Z", value)
        incident = str(uuid.uuid4())
        rendered = dashboard.render_reviews(
            {
                "reviews": {
                    "open_count": 1,
                    "items": [
                        {
                            "incident_uuid": incident,
                            "source_ip": "203.0.113.17",
                            "rule_id": "nginx-hostile-web-probing",
                            "review_reason": "delivery-failed",
                            "report_status": "failed",
                            "attempt_count": 3,
                            "first_seen": "2026-07-29T18:00:00Z",
                            "last_seen": "2026-07-29T19:00:00Z",
                            "updated_at": "2026-07-29T19:00:00Z",
                        }
                    ],
                    "recent_actions": [],
                }
            },
            {"review_note_max_chars": 2000},
        )
        self.assertIn("Open review items", rendered)
        self.assertIn("Retry next batch", rendered)
        self.assertIn("Permanent no contact", rendered)
        self.assertIn("Suppress report", rendered)

    def test_release_and_packaging_markers(self) -> None:
        self.assertEqual(
            "0.5.4.0",
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        )
        collector = (ROOT / "src/collector.py").read_text(encoding="utf-8")
        self.assertIn("SCHEMA_VERSION = 9", collector)
        self.assertIn('"reason": "lock-busy"', collector)
        builder = (ROOT / "packaging/build_debs.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('upstream != "0.5.4.0"', builder)
        self.assertIn('"review_queue.py"', builder)
        self.assertIn('"review_processor.py"', builder)
        self.assertIn(
            '"argent-sentinel-review-processor.path"',
            builder,
        )
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("__pycache__/", ignore)
        self.assertIn("dist/deb/", ignore)


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0520.py
