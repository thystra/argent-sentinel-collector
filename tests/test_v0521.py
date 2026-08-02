#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/tests/test_v0521.py
"""Regression coverage for Argent Sentinel 0.5.5.1."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import dashboard  # noqa: E402
import report_batcher  # noqa: E402
import review_processor  # noqa: E402
import review_queue  # noqa: E402


class DatabaseFixture:
    @staticmethod
    def database() -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
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
            CREATE TABLE enrichment_cache (
                source_ip TEXT PRIMARY KEY,
                fetched_epoch INTEGER NOT NULL,
                expires_epoch INTEGER NOT NULL,
                network_cidr TEXT,
                network_name TEXT,
                asn INTEGER,
                asn_holder TEXT,
                abuse_emails_json TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            """
        )
        review_queue.install_review_schema(connection)
        return connection

    @staticmethod
    def insert_incident(
        connection: sqlite3.Connection,
        *,
        incident_uuid: str,
        rule_id: str = "wordpress-persistent-credential-spray",
        report_status: str = "suppressed",
        report_detail: str = (
            "Persistent WordPress policy reporting disabled pending "
            "production review"
        ),
        decision_status: str = "applied",
        updated_at: str = "2026-07-29T20:30:00Z",
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
            ) VALUES (?, '198.51.100.77', ?, 100, 200,
                      '2026-07-29T20:00:00Z', '2026-07-29T20:30:00Z',
                      12, 3, 2, '198.51.100.0/24', '198.51.100.0/24',
                      64496, 'Example', 'hosting', ?, 'decision active',
                      ?, ?, 0, ?, ?)
            """,
            (
                incident_uuid,
                rule_id,
                decision_status,
                report_status,
                report_detail,
                updated_at,
                updated_at,
            ),
        )
        connection.commit()


class V0521Test(unittest.TestCase):
    def test_credential_spray_has_explicit_review_actions(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        DatabaseFixture.insert_incident(connection, incident_uuid=incident)
        snapshot = review_queue.build_review_snapshot(
            connection,
            {},
            50,
            now_epoch=1_000,
        )
        self.assertEqual(1, snapshot["open_count"])
        self.assertEqual(1, snapshot["category_counts"]["credential_spray"])
        item = snapshot["items"][0]
        self.assertEqual("credential-spray-review", item["review_reason"])
        self.assertIn("approve-report", item["available_actions"])
        self.assertIn("refresh-contact", item["available_actions"])

    def test_approve_report_sets_one_time_operator_disposition(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        updated = "2026-07-29T20:30:00Z"
        DatabaseFixture.insert_incident(
            connection,
            incident_uuid=incident,
            updated_at=updated,
        )
        result = review_processor.apply_request(
            connection,
            {
                "request_uuid": str(uuid.uuid4()),
                "incident_uuid": incident,
                "action": "approve-report",
                "operator": "alan",
                "note": "Approved after evidence review",
                "expected_updated_at": updated,
                "requested_at": "2026-07-29T20:31:00Z",
            },
        )
        self.assertEqual("credential-spray-approved", result["disposition"])
        row = connection.execute(
            """
            SELECT report_status, review_status, review_disposition
            FROM incidents WHERE incident_uuid = ?
            """,
            (incident,),
        ).fetchone()
        self.assertEqual("pending", row["report_status"])
        self.assertEqual("closed", row["review_status"])
        self.assertEqual("credential-spray-approved", row["review_disposition"])

    def test_refresh_contact_clears_cache_and_queues_lookup(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        updated = "2026-07-29T20:30:00Z"
        DatabaseFixture.insert_incident(
            connection,
            incident_uuid=incident,
            updated_at=updated,
        )
        connection.execute(
            """
            INSERT INTO enrichment_cache (
                source_ip, fetched_epoch, expires_epoch,
                abuse_emails_json, raw_json
            ) VALUES ('198.51.100.77', 1, 2, '[]', '{}')
            """
        )
        connection.commit()
        review_processor.apply_request(
            connection,
            {
                "request_uuid": str(uuid.uuid4()),
                "incident_uuid": incident,
                "action": "refresh-contact",
                "operator": "alan",
                "note": "Refresh provider ownership",
                "expected_updated_at": updated,
                "requested_at": "2026-07-29T20:31:00Z",
            },
        )
        count = connection.execute(
            "SELECT COUNT(*) FROM enrichment_cache"
        ).fetchone()[0]
        self.assertEqual(0, count)
        row = connection.execute(
            """
            SELECT report_status, review_disposition
            FROM incidents WHERE incident_uuid = ?
            """,
            (incident,),
        ).fetchone()
        self.assertEqual("no-contact", row["report_status"])
        self.assertEqual("contact-refresh-requested", row["review_disposition"])

    def test_verified_no_contact_ban_closes_and_audits(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        DatabaseFixture.insert_incident(
            connection,
            incident_uuid=incident,
            rule_id="nginx-hostile-web-probing",
            report_status="no-contact",
            report_detail="No RDAP abuse email was found",
        )
        result = review_queue.close_no_contact_review(
            connection,
            incident,
            decision_status="existing",
            decision_detail="decision already exists",
            report_detail="No RDAP abuse email was found",
            now_epoch=500,
        )
        self.assertEqual("closed", result["status"])
        row = connection.execute(
            """
            SELECT report_status, review_status, review_disposition
            FROM incidents WHERE incident_uuid = ?
            """,
            (incident,),
        ).fetchone()
        self.assertEqual("no-contact", row["report_status"])
        self.assertEqual("closed", row["review_status"])
        self.assertEqual("auto-no-contact-ban", row["review_disposition"])
        action = connection.execute(
            "SELECT action, operator FROM review_actions"
        ).fetchone()
        self.assertEqual("automatic-close", action["action"])
        self.assertEqual("system:no-contact", action["operator"])

    def test_failed_no_contact_enforcement_stays_open(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        DatabaseFixture.insert_incident(
            connection,
            incident_uuid=incident,
            rule_id="nginx-hostile-web-probing",
            report_status="no-contact",
            report_detail="No RDAP abuse email was found",
            decision_status="failed",
        )
        review_queue.open_no_contact_review(
            connection,
            incident,
            decision_status="failed",
            decision_detail="cscli timed out",
            report_detail="No RDAP abuse email was found",
            retry_epoch=900,
            now_epoch=500,
        )
        snapshot = review_queue.build_review_snapshot(
            connection,
            {},
            50,
            now_epoch=600,
        )
        self.assertEqual(1, snapshot["category_counts"]["no_contact"])
        self.assertEqual(
            "no-contact-enforcement",
            snapshot["items"][0]["review_reason"],
        )
        self.assertEqual(
            ["retry", "note"],
            snapshot["items"][0]["available_actions"],
        )

    class FakeDatabase:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.conn = connection

        def incident(self, incident_uuid: str) -> sqlite3.Row:
            row = self.conn.execute(
                "SELECT * FROM incidents WHERE incident_uuid = ?",
                (incident_uuid,),
            ).fetchone()
            if row is None:
                raise AssertionError(f"Missing incident {incident_uuid}")
            return row

        def update_incident(self, incident_uuid: str, **values: object) -> None:
            if not values:
                return
            columns = ", ".join(f"{key} = ?" for key in values)
            self.conn.execute(
                f"UPDATE incidents SET {columns} WHERE incident_uuid = ?",
                (*values.values(), incident_uuid),
            )
            self.conn.commit()

        def record_report_attempt(
            self,
            incident_uuid: str,
            recipients: object,
            status: str,
            detail: str,
            *,
            test_mode: bool,
            message_id: str | None = None,
            attempted_epoch: int | None = None,
        ) -> None:
            recipient = ", ".join(str(value) for value in recipients)
            epoch = int(attempted_epoch or 0)
            attempted_at = review_queue.utc_text(
                __import__("datetime").datetime.fromtimestamp(
                    epoch,
                    __import__("datetime").timezone.utc,
                )
            )
            self.conn.execute(
                """
                INSERT INTO report_attempts (
                    incident_uuid, attempted_epoch, attempted_at,
                    recipient, status, detail, test_mode, message_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_uuid,
                    epoch,
                    attempted_at,
                    recipient or None,
                    status,
                    detail,
                    int(test_mode),
                    message_id,
                ),
            )
            self.conn.commit()

        def incident_evidence(self, _incident_uuid: str) -> list[object]:
            return []

        def incident_network_evidence(
            self,
            _incident_uuid: str,
            _limit: int,
        ) -> list[object]:
            return []

    class FakeCollector:
        def __init__(
            self,
            connection: sqlite3.Connection,
            *,
            recipients: list[str],
            gate: tuple[str, str] | None = None,
            decision: tuple[str, str] = ("existing", "already active"),
        ) -> None:
            self.db = V0521Test.FakeDatabase(connection)
            self.recipients = recipients
            self.gate = gate
            self.decision = decision
            self.config = {
                "report_batching": {
                    "grace_minutes": 0,
                    "max_candidate_incidents": 50,
                    "ban_only": {},
                    "grouping": {
                        "minimum_ipv4_prefix_length": 24,
                        "minimum_ipv6_prefix_length": 48,
                    },
                },
                "abuse_reporting": {"test_mode": False},
                "network_reporting": {"max_tuple_evidence": 10},
            }

        def report_time_gate(
            self,
            _incident: sqlite3.Row,
        ) -> tuple[str, str] | None:
            return self.gate

        def source_protection_status(self, _source_ip: str) -> tuple[str, str]:
            return "allowed", "public source"

        def enrich(self, _source_ip: str) -> dict[str, object]:
            return {
                "network_cidr": "198.51.100.0/24",
                "asn": 64496,
                "asn_holder": "Example",
                "network_class": "hosting",
                "abuse_emails": list(self.recipients),
            }

        def report_recipients(
            self,
            _enrichment: object,
        ) -> list[str]:
            return list(self.recipients)

        def apply_decision(self, _incident: sqlite3.Row) -> tuple[str, str]:
            return self.decision

        def report_retry_epoch(self, now_epoch: int) -> int:
            return now_epoch + 3600

    def test_contact_refresh_closed_item_is_reprocessed_without_sending(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        updated = "2026-07-29T20:30:00Z"
        DatabaseFixture.insert_incident(
            connection,
            incident_uuid=incident,
            updated_at=updated,
        )
        review_processor.apply_request(
            connection,
            {
                "request_uuid": str(uuid.uuid4()),
                "incident_uuid": incident,
                "action": "refresh-contact",
                "operator": "alan",
                "note": "Refresh provider ownership",
                "expected_updated_at": updated,
                "requested_at": "2026-07-29T20:31:00Z",
            },
        )
        collector = self.FakeCollector(
            connection,
            recipients=["abuse@example.net"],
            gate=(
                "suppressed",
                "Incident is older than max_report_age_hours=168",
            ),
        )
        candidates, stats = report_batcher.prepare_candidates(collector)
        self.assertEqual([], candidates)
        self.assertEqual(1, stats["contact_refreshed"])
        row = connection.execute(
            """
            SELECT report_status, report_recipient,
                   review_status, review_disposition
            FROM incidents WHERE incident_uuid = ?
            """,
            (incident,),
        ).fetchone()
        self.assertEqual("suppressed", row["report_status"])
        self.assertEqual("abuse@example.net", row["report_recipient"])
        self.assertEqual("open", row["review_status"])
        self.assertEqual("contact-refreshed", row["review_disposition"])
        attempt = connection.execute(
            "SELECT status FROM report_attempts ORDER BY attempt_id DESC"
        ).fetchone()
        self.assertEqual("contact-refreshed", attempt["status"])

    def test_no_contact_batch_verifies_ban_and_auto_closes(self) -> None:
        connection = DatabaseFixture.database()
        incident = str(uuid.uuid4())
        DatabaseFixture.insert_incident(
            connection,
            incident_uuid=incident,
            rule_id="nginx-hostile-web-probing",
            report_status="pending",
            report_detail="Ready for provider lookup",
        )
        collector = self.FakeCollector(connection, recipients=[])
        candidates, stats = report_batcher.prepare_candidates(collector)
        self.assertEqual([], candidates)
        self.assertEqual(1, stats["no_contact"])
        self.assertEqual(1, stats["auto_closed_no_contact"])
        row = connection.execute(
            """
            SELECT report_status, review_status, review_disposition,
                   decision_status
            FROM incidents WHERE incident_uuid = ?
            """,
            (incident,),
        ).fetchone()
        self.assertEqual("no-contact", row["report_status"])
        self.assertEqual("closed", row["review_status"])
        self.assertEqual("auto-no-contact-ban", row["review_disposition"])
        self.assertEqual("existing", row["decision_status"])

    def test_dashboard_exposes_credential_actions(self) -> None:
        rendered = dashboard.render_reviews(
            {
                "reviews": {
                    "open_count": 1,
                    "category_counts": {
                        "credential_spray": 1,
                        "no_contact": 0,
                        "delivery_failed": 0,
                    },
                    "items": [
                        {
                            "incident_uuid": str(uuid.uuid4()),
                            "source_ip": "198.51.100.77",
                            "rule_id": "wordpress-persistent-credential-spray",
                            "review_reason": "credential-spray-review",
                            "report_status": "suppressed",
                            "available_actions": [
                                "approve-report",
                                "keep-suppressed",
                                "duplicate-subsumed",
                                "refresh-contact",
                                "note",
                            ],
                            "updated_at": "2026-07-29T20:30:00Z",
                        }
                    ],
                    "recent_actions": [],
                }
            },
            {"review_note_max_chars": 2000},
        )
        self.assertIn("Approve provider report", rendered)
        self.assertIn("Keep suppressed and close", rendered)
        self.assertIn("Close as duplicate/subsumed", rendered)
        self.assertIn("Refresh abuse contact", rendered)

    def test_release_markers(self) -> None:
        self.assertEqual(
            "0.5.5.1",
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        )
        batcher = (ROOT / "src/report_batcher.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("ensure_no_contact_enforcement", batcher)
        self.assertIn("contact-refresh-requested", batcher)
        self.assertIn("auto_closed_no_contact", batcher)
        builder = (ROOT / "packaging/build_debs.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('upstream != "0.5.5.1"', builder)
        self.assertIn('"test_v0521.py"', builder)


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0521.py
