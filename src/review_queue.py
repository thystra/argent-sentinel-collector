#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/review_queue.py
# Installed: /usr/lib/argent-sentinel/review_queue.py
"""Review-queue schema and sanitized projection helpers."""

from __future__ import annotations

import datetime as dt
import sqlite3
from typing import Any, Mapping

UTC = dt.timezone.utc
SCHEMA_VERSION = 7
OPEN_REPORT_STATES = ("failed", "no-contact")
REVIEW_ACTIONS = (
    "acknowledge",
    "retry",
    "suppress",
    "permanent-no-contact",
    "note",
)


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    current = (value or utc_now()).astimezone(UTC).replace(microsecond=0)
    return current.isoformat().replace("+00:00", "Z")


def table_columns(
    connection: sqlite3.Connection,
    table: str,
) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})")
    }


def ensure_column(
    connection: sqlite3.Connection,
    table: str,
    name: str,
    definition: str,
) -> None:
    if name not in table_columns(connection, table):
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
        )


def install_review_schema(connection: sqlite3.Connection) -> None:
    """Install the schema-v7 review audit without changing old dispositions."""

    ensure_column(
        connection,
        "incidents",
        "review_status",
        "TEXT NOT NULL DEFAULT 'open'",
    )
    ensure_column(connection, "incidents", "review_disposition", "TEXT")
    ensure_column(connection, "incidents", "review_note", "TEXT")
    ensure_column(connection, "incidents", "review_updated_epoch", "INTEGER")
    ensure_column(connection, "incidents", "review_updated_at", "TEXT")

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS review_actions (
            action_id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_uuid TEXT NOT NULL UNIQUE,
            incident_uuid TEXT NOT NULL REFERENCES incidents(incident_uuid),
            action TEXT NOT NULL,
            operator TEXT NOT NULL,
            note TEXT,
            previous_report_status TEXT,
            new_report_status TEXT,
            previous_review_status TEXT,
            new_review_status TEXT,
            disposition TEXT,
            requested_at TEXT NOT NULL,
            applied_epoch INTEGER NOT NULL,
            applied_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS review_actions_incident_time
            ON review_actions(incident_uuid, applied_epoch DESC);
        CREATE INDEX IF NOT EXISTS review_actions_operator_time
            ON review_actions(operator, applied_epoch DESC);
        """
    )


def _review_predicate() -> str:
    return """
        (
            COALESCE(i.review_status, 'open') != 'closed'
            OR (
                i.report_status IN ('failed', 'no-contact', 'deferred')
                AND COALESCE(a.latest_attempt_epoch, 0)
                    > COALESCE(i.review_updated_epoch, 0)
            )
        )
        AND (
            i.report_status IN ('failed', 'no-contact')
            OR (
                i.report_status = 'deferred'
                AND (
                    COALESCE(i.next_report_after_epoch, 0) <= ?
                    OR COALESCE(a.deferred_count, 0) >= ?
                )
            )
            OR (
                i.report_status = 'suppressed'
                AND lower(COALESCE(i.report_detail, ''))
                    LIKE '%pending production review%'
            )
        )
    """


def review_reason(row: Mapping[str, Any], now_epoch: int) -> str:
    report_status = str(row.get("report_status") or "")
    detail = str(row.get("report_detail") or "")
    deferred_count = int(row.get("deferred_count") or 0)
    next_epoch = int(row.get("next_report_after_epoch") or 0)
    if report_status == "failed":
        return "delivery-failed"
    if report_status == "no-contact":
        return "no-usable-contact"
    if report_status == "deferred":
        if deferred_count >= int(row.get("deferred_review_threshold") or 3):
            return "repeatedly-deferred"
        if next_epoch <= now_epoch:
            return "overdue-deferred"
        return "deferred"
    if "pending production review" in detail.lower():
        return "policy-review"
    return "operator-review"


def _review_rows(
    connection: sqlite3.Connection,
    *,
    now_epoch: int,
    overdue_seconds: int,
    deferred_review_threshold: int,
    limit: int | None,
) -> list[dict[str, Any]]:
    overdue_epoch = now_epoch - max(0, int(overdue_seconds))
    limit_sql = "" if limit is None else " LIMIT ?"
    parameters: list[Any] = [
        overdue_epoch,
        max(1, int(deferred_review_threshold)),
    ]
    if limit is not None:
        parameters.append(max(1, int(limit)))
    query = f"""
        WITH attempts AS (
            SELECT incident_uuid,
                   COUNT(*) AS attempt_count,
                   SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
                       AS failed_count,
                   SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END)
                       AS deferred_count,
                   MAX(attempted_at) AS latest_attempt_at,
                   MAX(attempted_epoch) AS latest_attempt_epoch,
                   MAX(recipient) AS latest_recipient,
                   MAX(detail) AS latest_attempt_detail
            FROM report_attempts
            GROUP BY incident_uuid
        )
        SELECT i.incident_uuid, i.source_ip, i.rule_id,
               i.first_seen, i.last_seen, i.last_seen_epoch,
               i.event_count, i.distinct_accounts, i.site_count,
               i.registered_cidr, i.network_cidr, i.asn, i.asn_holder,
               i.network_class, i.decision_status, i.decision_detail,
               i.report_status, i.report_detail,
               i.next_report_after_epoch, i.report_recipient,
               i.report_message_id, i.updated_at,
               i.review_status, i.review_disposition, i.review_note,
               i.review_updated_at,
               COALESCE(a.attempt_count, 0) AS attempt_count,
               COALESCE(a.failed_count, 0) AS failed_count,
               COALESCE(a.deferred_count, 0) AS deferred_count,
               a.latest_attempt_at, a.latest_attempt_epoch,
               a.latest_recipient, a.latest_attempt_detail
        FROM incidents AS i
        LEFT JOIN attempts AS a
          ON a.incident_uuid = i.incident_uuid
        WHERE {_review_predicate()}
        ORDER BY
          CASE i.report_status
            WHEN 'failed' THEN 0
            WHEN 'no-contact' THEN 1
            WHEN 'deferred' THEN 2
            ELSE 3
          END,
          i.last_seen_epoch DESC
        {limit_sql}
    """
    result = [dict(row) for row in connection.execute(query, parameters)]
    for item in result:
        item["deferred_review_threshold"] = max(
            1,
            int(deferred_review_threshold),
        )
        item["review_reason"] = review_reason(item, now_epoch)
    return result


def open_review_count(
    connection: sqlite3.Connection,
    *,
    now_epoch: int,
    overdue_seconds: int,
    deferred_review_threshold: int,
) -> int:
    overdue_epoch = now_epoch - max(0, int(overdue_seconds))
    row = connection.execute(
        f"""
        WITH attempts AS (
            SELECT incident_uuid,
                   SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END)
                       AS deferred_count,
                   MAX(attempted_epoch) AS latest_attempt_epoch
            FROM report_attempts
            GROUP BY incident_uuid
        )
        SELECT COUNT(*)
        FROM incidents AS i
        LEFT JOIN attempts AS a
          ON a.incident_uuid = i.incident_uuid
        WHERE {_review_predicate()}
        """,
        (
            overdue_epoch,
            max(1, int(deferred_review_threshold)),
        ),
    ).fetchone()
    return int(row[0] if row else 0)



def attach_recent_attempts(
    connection: sqlite3.Connection,
    items: list[dict[str, Any]],
    *,
    per_incident: int,
) -> None:
    incident_ids = [str(item["incident_uuid"]) for item in items]
    if not incident_ids:
        return
    placeholders = ", ".join("?" for _ in incident_ids)
    query = f"""
        SELECT incident_uuid, attempted_at, recipient, status, detail,
               test_mode, message_id
        FROM (
            SELECT incident_uuid, attempted_at, recipient, status, detail,
                   test_mode, message_id, attempt_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY incident_uuid
                       ORDER BY attempt_id DESC
                   ) AS review_rank
            FROM report_attempts
            WHERE incident_uuid IN ({placeholders})
        )
        WHERE review_rank <= ?
        ORDER BY incident_uuid, review_rank
    """
    rows = connection.execute(
        query,
        [*incident_ids, max(1, int(per_incident))],
    )
    grouped: dict[str, list[dict[str, Any]]] = {
        incident_uuid: [] for incident_uuid in incident_ids
    }
    for row in rows:
        grouped[str(row["incident_uuid"])].append(dict(row))
    for item in items:
        item["recent_attempts"] = grouped.get(
            str(item["incident_uuid"]),
            [],
        )

def recent_review_actions(
    connection: sqlite3.Connection,
    limit: int,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT action_id, request_uuid, incident_uuid, action,
                   operator, note, previous_report_status,
                   new_report_status, previous_review_status,
                   new_review_status, disposition, requested_at,
                   applied_at
            FROM review_actions
            ORDER BY action_id DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        )
    ]


def build_review_snapshot(
    connection: sqlite3.Connection,
    config: Mapping[str, Any],
    max_rows: int,
    *,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    current = int(
        now_epoch if now_epoch is not None else utc_now().timestamp()
    )
    overdue_seconds = max(
        0,
        int(config.get("deferred_overdue_minutes", 60)) * 60,
    )
    threshold = max(1, int(config.get("deferred_attempt_threshold", 3)))
    items = _review_rows(
        connection,
        now_epoch=current,
        overdue_seconds=overdue_seconds,
        deferred_review_threshold=threshold,
        limit=max_rows,
    )
    attach_recent_attempts(
        connection,
        items,
        per_incident=int(config.get("recent_attempts_per_item", 10)),
    )
    return {
        "open_count": open_review_count(
            connection,
            now_epoch=current,
            overdue_seconds=overdue_seconds,
            deferred_review_threshold=threshold,
        ),
        "items": items,
        "recent_actions": recent_review_actions(connection, max_rows),
        "policy": {
            "deferred_overdue_minutes": int(
                config.get("deferred_overdue_minutes", 60)
            ),
            "deferred_attempt_threshold": threshold,
            "note_max_chars": int(config.get("note_max_chars", 2000)),
            "recent_attempts_per_item": int(
                config.get("recent_attempts_per_item", 10)
            ),
        },
        "allowed_actions": list(REVIEW_ACTIONS),
    }

# EOF: /home/alan/src/argent-sentinel-collector/src/review_queue.py
