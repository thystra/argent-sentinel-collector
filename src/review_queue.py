#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/review_queue.py
# Installed: /usr/lib/argent-sentinel/review_queue.py
"""Review-queue schema and sanitized projection helpers."""

from __future__ import annotations

import datetime as dt
import ipaddress
import sqlite3
import uuid
from typing import Any, Mapping

UTC = dt.timezone.utc
SCHEMA_VERSION = 8
OPEN_REPORT_STATES = ("failed", "no-contact")
CREDENTIAL_SPRAY_RULES = (
    "wordpress-credential-spray",
    "wordpress-persistent-credential-spray",
    "wordpress-persistent-single-account-bruteforce",
)
CREDENTIAL_REVIEW_ACTIONS = (
    "approve-report",
    "keep-suppressed",
    "duplicate-subsumed",
    "refresh-contact",
)
NETWORK_REVIEW_ACTIONS = (
    "network-block-180",
    "network-block-365",
    "network-observe",
    "network-reject",
    "network-remove-block",
    "network-note",
    "network-ack-protected",
)
REVIEW_ACTIONS = (
    "acknowledge",
    "retry",
    "suppress",
    "permanent-no-contact",
    *CREDENTIAL_REVIEW_ACTIONS,
    "note",
    *NETWORK_REVIEW_ACTIONS,
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
    """Install the schema-v8 incident and network review audit."""

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
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS network_cases (
            network_cidr TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'observing',
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
    for name, definition in (
        ("proposal_cidr", "TEXT"),
        ("proposal_revision", "TEXT"),
        ("proposal_hostile_ips", "INTEGER NOT NULL DEFAULT 0"),
        ("proposal_incident_count", "INTEGER NOT NULL DEFAULT 0"),
        ("proposal_event_count", "INTEGER NOT NULL DEFAULT 0"),
        ("proposal_active_days", "INTEGER NOT NULL DEFAULT 0"),
        ("proposal_coverage_percent", "REAL NOT NULL DEFAULT 0"),
        ("proposal_basis", "TEXT"),
        ("review_status", "TEXT NOT NULL DEFAULT 'open'"),
        ("review_disposition", "TEXT"),
        ("review_note", "TEXT"),
        ("review_updated_epoch", "INTEGER"),
        ("review_updated_at", "TEXT"),
        ("decision_cidr", "TEXT"),
        ("decision_status", "TEXT"),
        ("decision_detail", "TEXT"),
        ("decision_duration_days", "INTEGER NOT NULL DEFAULT 0"),
        ("decision_applied_at", "TEXT"),
    ):
        ensure_column(connection, "network_cases", name, definition)

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
        CREATE TABLE IF NOT EXISTS network_review_actions (
            action_id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_uuid TEXT NOT NULL UNIQUE,
            network_cidr TEXT NOT NULL REFERENCES network_cases(network_cidr),
            proposal_cidr TEXT,
            proposal_revision TEXT,
            action TEXT NOT NULL,
            operator TEXT NOT NULL,
            note TEXT,
            previous_status TEXT,
            new_status TEXT,
            previous_review_status TEXT,
            new_review_status TEXT,
            disposition TEXT,
            requested_duration_days INTEGER NOT NULL DEFAULT 0,
            decision_status TEXT,
            decision_detail TEXT,
            requested_at TEXT NOT NULL,
            applied_epoch INTEGER NOT NULL,
            applied_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS network_review_actions_case_time
            ON network_review_actions(network_cidr, applied_epoch DESC);
        CREATE INDEX IF NOT EXISTS network_review_actions_operator_time
            ON network_review_actions(operator, applied_epoch DESC);
        """
    )


def _configured_protection_sets(
    config: Mapping[str, Any] | None,
) -> tuple[list[Any], list[Any]]:
    if not isinstance(config, Mapping):
        return [], []
    trusted = config.get("trusted_cidrs", [])
    protection = config.get("enforcement_protection", {})
    protected = config.get("protected_cidrs", [])
    if isinstance(protection, Mapping):
        protected = protection.get("protected_cidrs", protected)
    return (
        list(trusted) if isinstance(trusted, list) else [],
        list(protected) if isinstance(protected, list) else [],
    )


def network_protection_match(
    proposal_cidr: Any,
    config: Mapping[str, Any] | None,
) -> dict[str, str] | None:
    value = str(proposal_cidr or "").strip()
    if not value:
        return None
    try:
        proposal = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    trusted, protected = _configured_protection_sets(config)
    for source, values in (
        ("trusted-cidrs", trusted),
        ("protected-cidrs", protected),
    ):
        for configured in values:
            try:
                network = ipaddress.ip_network(str(configured), strict=False)
            except ValueError:
                continue
            if network.version == proposal.version and network.overlaps(proposal):
                return {
                    "protection_status": "protected-overlap",
                    "protection_source": source,
                    "protected_by_cidr": str(network),
                }
    return None


def annotate_network_protection(
    row: dict[str, Any],
    config: Mapping[str, Any] | None,
) -> dict[str, Any]:
    match = network_protection_match(row.get("proposal_cidr"), config)
    row["protection_status"] = None
    row["protection_source"] = None
    row["protected_by_cidr"] = None
    if match:
        row.update(match)
    return row


def network_available_actions(row: Mapping[str, Any]) -> list[str]:
    status = str(row.get("status") or "")
    review_status = str(row.get("review_status") or "open")
    proposal = str(row.get("proposal_cidr") or "").strip()
    protected = str(row.get("protection_status") or "") == "protected-overlap"
    proposal_evidence = (
        int(row.get("proposal_hostile_ips") or 0) >= 2
        or int(row.get("proposal_active_days") or 0) >= 2
    )
    if status == "blocked":
        return ["network-remove-block", "network-note"]
    if review_status == "closed":
        return []
    if protected:
        return ["network-ack-protected", "network-note"]
    actions: list[str] = []
    if (
        status in {"escalation-review", "long-block-review"}
        and proposal
        and proposal_evidence
    ):
        actions.extend(("network-block-180", "network-block-365"))
    actions.extend(("network-observe", "network-reject", "network-note"))
    return actions

def _review_predicate() -> str:
    credential_marks = ", ".join(
        f"'{value}'" for value in CREDENTIAL_SPRAY_RULES
    )
    return f"""
        (
            COALESCE(i.review_status, 'open') != 'closed'
            OR (
                i.report_status IN ('failed', 'no-contact', 'deferred')
                AND COALESCE(a.latest_attempt_epoch, 0)
                    > COALESCE(i.review_updated_epoch, 0)
            )
            OR (
                i.report_status = 'suppressed'
                AND COALESCE(i.updated_at, '')
                    > COALESCE(i.review_updated_at, '')
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
                AND (
                    lower(COALESCE(i.report_detail, ''))
                        LIKE '%pending production review%'
                    OR (
                        i.rule_id IN ({credential_marks})
                        AND (
                            lower(COALESCE(i.report_detail, ''))
                                LIKE '%contact refresh%'
                            OR COALESCE(i.review_disposition, '')
                                IN (
                                    'credential-spray-review',
                                    'contact-refreshed'
                                )
                        )
                    )
                )
            )
        )
    """

def review_reason(row: Mapping[str, Any], now_epoch: int) -> str:
    report_status = str(row.get("report_status") or "")
    detail = str(row.get("report_detail") or "")
    rule_id = str(row.get("rule_id") or "")
    deferred_count = int(row.get("deferred_count") or 0)
    next_epoch = int(row.get("next_report_after_epoch") or 0)
    if report_status == "failed":
        return "delivery-failed"
    if report_status == "no-contact":
        return "no-contact-enforcement"
    if report_status == "deferred":
        if deferred_count >= int(row.get("deferred_review_threshold") or 3):
            return "repeatedly-deferred"
        if next_epoch <= now_epoch:
            return "overdue-deferred"
        return "deferred"
    if (
        rule_id in CREDENTIAL_SPRAY_RULES
        and report_status == "suppressed"
        and (
            "pending production review" in detail.lower()
            or "contact refresh" in detail.lower()
            or str(row.get("review_disposition") or "")
                in {"credential-spray-review", "contact-refreshed"}
        )
    ):
        return "credential-spray-review"
    if (
        report_status == "suppressed"
        and "pending production review" in detail.lower()
    ):
        return "policy-review"
    return "operator-review"

def available_actions(row: Mapping[str, Any]) -> list[str]:
    if str(row.get("review_reason") or "") == "credential-spray-review":
        return [*CREDENTIAL_REVIEW_ACTIONS, "note"]
    if str(row.get("review_reason") or "") == "no-contact-enforcement":
        # A no-contact review must remain open until local enforcement is
        # verified. The dashboard therefore exposes only retry and note.
        return ["retry", "note"]
    return [
        "acknowledge",
        "retry",
        "suppress",
        "permanent-no-contact",
        "note",
    ]


def append_operator_note(
    existing: Any,
    note: str,
    operator: str,
    applied_at: str,
) -> str:
    current = str(existing or "").strip()
    if not note:
        return current
    addition = f"[{applied_at} {operator}] {note}"
    return f"{current}\n{addition}".strip()


def _system_request_uuid(
    action: str,
    incident_uuid: str,
    revision: str,
) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"argent-sentinel:{action}:{incident_uuid}:{revision}",
        )
    )


def _record_system_action(
    connection: sqlite3.Connection,
    *,
    request_uuid: str,
    incident_uuid: str,
    action: str,
    operator: str,
    note: str,
    previous_report_status: str,
    new_report_status: str,
    previous_review_status: str,
    new_review_status: str,
    disposition: str,
    applied_epoch: int,
    applied_at: str,
) -> int | None:
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO review_actions (
            request_uuid, incident_uuid, action, operator, note,
            previous_report_status, new_report_status,
            previous_review_status, new_review_status,
            disposition, requested_at, applied_epoch, applied_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_uuid,
            incident_uuid,
            action,
            operator,
            note or None,
            previous_report_status,
            new_report_status,
            previous_review_status,
            new_review_status,
            disposition,
            applied_at,
            applied_epoch,
            applied_at,
        ),
    )
    return int(cursor.lastrowid) if cursor.rowcount else None


def close_no_contact_review(
    connection: sqlite3.Connection,
    incident_uuid: str,
    *,
    decision_status: str,
    decision_detail: str,
    report_detail: str,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Close a no-contact item only after active local enforcement succeeds."""

    if decision_status not in {"applied", "existing"}:
        return {
            "status": "unresolved",
            "incident_uuid": incident_uuid,
            "decision_status": decision_status,
        }
    install_review_schema(connection)
    incident = connection.execute(
        """
        SELECT incident_uuid, last_seen_epoch, report_status, report_detail,
               review_status, review_note
        FROM incidents WHERE incident_uuid = ?
        """,
        (incident_uuid,),
    ).fetchone()
    if incident is None:
        raise ValueError(f"Incident not found: {incident_uuid}")
    epoch = int(now_epoch if now_epoch is not None else utc_now().timestamp())
    applied_at = utc_text(dt.datetime.fromtimestamp(epoch, UTC))
    previous_report = str(incident["report_status"] or "no-contact")
    previous_review = str(incident["review_status"] or "open")
    note = (
        "No usable abuse contact; verified local CrowdSec enforcement "
        f"status={decision_status}: {decision_detail}"
    )
    review_note = append_operator_note(
        incident["review_note"],
        note,
        "system:no-contact",
        applied_at,
    )
    detail = str(report_detail or incident["report_detail"] or "").strip()
    suffix = (
        "No usable abuse contact; local enforcement verified; "
        f"decision={decision_status}: {decision_detail}"
    )
    if suffix not in detail:
        detail = f"{detail}; {suffix}" if detail else suffix
    revision = f"{incident['last_seen_epoch']}:{decision_status}"
    request_uuid = _system_request_uuid(
        "auto-no-contact-ban",
        incident_uuid,
        revision,
    )
    with connection:
        connection.execute(
            """
            UPDATE incidents
            SET report_status = 'no-contact',
                report_detail = ?,
                next_report_after_epoch = 0,
                review_status = 'closed',
                review_disposition = 'auto-no-contact-ban',
                review_note = ?,
                review_updated_epoch = ?,
                review_updated_at = ?,
                updated_at = ?
            WHERE incident_uuid = ?
            """,
            (
                detail,
                review_note or None,
                epoch,
                applied_at,
                applied_at,
                incident_uuid,
            ),
        )
        action_id = _record_system_action(
            connection,
            request_uuid=request_uuid,
            incident_uuid=incident_uuid,
            action="automatic-close",
            operator="system:no-contact",
            note=note,
            previous_report_status=previous_report,
            new_report_status="no-contact",
            previous_review_status=previous_review,
            new_review_status="closed",
            disposition="auto-no-contact-ban",
            applied_epoch=epoch,
            applied_at=applied_at,
        )
    return {
        "status": "closed",
        "incident_uuid": incident_uuid,
        "request_uuid": request_uuid,
        "action_id": action_id,
        "review_status": "closed",
        "disposition": "auto-no-contact-ban",
    }


def open_no_contact_review(
    connection: sqlite3.Connection,
    incident_uuid: str,
    *,
    decision_status: str,
    decision_detail: str,
    report_detail: str,
    retry_epoch: int,
    now_epoch: int | None = None,
) -> None:
    install_review_schema(connection)
    epoch = int(now_epoch if now_epoch is not None else utc_now().timestamp())
    applied_at = utc_text(dt.datetime.fromtimestamp(epoch, UTC))
    detail = str(report_detail or "").strip()
    suffix = (
        "No usable abuse contact; local enforcement could not be verified; "
        f"decision={decision_status}: {decision_detail}"
    )
    if suffix not in detail:
        detail = f"{detail}; {suffix}" if detail else suffix
    with connection:
        connection.execute(
            """
            UPDATE incidents
            SET report_status = 'no-contact',
                report_detail = ?,
                next_report_after_epoch = ?,
                review_status = 'open',
                review_disposition = 'no-contact-enforcement-failed',
                review_updated_epoch = ?,
                review_updated_at = ?,
                updated_at = ?
            WHERE incident_uuid = ?
            """,
            (
                detail,
                int(retry_epoch),
                epoch,
                applied_at,
                applied_at,
                incident_uuid,
            ),
        )


def reopen_contact_refreshed_review(
    connection: sqlite3.Connection,
    incident_uuid: str,
    *,
    recipients: list[str],
    now_epoch: int | None = None,
) -> dict[str, Any]:
    install_review_schema(connection)
    incident = connection.execute(
        """
        SELECT incident_uuid, report_status, review_status, review_note,
               review_updated_at
        FROM incidents WHERE incident_uuid = ?
        """,
        (incident_uuid,),
    ).fetchone()
    if incident is None:
        raise ValueError(f"Incident not found: {incident_uuid}")
    epoch = int(now_epoch if now_epoch is not None else utc_now().timestamp())
    applied_at = utc_text(dt.datetime.fromtimestamp(epoch, UTC))
    cleaned = sorted({str(value).strip().lower() for value in recipients if value})
    joined = ", ".join(cleaned)
    note = f"Contact refresh found usable recipient(s): {joined}"
    review_note = append_operator_note(
        incident["review_note"],
        note,
        "system:contact-refresh",
        applied_at,
    )
    detail = (
        f"Credential-spray contact refresh found {joined}; "
        "pending production review"
    )
    revision = str(incident["review_updated_at"] or applied_at)
    request_uuid = _system_request_uuid(
        "contact-refreshed",
        incident_uuid,
        revision,
    )
    with connection:
        connection.execute(
            """
            UPDATE incidents
            SET report_status = 'suppressed',
                report_detail = ?,
                report_recipient = ?,
                next_report_after_epoch = 0,
                review_status = 'open',
                review_disposition = 'contact-refreshed',
                review_note = ?,
                review_updated_epoch = ?,
                review_updated_at = ?,
                updated_at = ?
            WHERE incident_uuid = ?
            """,
            (
                detail,
                joined or None,
                review_note or None,
                epoch,
                applied_at,
                applied_at,
                incident_uuid,
            ),
        )
        action_id = _record_system_action(
            connection,
            request_uuid=request_uuid,
            incident_uuid=incident_uuid,
            action="automatic-refresh-result",
            operator="system:contact-refresh",
            note=note,
            previous_report_status=str(incident["report_status"] or "pending"),
            new_report_status="suppressed",
            previous_review_status=str(incident["review_status"] or "closed"),
            new_review_status="open",
            disposition="contact-refreshed",
            applied_epoch=epoch,
            applied_at=applied_at,
        )
    return {
        "status": "reopened",
        "incident_uuid": incident_uuid,
        "request_uuid": request_uuid,
        "action_id": action_id,
        "recipients": cleaned,
    }


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
        item["available_actions"] = available_actions(item)
        item["credential_spray_review"] = (
            item["review_reason"] == "credential-spray-review"
        )
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


def recent_network_review_actions(
    connection: sqlite3.Connection,
    limit: int,
) -> list[dict[str, Any]]:
    try:
        rows = connection.execute(
            """
            SELECT action_id, request_uuid, network_cidr, proposal_cidr,
                   proposal_revision, action, operator, note,
                   previous_status, new_status, previous_review_status,
                   new_review_status, disposition,
                   requested_duration_days, decision_status,
                   decision_detail, requested_at, applied_at
            FROM network_review_actions
            ORDER BY action_id DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        )
    except sqlite3.OperationalError:
        return []
    return [dict(row) for row in rows]


def prepare_network_cases(
    cases: list[dict[str, Any]],
    protection_config: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    for item in cases:
        annotate_network_protection(item, protection_config)
        item["available_actions"] = network_available_actions(item)
    return cases


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
    all_items = _review_rows(
        connection,
        now_epoch=current,
        overdue_seconds=overdue_seconds,
        deferred_review_threshold=threshold,
        limit=None,
    )
    items = all_items[: max(1, int(max_rows))]
    attach_recent_attempts(
        connection,
        items,
        per_incident=int(config.get("recent_attempts_per_item", 10)),
    )
    category_counts = {
        "credential_spray": sum(
            item["review_reason"] == "credential-spray-review"
            for item in all_items
        ),
        "no_contact": sum(
            item["review_reason"] == "no-contact-enforcement"
            for item in all_items
        ),
        "delivery_failed": sum(
            item["review_reason"] == "delivery-failed"
            for item in all_items
        ),
        "deferred": sum(
            item["review_reason"]
            in {"repeatedly-deferred", "overdue-deferred"}
            for item in all_items
        ),
    }
    category_counts["other"] = max(
        0,
        len(all_items) - sum(category_counts.values()),
    )
    return {
        "open_count": len(all_items),
        "category_counts": category_counts,
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
        "credential_spray_rules": list(CREDENTIAL_SPRAY_RULES),
    }

# EOF: /home/alan/src/argent-sentinel-collector/src/review_queue.py
