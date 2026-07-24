#!/usr/bin/env python3
"""Argent Sentinel host collector.

Imports atomic WordPress event batches, deduplicates immutable events, correlates
credential-spray incidents, and optionally submits long-lived CrowdSec decisions
and sanitized abuse reports.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import email.utils
import errno
import fcntl
import glob
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

LOG = logging.getLogger("argent-sentinel")
UTC = dt.timezone.utc

DEFAULTS: dict[str, Any] = {
    "state_db": "/var/lib/argent-sentinel/collector/state.sqlite3",
    "lock_file": "/run/argent-sentinel/collector.lock",
    "incoming_globs": [
        "/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json"
    ],
    "processing_dir": "/var/lib/argent-sentinel/collector/processing",
    "archive_dir": "/var/lib/argent-sentinel/collector/archive",
    "rejected_dir": "/var/lib/argent-sentinel/collector/rejected",
    "max_batch_bytes": 20 * 1024 * 1024,
    "trusted_cidrs": ["127.0.0.0/8", "::1/128", "192.168.0.0/16"],
    "policy": {
        "window_seconds": 60,
        "failure_threshold": 5,
        "distinct_accounts": 2,
        "single_account_threshold": 10,
        "incident_merge_seconds": 300,
        "max_enforcement_age_days": 7,
        "ban_duration": "720h",
        "reason_prefix": "argent-sentinel",
        "network_review_window_days": 7,
        "network_review_distinct_ips": 3,
        "network_escalation_distinct_ips": 5,
        "network_escalation_active_days": 3,
    },
    "crowdsec": {
        "enabled": False,
        "cscli_path": "/usr/bin/cscli",
        "command_timeout_seconds": 20,
    },
    "enrichment": {
        "enabled": True,
        "rdap_url": "https://rdap.org/ip/{ip}",
        "ripe_prefix_url": "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
        "timeout_seconds": 12,
        "cache_days": 7,
        "enrich_when_actions_disabled": False,
        "user_agent": "Argent-Sentinel/0.2.2 (+self-hosted security abuse reporting)",
        "asn_classifications": {},
    },
    "abuse_reporting": {
        "enabled": False,
        "test_mode": False,
        "from": "",
        "admin_copy": "",
        "recipient_override": "",
        "sendmail_path": "/usr/sbin/sendmail",
        "send_timeout_seconds": 30,
        "subject_prefix": "[Argent Sentinel]",
        "message_id_domain": "argentwolf.org",
        "operator_contact": "",
        "max_evidence_uuids": 20,
        "max_reports_per_run": 3,
        "max_report_age_hours": 24,
        "recipient_cooldown_minutes": 15,
        "max_reports_per_recipient_per_day": 10,
        "report_not_before_utc": "",
        "retry_backoff_minutes": 60,
    },
}


class CollectorError(RuntimeError):
    """Expected collector failure."""


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    value = value or utc_now()
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise CollectorError("Missing RFC3339 timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise CollectorError(f"Invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise CollectorError("Timestamp must include a timezone")
    return parsed.astimezone(UTC)


def deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key, value in base.items():
        merged[key] = deep_merge(value, {}) if isinstance(value, dict) else value
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Path) -> dict[str, Any]:
    try:
        supplied = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CollectorError(f"Configuration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CollectorError(f"Invalid configuration JSON: {exc}") from exc
    if not isinstance(supplied, dict):
        raise CollectorError("Configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    validate_config(config)
    return config


def validate_config(config: Mapping[str, Any]) -> None:
    policy = config["policy"]
    for name in (
        "window_seconds",
        "failure_threshold",
        "distinct_accounts",
        "single_account_threshold",
        "incident_merge_seconds",
        "max_enforcement_age_days",
        "network_review_window_days",
        "network_review_distinct_ips",
        "network_escalation_distinct_ips",
        "network_escalation_active_days",
    ):
        if int(policy[name]) < 1:
            raise CollectorError(f"policy.{name} must be positive")
    if not str(policy.get("ban_duration", "")).strip():
        raise CollectorError("policy.ban_duration is required")
    if not str(policy.get("reason_prefix", "")).strip():
        raise CollectorError("policy.reason_prefix is required")
    for cidr in config.get("trusted_cidrs", []):
        ipaddress.ip_network(str(cidr), strict=False)
    reporting = config["abuse_reporting"]
    if reporting.get("enabled") and not valid_email_header(str(reporting.get("from", ""))):
        raise CollectorError("abuse_reporting.from must contain a valid email address")
    for name in ("admin_copy", "recipient_override"):
        value = str(reporting.get(name, "")).strip()
        if value and not valid_email_header(value):
            raise CollectorError(f"abuse_reporting.{name} must contain a valid email address")
    test_mode = bool(reporting.get("test_mode"))
    override = str(reporting.get("recipient_override", "")).strip()
    if override and not test_mode:
        raise CollectorError("abuse_reporting.recipient_override requires test_mode=true")
    if test_mode and not override:
        raise CollectorError("abuse_reporting.test_mode requires recipient_override")
    for name in (
        "max_reports_per_run",
        "max_report_age_hours",
        "max_reports_per_recipient_per_day",
        "retry_backoff_minutes",
        "send_timeout_seconds",
    ):
        if int(reporting.get(name, 0)) < 1:
            raise CollectorError(f"abuse_reporting.{name} must be positive")
    if int(reporting.get("recipient_cooldown_minutes", 0)) < 0:
        raise CollectorError("abuse_reporting.recipient_cooldown_minutes cannot be negative")
    cutoff = str(reporting.get("report_not_before_utc", "")).strip()
    if cutoff:
        parse_time(cutoff)
    if reporting.get("enabled") and not test_mode and not cutoff:
        raise CollectorError(
            "abuse_reporting.report_not_before_utc is required when production reporting is enabled"
        )
    message_domain = str(reporting.get("message_id_domain", "")).strip()
    if not message_domain or any(character in message_domain for character in "\r\n <>@"):
        raise CollectorError("abuse_reporting.message_id_domain must be a safe DNS-style domain")


def valid_email_header(value: str) -> bool:
    value = value.strip()
    if not value or "\r" in value or "\n" in value:
        return False
    _, address = email.utils.parseaddr(value)
    return bool(address and "@" in address and len(address) <= 254)


def ensure_parent(path: Path, mode: int = 0o750) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=mode)


@contextlib.contextmanager
def process_lock(path: Path) -> Iterator[None]:
    ensure_parent(path)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CollectorError("Another collector process is already running") from exc
        yield


class StateDB:
    def __init__(self, path: Path) -> None:
        ensure_parent(path)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = FULL")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.install()

    def close(self) -> None:
        self.conn.close()

    def install(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS batches (
                batch_uuid TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                source_host TEXT NOT NULL,
                site_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                original_path TEXT NOT NULL,
                archived_path TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                event_uuid TEXT PRIMARY KEY,
                batch_uuid TEXT NOT NULL REFERENCES batches(batch_uuid),
                occurred_epoch INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                recorded_at TEXT,
                site_id TEXT NOT NULL,
                source_host TEXT NOT NULL,
                event_type TEXT NOT NULL,
                outcome TEXT NOT NULL,
                source_ip TEXT,
                account_key TEXT,
                user_agent TEXT,
                request_path TEXT,
                metadata_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_ip_time
                ON events(source_ip, event_type, outcome, occurred_epoch);
            CREATE INDEX IF NOT EXISTS events_site_time
                ON events(site_id, occurred_epoch);
            CREATE TABLE IF NOT EXISTS incidents (
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
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS incidents_ip_time
                ON incidents(source_ip, rule_id, last_seen_epoch);
            CREATE INDEX IF NOT EXISTS incidents_network_time
                ON incidents(network_cidr, last_seen_epoch);
            CREATE TABLE IF NOT EXISTS incident_events (
                incident_uuid TEXT NOT NULL REFERENCES incidents(incident_uuid),
                event_uuid TEXT NOT NULL REFERENCES events(event_uuid),
                PRIMARY KEY (incident_uuid, event_uuid)
            );
            CREATE TABLE IF NOT EXISTS enrichment_cache (
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
            CREATE TABLE IF NOT EXISTS report_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_uuid TEXT NOT NULL REFERENCES incidents(incident_uuid),
                attempted_epoch INTEGER NOT NULL,
                attempted_at TEXT NOT NULL,
                recipient TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                test_mode INTEGER NOT NULL DEFAULT 0,
                message_id TEXT
            );
            CREATE INDEX IF NOT EXISTS report_attempts_recipient_time
                ON report_attempts(recipient, test_mode, status, attempted_epoch);
            CREATE INDEX IF NOT EXISTS report_attempts_incident_time
                ON report_attempts(incident_uuid, attempted_epoch);
            """
        )
        self.ensure_column("incidents", "registered_cidr", "TEXT")
        self.ensure_column("incidents", "next_report_after_epoch", "INTEGER NOT NULL DEFAULT 0")
        self.ensure_column("incidents", "report_sent_epoch", "INTEGER")
        self.ensure_column("incidents", "report_recipient", "TEXT")
        self.ensure_column("incidents", "report_message_id", "TEXT")
        self.conn.commit()

    def ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {str(row[1]) for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def batch_exists(self, batch_uuid: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM batches WHERE batch_uuid = ?", (batch_uuid,)
        ).fetchone() is not None

    def import_batch(
        self,
        batch: Mapping[str, Any],
        digest: str,
        original_path: Path,
        events: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        source = batch["source"]
        imported: list[dict[str, Any]] = []
        with self.conn:
            self.conn.execute(
                """INSERT INTO batches
                (batch_uuid, sha256, source_host, site_id, created_at, imported_at, original_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    batch["batch_uuid"],
                    digest,
                    source["host"],
                    source["site_id"],
                    batch["created_at"],
                    utc_text(),
                    str(original_path),
                ),
            )
            for event in events:
                cursor = self.conn.execute(
                    """INSERT OR IGNORE INTO events
                    (event_uuid, batch_uuid, occurred_epoch, occurred_at, recorded_at,
                     site_id, source_host, event_type, outcome, source_ip, account_key,
                     user_agent, request_path, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event["event_uuid"],
                        batch["batch_uuid"],
                        event["occurred_epoch"],
                        event["occurred_at"],
                        event.get("recorded_at"),
                        source["site_id"],
                        source["host"],
                        event["event_type"],
                        event["outcome"],
                        event.get("source_ip"),
                        event.get("account_key"),
                        event.get("user_agent"),
                        event.get("request_path"),
                        json.dumps(event.get("metadata", {}), sort_keys=True, separators=(",", ":")),
                    ),
                )
                if cursor.rowcount == 1:
                    imported.append(dict(event))
        return imported

    def set_archive_path(self, batch_uuid: str, path: Path) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE batches SET archived_path = ? WHERE batch_uuid = ?",
                (str(path), batch_uuid),
            )

    def login_failures(self, source_ip: str, start_epoch: int, end_epoch: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT event_uuid, occurred_epoch, occurred_at, site_id, account_key,
                          user_agent, request_path
                   FROM events
                   WHERE source_ip = ?
                     AND event_type = 'login_failed'
                     AND outcome = 'denied'
                     AND occurred_epoch BETWEEN ? AND ?
                   ORDER BY occurred_epoch ASC, event_uuid ASC""",
                (source_ip, start_epoch, end_epoch),
            )
        )

    def recent_incident(self, source_ip: str, rule_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT * FROM incidents
               WHERE source_ip = ? AND rule_id = ?
               ORDER BY last_seen_epoch DESC LIMIT 1""",
            (source_ip, rule_id),
        ).fetchone()

    def create_or_merge_incident(
        self,
        source_ip: str,
        rule_id: str,
        rows: Sequence[sqlite3.Row],
        merge_seconds: int,
    ) -> str:
        first_epoch = min(int(row["occurred_epoch"]) for row in rows)
        last_epoch = max(int(row["occurred_epoch"]) for row in rows)
        recent = self.recent_incident(source_ip, rule_id)
        if recent is not None and first_epoch <= int(recent["last_seen_epoch"]) + merge_seconds:
            incident_uuid = str(recent["incident_uuid"])
        else:
            incident_uuid = str(uuid.uuid4())
            now = utc_text()
            network = candidate_network(source_ip)
            with self.conn:
                self.conn.execute(
                    """INSERT INTO incidents
                    (incident_uuid, source_ip, rule_id, first_seen_epoch, last_seen_epoch,
                     first_seen, last_seen, event_count, distinct_accounts, site_count,
                     network_cidr, decision_status, report_status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, 'pending', 'pending', ?, ?)""",
                    (
                        incident_uuid,
                        source_ip,
                        rule_id,
                        first_epoch,
                        last_epoch,
                        epoch_text(first_epoch),
                        epoch_text(last_epoch),
                        network,
                        now,
                        now,
                    ),
                )
        with self.conn:
            for row in rows:
                self.conn.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_uuid, event_uuid) VALUES (?, ?)",
                    (incident_uuid, row["event_uuid"]),
                )
            stats = self.conn.execute(
                """SELECT MIN(e.occurred_epoch) AS first_epoch,
                          MAX(e.occurred_epoch) AS last_epoch,
                          COUNT(*) AS event_count,
                          COUNT(DISTINCT e.account_key) AS distinct_accounts,
                          COUNT(DISTINCT e.site_id) AS site_count
                   FROM incident_events ie JOIN events e ON e.event_uuid = ie.event_uuid
                   WHERE ie.incident_uuid = ?""",
                (incident_uuid,),
            ).fetchone()
            self.conn.execute(
                """UPDATE incidents SET
                    first_seen_epoch = ?, last_seen_epoch = ?, first_seen = ?, last_seen = ?,
                    event_count = ?, distinct_accounts = ?, site_count = ?, updated_at = ?
                   WHERE incident_uuid = ?""",
                (
                    stats["first_epoch"],
                    stats["last_epoch"],
                    epoch_text(stats["first_epoch"]),
                    epoch_text(stats["last_epoch"]),
                    stats["event_count"],
                    stats["distinct_accounts"],
                    stats["site_count"],
                    utc_text(),
                    incident_uuid,
                ),
            )
        return incident_uuid

    def pending_incidents(self, retry_dry_run: bool, retry_disabled_reports: bool) -> list[sqlite3.Row]:
        decision_states = ["pending", "failed"]
        report_states = ["pending", "failed", "deferred"]
        if retry_dry_run:
            decision_states.append("dry-run")
        if retry_disabled_reports:
            report_states.extend(["disabled", "no-contact"])
        decision_marks = ",".join("?" for _ in decision_states)
        report_marks = ",".join("?" for _ in report_states)
        now_epoch = int(utc_now().timestamp())
        query = f"""SELECT * FROM incidents
                    WHERE decision_status IN ({decision_marks})
                       OR (
                           report_status IN ({report_marks})
                           AND COALESCE(next_report_after_epoch, 0) <= ?
                       )
                    ORDER BY created_at ASC"""
        return list(
            self.conn.execute(
                query,
                tuple(decision_states + report_states + [now_epoch]),
            )
        )

    def incident(self, incident_uuid: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM incidents WHERE incident_uuid = ?", (incident_uuid,)
        ).fetchone()
        if row is None:
            raise CollectorError(f"Incident not found: {incident_uuid}")
        return row

    def incident_evidence(self, incident_uuid: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT e.* FROM incident_events ie
                   JOIN events e ON e.event_uuid = ie.event_uuid
                   WHERE ie.incident_uuid = ?
                   ORDER BY e.occurred_epoch ASC, e.event_uuid ASC""",
                (incident_uuid,),
            )
        )

    def update_incident(self, incident_uuid: str, **values: Any) -> None:
        allowed = {
            "decision_status", "decision_detail", "report_status", "report_detail",
            "network_cidr", "registered_cidr", "asn", "asn_holder", "network_class",
            "next_report_after_epoch", "report_sent_epoch", "report_recipient",
            "report_message_id",
        }
        clean = {key: value for key, value in values.items() if key in allowed}
        if not clean:
            return
        clean["updated_at"] = utc_text()
        columns = ", ".join(f"{key} = ?" for key in clean)
        with self.conn:
            self.conn.execute(
                f"UPDATE incidents SET {columns} WHERE incident_uuid = ?",
                tuple(clean.values()) + (incident_uuid,),
            )


    def record_report_attempt(
        self,
        incident_uuid: str,
        recipients: Sequence[str],
        status: str,
        detail: str,
        *,
        test_mode: bool,
        message_id: str | None = None,
        attempted_epoch: int | None = None,
    ) -> None:
        epoch = int(attempted_epoch if attempted_epoch is not None else utc_now().timestamp())
        attempted_at = epoch_text(epoch)
        normalized = sorted({str(item).strip().lower() for item in recipients if str(item).strip()})
        rows: list[str | None] = normalized or [None]
        with self.conn:
            for recipient in rows:
                self.conn.execute(
                    """INSERT INTO report_attempts
                    (incident_uuid, attempted_epoch, attempted_at, recipient, status,
                     detail, test_mode, message_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        incident_uuid,
                        epoch,
                        attempted_at,
                        recipient,
                        status,
                        clean_optional(detail, 2000),
                        1 if test_mode else 0,
                        clean_optional(message_id, 255),
                    ),
                )

    def recipient_report_stats(
        self,
        recipient: str,
        *,
        test_mode: bool,
        since_epoch: int,
    ) -> tuple[int, int | None, int | None]:
        row = self.conn.execute(
            """SELECT COUNT(*) AS sent_count,
                      MAX(attempted_epoch) AS last_sent_epoch,
                      MIN(attempted_epoch) AS oldest_sent_epoch
               FROM report_attempts
               WHERE recipient = ?
                 AND test_mode = ?
                 AND status = 'sent'
                 AND attempted_epoch >= ?""",
            (recipient.strip().lower(), 1 if test_mode else 0, int(since_epoch)),
        ).fetchone()
        count = int(row["sent_count"] or 0)
        last_epoch = int(row["last_sent_epoch"]) if row["last_sent_epoch"] is not None else None
        oldest_epoch = int(row["oldest_sent_epoch"]) if row["oldest_sent_epoch"] is not None else None
        return count, last_epoch, oldest_epoch

    def incident_sites(self, incident_uuid: str) -> list[str]:
        return [
            str(row[0])
            for row in self.conn.execute(
                """SELECT DISTINCT e.site_id
                   FROM incident_events ie
                   JOIN events e ON e.event_uuid = ie.event_uuid
                   WHERE ie.incident_uuid = ?
                   ORDER BY e.site_id ASC""",
                (incident_uuid,),
            )
        ]

    def recent_report_attempts(self, limit: int = 20) -> list[sqlite3.Row]:
        bounded = max(1, min(100, int(limit)))
        return list(
            self.conn.execute(
                """SELECT attempt_id, incident_uuid, attempted_at, recipient, status,
                          detail, test_mode, message_id
                   FROM report_attempts
                   ORDER BY attempt_id DESC LIMIT ?""",
                (bounded,),
            )
        )

    def cache_get(self, source_ip: str, now_epoch: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM enrichment_cache WHERE source_ip = ? AND expires_epoch > ?",
            (source_ip, now_epoch),
        ).fetchone()

    def cache_put(self, source_ip: str, data: Mapping[str, Any], cache_days: int) -> None:
        now = int(utc_now().timestamp())
        with self.conn:
            self.conn.execute(
                """INSERT INTO enrichment_cache
                (source_ip, fetched_epoch, expires_epoch, network_cidr, network_name,
                 asn, asn_holder, abuse_emails_json, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_ip) DO UPDATE SET
                 fetched_epoch=excluded.fetched_epoch, expires_epoch=excluded.expires_epoch,
                 network_cidr=excluded.network_cidr, network_name=excluded.network_name,
                 asn=excluded.asn, asn_holder=excluded.asn_holder,
                 abuse_emails_json=excluded.abuse_emails_json, raw_json=excluded.raw_json""",
                (
                    source_ip,
                    now,
                    now + max(1, cache_days) * 86400,
                    data.get("network_cidr"),
                    data.get("network_name"),
                    data.get("asn"),
                    data.get("asn_holder"),
                    json.dumps(data.get("abuse_emails", []), sort_keys=True),
                    json.dumps(data.get("raw", {}), sort_keys=True),
                ),
            )

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for table in ("batches", "events", "incidents"):
            result[table] = int(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        result["pending_decisions"] = int(
            self.conn.execute("SELECT COUNT(*) FROM incidents WHERE decision_status IN ('pending','failed')").fetchone()[0]
        )
        result["pending_reports"] = int(
            self.conn.execute("SELECT COUNT(*) FROM incidents WHERE report_status IN ('pending','failed','deferred')").fetchone()[0]
        )
        return result

    def recent_incidents(self, limit: int = 20) -> list[sqlite3.Row]:
        limit = max(1, min(100, int(limit)))
        return list(
            self.conn.execute(
                """SELECT incident_uuid, source_ip, rule_id, first_seen, last_seen,
                          event_count, distinct_accounts, site_count, network_cidr,
                          registered_cidr, asn, asn_holder, network_class,
                          decision_status, decision_detail, report_status, report_detail,
                          next_report_after_epoch, report_sent_epoch, report_recipient,
                          report_message_id
                   FROM incidents ORDER BY last_seen_epoch DESC LIMIT ?""",
                (limit,),
            )
        )

    def network_candidates(self, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
        cutoff = int(utc_now().timestamp()) - int(policy["network_review_window_days"]) * 86400
        review_ips = int(policy["network_review_distinct_ips"])
        escalation_ips = int(policy["network_escalation_distinct_ips"])
        escalation_days = int(policy["network_escalation_active_days"])
        rows = self.conn.execute(
            """SELECT network_cidr,
                      COUNT(DISTINCT source_ip) AS hostile_ips,
                      COUNT(DISTINCT substr(first_seen, 1, 10)) AS active_days,
                      MIN(first_seen) AS first_seen,
                      MAX(last_seen) AS last_seen,
                      GROUP_CONCAT(DISTINCT asn) AS asns,
                      GROUP_CONCAT(DISTINCT network_class) AS network_classes
               FROM incidents
               WHERE network_cidr IS NOT NULL AND last_seen_epoch >= ?
               GROUP BY network_cidr
               HAVING COUNT(DISTINCT source_ip) >= ?
               ORDER BY hostile_ips DESC, active_days DESC, last_seen DESC""",
            (cutoff, review_ips),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["recommendation"] = (
                "escalation-review"
                if int(row["hostile_ips"]) >= escalation_ips or int(row["active_days"]) >= escalation_days
                else "review"
            )
            item["automatic_block"] = False
            result.append(item)
        return result


def epoch_text(epoch: int) -> str:
    return dt.datetime.fromtimestamp(int(epoch), UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def candidate_network(source_ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def validate_uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise CollectorError(f"{name} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise CollectorError(f"Invalid {name}") from exc
    return str(parsed)


def normalize_batch(raw: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(raw, dict):
        raise CollectorError("Batch root must be an object")
    if raw.get("schema_version") != 1:
        raise CollectorError("Unsupported batch schema_version")
    batch_uuid = validate_uuid(raw.get("batch_uuid"), "batch_uuid")
    created_at = utc_text(parse_time(raw.get("created_at")))
    source = raw.get("source")
    if not isinstance(source, dict):
        raise CollectorError("Batch source must be an object")
    normalized_source: dict[str, str] = {}
    for key in ("host", "site_id", "site_url", "service", "plugin_version"):
        value = source.get(key)
        if not isinstance(value, str) or not value.strip():
            raise CollectorError(f"Batch source.{key} is required")
        normalized_source[key] = value.strip()[:512]
    if normalized_source["service"] != "wordpress":
        raise CollectorError("This collector build accepts WordPress batches only")
    raw_events = raw.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise CollectorError("Batch events must be a non-empty array")
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_event in raw_events:
        event = normalize_event(raw_event, normalized_source["site_id"])
        if event["event_uuid"] in seen:
            raise CollectorError("Duplicate event_uuid inside batch")
        seen.add(event["event_uuid"])
        events.append(event)
    return (
        {
            "schema_version": 1,
            "batch_uuid": batch_uuid,
            "created_at": created_at,
            "source": normalized_source,
        },
        events,
    )


def normalize_event(raw: Any, site_id: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CollectorError("Event must be an object")
    event_uuid = validate_uuid(raw.get("event_uuid"), "event_uuid")
    occurred = parse_time(raw.get("occurred_at"))
    recorded_value = raw.get("recorded_at")
    recorded = utc_text(parse_time(recorded_value)) if recorded_value else None
    event_type = str(raw.get("event_type", "")).strip()[:64]
    outcome = str(raw.get("outcome", "")).strip()[:32]
    if not event_type or not outcome:
        raise CollectorError("Event type and outcome are required")
    source_ip: str | None = None
    if raw.get("source_ip") not in (None, ""):
        try:
            source_ip = str(ipaddress.ip_address(str(raw["source_ip"])))
        except ValueError as exc:
            raise CollectorError("Event contains malformed source_ip") from exc
    user_id = raw.get("wordpress_user_id")
    username = raw.get("username")
    account_key: str | None = None
    if user_id is not None:
        try:
            numeric_id = int(user_id)
        except (TypeError, ValueError) as exc:
            raise CollectorError("wordpress_user_id must be an integer") from exc
        if numeric_id > 0:
            account_key = f"{site_id}:user:{numeric_id}"
    elif isinstance(username, str) and username.strip():
        account_key = f"{site_id}:login:{username.strip().casefold()}"
    request = raw.get("request") if isinstance(raw.get("request"), dict) else {}
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    return {
        "event_uuid": event_uuid,
        "occurred_epoch": int(occurred.timestamp()),
        "occurred_at": utc_text(occurred),
        "recorded_at": recorded,
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": source_ip,
        "account_key": account_key,
        "user_agent": clean_optional(raw.get("user_agent"), 512),
        "request_path": clean_optional(request.get("path"), 1024),
        "metadata": metadata,
    }


def clean_optional(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    cleaned = str(value).replace("\r", " ").replace("\n", " ").strip()
    return cleaned[:limit] or None


class Collector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.db = StateDB(Path(config["state_db"]))
        self.trusted = [ipaddress.ip_network(str(cidr), strict=False) for cidr in config["trusted_cidrs"]]
        self._enrichment_results: dict[str, dict[str, Any]] = {}
        self._enrichment_errors: dict[str, str] = {}

    def close(self) -> None:
        self.db.close()

    def run(self) -> int:
        imported_files = 0
        for path in self.incoming_files():
            claimed: Path | None = None
            try:
                claimed = self.claim_file(path)
                self.process_file(claimed, original_path=path)
                imported_files += 1
            except Exception as exc:  # continue processing independent batches
                LOG.exception("Rejecting batch %s: %s", path, exc)
                self.reject_file(claimed or path, str(exc))
        self.retry_pending_incidents()
        LOG.info("Collector run complete: %d files", imported_files)
        return imported_files

    def incoming_files(self) -> list[Path]:
        paths: set[Path] = set()
        for pattern in self.config["incoming_globs"]:
            for value in glob.glob(str(pattern)):
                path = Path(value)
                if path.name.startswith(".") or path.suffix.lower() != ".json":
                    continue
                paths.add(path)
        return sorted(paths, key=lambda item: str(item))

    def claim_file(self, path: Path) -> Path:
        try:
            initial = path.lstat()
        except FileNotFoundError as exc:
            raise CollectorError("Incoming batch disappeared before it could be claimed") from exc
        if path.is_symlink() or not path.is_file():
            raise CollectorError("Incoming batch must be a regular, non-symlink file")
        processing = Path(self.config["processing_dir"])
        processing.mkdir(parents=True, exist_ok=True, mode=0o750)
        claimed = processing / f"{uuid.uuid4()}-{path.name}"
        copied = self.move_regular_file(path, claimed, initial)
        moved = claimed.lstat()
        if not stat_is_regular(moved.st_mode):
            raise CollectorError("Claimed batch is not a regular file")
        if copied:
            if moved.st_size != initial.st_size:
                raise CollectorError("Cross-filesystem claim changed the batch size")
        elif moved.st_dev != initial.st_dev or moved.st_ino != initial.st_ino:
            raise CollectorError("Incoming batch changed filesystem identity while being claimed")
        if os.geteuid() == 0:
            os.chown(claimed, 0, 0)
        os.chmod(claimed, 0o400)
        return claimed

    def move_regular_file(
        self,
        source: Path,
        destination: Path,
        expected_stat: os.stat_result | None = None,
    ) -> bool:
        """Move a regular file, copying safely when rename crosses filesystems.

        Returns True when a copy-and-unlink fallback was required. The fallback
        writes a hidden temporary file in the destination directory, fsyncs it,
        and atomically publishes it before removing the original.
        """
        expected = expected_stat or source.lstat()
        if not stat_is_regular(expected.st_mode):
            raise CollectorError("Source must be a regular file")
        try:
            os.replace(source, destination)
            return False
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise

        temporary = destination.parent / f".{destination.name}.{uuid.uuid4()}.tmp"
        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        source_fd = os.open(source, source_flags)
        destination_fd: int | None = None
        published = False
        try:
            opened = os.fstat(source_fd)
            if not stat_is_regular(opened.st_mode):
                raise CollectorError("Source changed into a non-regular file")
            if opened.st_dev != expected.st_dev or opened.st_ino != expected.st_ino:
                raise CollectorError("Source changed identity before cross-filesystem copy")

            destination_fd = os.open(temporary, destination_flags, 0o600)
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise CollectorError("Short write during cross-filesystem copy")
                    view = view[written:]
            os.fsync(destination_fd)

            after = os.fstat(source_fd)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
            ):
                raise CollectorError("Source changed while being copied")

            current = source.lstat()
            if current.st_dev != expected.st_dev or current.st_ino != expected.st_ino:
                raise CollectorError("Source path changed before cross-filesystem publish")

            os.replace(temporary, destination)
            published = True
            self.fsync_directory(destination.parent)
            source.unlink()
            self.fsync_directory(source.parent)
            return True
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            os.close(source_fd)
            if not published:
                with contextlib.suppress(FileNotFoundError):
                    temporary.unlink()

    @staticmethod
    def fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def read_claimed_file(self, path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            stat_result = os.fstat(fd)
            if not stat_is_regular(stat_result.st_mode):
                raise CollectorError("Claimed batch is not a regular file")
            if stat_result.st_size <= 0 or stat_result.st_size > int(self.config["max_batch_bytes"]):
                raise CollectorError("Incoming batch size is outside configured limits")
            chunks: list[bytes] = []
            remaining = stat_result.st_size
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != stat_result.st_size:
                raise CollectorError("Incoming batch changed while being read")
            return data
        finally:
            os.close(fd)

    def process_file(self, path: Path, original_path: Path) -> None:
        data = self.read_claimed_file(path)
        digest = hashlib.sha256(data).hexdigest()
        try:
            raw = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorError(f"Batch is not valid UTF-8 JSON: {exc}") from exc
        batch, events = normalize_batch(raw)
        if self.db.batch_exists(batch["batch_uuid"]):
            archive = self.archive_file(path, original_path.name, batch["batch_uuid"], duplicate=True)
            LOG.info("Archived duplicate batch %s as %s", batch["batch_uuid"], archive)
            return
        imported = self.db.import_batch(batch, digest, original_path, events)
        archive = self.archive_file(path, original_path.name, batch["batch_uuid"], duplicate=False)
        self.db.set_archive_path(batch["batch_uuid"], archive)
        LOG.info(
            "Imported batch %s: %d new of %d events",
            batch["batch_uuid"], len(imported), len(events),
        )
        self.evaluate_new_events(imported)

    def archive_file(self, path: Path, original_name: str, batch_uuid: str, duplicate: bool) -> Path:
        now = utc_now()
        destination = Path(self.config["archive_dir"]) / f"{now:%Y}" / f"{now:%m}" / f"{now:%d}"
        if duplicate:
            destination /= "duplicates"
        destination.mkdir(parents=True, exist_ok=True, mode=0o750)
        safe_name = Path(original_name).name
        final = destination / safe_name
        if final.exists():
            original = Path(safe_name)
            final = destination / f"{original.stem}-{batch_uuid}{original.suffix}"
        self.move_regular_file(path, final)
        if os.geteuid() == 0:
            os.chown(final, 0, 0)
        os.chmod(final, 0o640)
        return final

    def reject_file(self, path: Path, error: str) -> None:
        if not path.exists() or path.is_symlink():
            return
        destination = Path(self.config["rejected_dir"]) / f"{utc_now():%Y-%m-%d}"
        destination.mkdir(parents=True, exist_ok=True, mode=0o750)
        final = destination / path.name
        if final.exists():
            final = destination / f"{path.stem}-{uuid.uuid4()}{path.suffix}"
        self.move_regular_file(path, final)
        os.chmod(final, 0o640)
        error_path = final.with_suffix(final.suffix + ".error.txt")
        error_path.write_text(clean_optional(error, 2000) or "Unknown error", encoding="utf-8")
        os.chmod(error_path, 0o640)

    def evaluate_new_events(self, events: Sequence[Mapping[str, Any]]) -> None:
        policy_events = [
            event for event in events
            if event.get("event_type") == "login_failed"
            and event.get("outcome") == "denied"
            and event.get("source_ip")
        ]
        by_ip: dict[str, list[Mapping[str, Any]]] = {}
        for event in policy_events:
            by_ip.setdefault(str(event["source_ip"]), []).append(event)
        window = int(self.config["policy"]["window_seconds"])
        for source_ip, new_rows in by_ip.items():
            earliest = min(int(item["occurred_epoch"]) for item in new_rows) - window
            latest = max(int(item["occurred_epoch"]) for item in new_rows) + window
            rows = self.db.login_failures(source_ip, earliest, latest)
            for rule_id, evidence in self.find_candidates(rows):
                incident_uuid = self.db.create_or_merge_incident(
                    source_ip,
                    rule_id,
                    evidence,
                    int(self.config["policy"]["incident_merge_seconds"]),
                )
                LOG.warning(
                    "Credential-spray incident %s: ip=%s rule=%s events=%d accounts=%d",
                    incident_uuid,
                    source_ip,
                    rule_id,
                    len(evidence),
                    len({row["account_key"] for row in evidence if row["account_key"]}),
                )

    def find_candidates(self, rows: Sequence[sqlite3.Row]) -> list[tuple[str, list[sqlite3.Row]]]:
        policy = self.config["policy"]
        window_seconds = int(policy["window_seconds"])
        candidates: list[tuple[str, list[sqlite3.Row]]] = []
        segment: list[sqlite3.Row] = []
        previous_epoch: int | None = None
        for row in rows:
            current = int(row["occurred_epoch"])
            if previous_epoch is not None and current - previous_epoch > window_seconds:
                candidate = self.qualify_segment(segment)
                if candidate is not None:
                    candidates.append(candidate)
                segment = []
            segment.append(row)
            previous_epoch = current
        candidate = self.qualify_segment(segment)
        if candidate is not None:
            candidates.append(candidate)
        return candidates

    def qualify_segment(self, segment: Sequence[sqlite3.Row]) -> tuple[str, list[sqlite3.Row]] | None:
        if not segment:
            return None
        policy = self.config["policy"]
        window_seconds = int(policy["window_seconds"])
        threshold = int(policy["failure_threshold"])
        distinct_required = int(policy["distinct_accounts"])
        single_threshold = int(policy["single_account_threshold"])
        active: deque[sqlite3.Row] = deque()
        primary = False
        single = False
        single_key: str | None = None
        for row in segment:
            current = int(row["occurred_epoch"])
            while active and int(active[0]["occurred_epoch"]) < current - window_seconds:
                active.popleft()
            active.append(row)
            accounts = {item["account_key"] for item in active if item["account_key"]}
            if len(active) >= threshold and len(accounts) >= distinct_required:
                primary = True
                break
            counts: dict[str, int] = {}
            for item in active:
                key = item["account_key"]
                if key:
                    counts[key] = counts.get(key, 0) + 1
            if counts and max(counts.values()) >= single_threshold:
                single = True
                single_key = max(counts, key=counts.get)
                break
        if primary:
            return "wordpress-credential-spray", list(segment)
        if single and single_key is not None:
            return (
                "wordpress-single-account-bruteforce",
                [item for item in segment if item["account_key"] == single_key],
            )
        return None

    def retry_pending_incidents(self) -> None:
        reporting = self.config["abuse_reporting"]
        reporting_enabled = bool(reporting.get("enabled"))
        max_reports = int(reporting["max_reports_per_run"])
        processed_reports = 0

        for incident in self.db.pending_incidents(
            retry_dry_run=bool(self.config["crowdsec"].get("enabled")),
            retry_disabled_reports=reporting_enabled,
        ):
            incident_uuid = str(incident["incident_uuid"])
            decision_states = {"pending", "failed"}
            if self.config["crowdsec"].get("enabled"):
                decision_states.add("dry-run")
            if incident["decision_status"] in decision_states:
                status, detail = self.apply_decision(incident)
                self.db.update_incident(
                    incident_uuid,
                    decision_status=status,
                    decision_detail=detail,
                )

            incident = self.db.incident(incident_uuid)
            report_states = {"pending", "failed", "deferred"}
            if reporting_enabled:
                report_states.update({"disabled", "no-contact"})
            if incident["report_status"] not in report_states:
                continue
            if int(incident["next_report_after_epoch"] or 0) > int(utc_now().timestamp()):
                continue

            if not reporting_enabled:
                self.db.update_incident(
                    incident_uuid,
                    report_status="disabled",
                    report_detail="Abuse reporting disabled in configuration",
                    next_report_after_epoch=0,
                )
                continue

            gate = self.report_time_gate(incident)
            if gate is not None:
                status, detail = gate
                self.db.update_incident(
                    incident_uuid,
                    report_status=status,
                    report_detail=detail,
                    next_report_after_epoch=0,
                )
                self.db.record_report_attempt(
                    incident_uuid,
                    [],
                    status,
                    detail,
                    test_mode=bool(reporting.get("test_mode")),
                )
                continue

            # Limit both enrichment work and outbound mail attempts per collector run.
            if processed_reports >= max_reports:
                continue
            processed_reports += 1

            try:
                enrichment = self.enrich(str(incident["source_ip"]))
                self.db.update_incident(
                    incident_uuid,
                    registered_cidr=enrichment.get("network_cidr"),
                    asn=enrichment.get("asn"),
                    asn_holder=enrichment.get("asn_holder"),
                    network_class=enrichment.get("network_class", "unknown"),
                )
            except Exception as exc:
                detail = f"Enrichment failed before abuse report: {exc}"
                next_epoch = self.report_retry_epoch()
                self.db.update_incident(
                    incident_uuid,
                    report_status="failed",
                    report_detail=detail,
                    next_report_after_epoch=next_epoch,
                )
                self.db.record_report_attempt(
                    incident_uuid,
                    [],
                    "failed",
                    detail,
                    test_mode=bool(reporting.get("test_mode")),
                )
                LOG.warning("Enrichment failed for %s: %s", incident["source_ip"], exc)
                continue

            incident = self.db.incident(incident_uuid)
            recipients = self.report_recipients(enrichment)
            if not recipients:
                detail = "No RDAP abuse email was found"
                next_epoch = self.report_retry_epoch()
                self.db.update_incident(
                    incident_uuid,
                    report_status="no-contact",
                    report_detail=detail,
                    next_report_after_epoch=next_epoch,
                )
                self.db.record_report_attempt(
                    incident_uuid,
                    [],
                    "no-contact",
                    detail,
                    test_mode=bool(reporting.get("test_mode")),
                )
                continue

            recipient_gate = self.report_recipient_gate(recipients)
            if recipient_gate is not None:
                status, detail, next_epoch = recipient_gate
                self.db.update_incident(
                    incident_uuid,
                    report_status=status,
                    report_detail=detail,
                    report_recipient=", ".join(recipients),
                    next_report_after_epoch=next_epoch,
                )
                self.db.record_report_attempt(
                    incident_uuid,
                    recipients,
                    status,
                    detail,
                    test_mode=bool(reporting.get("test_mode")),
                )
                continue

            status, detail, message_id = self.send_abuse_report(
                incident,
                enrichment,
                recipients,
            )
            now_epoch = int(utc_now().timestamp())
            update: dict[str, Any] = {
                "report_status": status,
                "report_detail": detail,
                "report_recipient": ", ".join(recipients),
                "report_message_id": message_id,
            }
            if status == "sent":
                update["report_sent_epoch"] = now_epoch
                update["next_report_after_epoch"] = 0
            elif status == "failed":
                update["next_report_after_epoch"] = self.report_retry_epoch(now_epoch)
            else:
                update["next_report_after_epoch"] = 0
            self.db.update_incident(incident_uuid, **update)
            self.db.record_report_attempt(
                incident_uuid,
                recipients,
                status,
                detail,
                test_mode=bool(reporting.get("test_mode")),
                message_id=message_id,
                attempted_epoch=now_epoch,
            )

    def report_time_gate(self, incident: sqlite3.Row) -> tuple[str, str] | None:
        settings = self.config["abuse_reporting"]
        now_epoch = int(utc_now().timestamp())
        maximum_age = int(settings["max_report_age_hours"]) * 3600
        age = now_epoch - int(incident["last_seen_epoch"])
        if age > maximum_age:
            return (
                "suppressed",
                f"Incident is older than max_report_age_hours={settings['max_report_age_hours']}",
            )
        cutoff = str(settings.get("report_not_before_utc", "")).strip()
        if cutoff:
            cutoff_epoch = int(parse_time(cutoff).timestamp())
            if int(incident["last_seen_epoch"]) < cutoff_epoch:
                return (
                    "suppressed",
                    f"Incident predates report_not_before_utc={utc_text(parse_time(cutoff))}",
                )
        return None

    def report_recipients(self, enrichment: Mapping[str, Any]) -> list[str]:
        settings = self.config["abuse_reporting"]
        if settings.get("test_mode"):
            candidates = [str(settings.get("recipient_override", ""))]
        else:
            candidates = [str(item) for item in enrichment.get("abuse_emails", [])]
        return sorted({item.strip().lower() for item in candidates if valid_email_header(item)})

    def report_recipient_gate(self, recipients: Sequence[str]) -> tuple[str, str, int] | None:
        settings = self.config["abuse_reporting"]
        now_epoch = int(utc_now().timestamp())
        cooldown_seconds = int(settings["recipient_cooldown_minutes"]) * 60
        daily_limit = int(settings["max_reports_per_recipient_per_day"])
        day_start = now_epoch - 86400
        blocked_until = 0
        reasons: list[str] = []
        test_mode = bool(settings.get("test_mode"))
        for recipient in recipients:
            count, last_epoch, oldest_epoch = self.db.recipient_report_stats(
                recipient,
                test_mode=test_mode,
                since_epoch=day_start,
            )
            if cooldown_seconds and last_epoch is not None and last_epoch + cooldown_seconds > now_epoch:
                blocked_until = max(blocked_until, last_epoch + cooldown_seconds)
                reasons.append(f"cooldown active for {recipient}")
            if count >= daily_limit:
                daily_reset = (oldest_epoch or now_epoch) + 86400
                blocked_until = max(blocked_until, daily_reset)
                reasons.append(f"rolling 24-hour limit reached for {recipient}")
        if reasons:
            return "deferred", "; ".join(sorted(set(reasons))), blocked_until
        return None

    def report_retry_epoch(self, now_epoch: int | None = None) -> int:
        current = int(now_epoch if now_epoch is not None else utc_now().timestamp())
        return current + int(self.config["abuse_reporting"]["retry_backoff_minutes"]) * 60

    def trusted_ip(self, source_ip: str) -> bool:
        address = ipaddress.ip_address(source_ip)
        return any(address in network for network in self.trusted)

    def source_protection_status(self, source_ip: str) -> tuple[str, str]:
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return "protected", "Malformed source IP"
        if self.trusted_ip(source_ip):
            return "protected", "Address matches collector trusted_cidrs"
        if not address.is_global:
            return "protected", "Address is not globally routable"

        settings = self.config["crowdsec"]
        cscli = str(settings["cscli_path"])
        timeout = int(settings["command_timeout_seconds"])
        try:
            check = subprocess.run(
                [cscli, "allowlists", "check", source_ip],
                text=True, capture_output=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "error", f"Could not verify CrowdSec allowlist: {exc}"
        combined = (check.stdout + "\n" + check.stderr).lower()
        if "is allowlisted" in combined:
            return "protected", "CrowdSec reports address is allowlisted"
        if check.returncode not in (0, 1):
            detail = clean_optional(f"Allowlist check failed: {combined}", 1000) or "Allowlist check failed"
            return "error", detail
        return "unprotected", "Address is not allowlisted"

    def apply_decision(self, incident: sqlite3.Row) -> tuple[str, str]:
        source_ip = str(incident["source_ip"])
        settings = self.config["crowdsec"]
        if not settings.get("enabled"):
            return "dry-run", "CrowdSec enforcement disabled in configuration"
        maximum_age = int(self.config["policy"]["max_enforcement_age_days"]) * 86400
        if int(utc_now().timestamp()) - int(incident["last_seen_epoch"]) > maximum_age:
            return "stale", "Incident is older than the configured enforcement window"
        protection, protection_detail = self.source_protection_status(source_ip)
        if protection == "protected":
            return "refused", protection_detail
        if protection == "error":
            return "failed", protection_detail
        cscli = str(settings["cscli_path"])
        timeout = int(settings["command_timeout_seconds"])
        reason_prefix = str(self.config["policy"]["reason_prefix"]).rstrip("/")
        reason = f"{reason_prefix}/{incident['rule_id']}"
        command = [
            cscli, "decisions", "add", "--ip", source_ip,
            "--duration", str(self.config["policy"]["ban_duration"]),
            "--reason", reason,
        ]
        try:
            result = subprocess.run(
                command, text=True, capture_output=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "failed", f"CrowdSec decision command failed: {exc}"
        output = clean_optional((result.stdout + "\n" + result.stderr).strip(), 1500) or ""
        if result.returncode == 0:
            return "applied", output or "CrowdSec decision added"
        if "already" in output.lower() or "existing" in output.lower():
            return "existing", output
        return "failed", output or f"cscli exited {result.returncode}"

    def enrich(self, source_ip: str) -> dict[str, Any]:
        settings = self.config["enrichment"]
        if not settings.get("enabled"):
            return {"abuse_emails": [], "network_class": "unknown"}
        if source_ip in self._enrichment_results:
            return dict(self._enrichment_results[source_ip])
        if source_ip in self._enrichment_errors:
            raise CollectorError(self._enrichment_errors[source_ip])
        cached = self.db.cache_get(source_ip, int(utc_now().timestamp()))
        if cached is not None:
            result = {
                "network_cidr": cached["network_cidr"],
                "network_name": cached["network_name"],
                "asn": cached["asn"],
                "asn_holder": cached["asn_holder"],
                "abuse_emails": json.loads(cached["abuse_emails_json"]),
            }
            result["network_class"] = self.network_class(result.get("asn"))
            self._enrichment_results[source_ip] = dict(result)
            return result
        try:
            rdap_token = urllib.parse.quote(source_ip, safe=":")
            ripe_token = urllib.parse.quote(source_ip, safe="")
            rdap = self.fetch_json(str(settings["rdap_url"]).format(ip=rdap_token))
            ripe = self.fetch_json(
                str(settings["ripe_prefix_url"]).format(ip=ripe_token),
                optional=True,
            )
            abuse_emails = sorted(extract_abuse_emails(rdap))
            network_cidr = rdap_network(rdap) or ripe_value(ripe, "prefix") or candidate_network(source_ip)
            asn, asn_holder = ripe_asn_details(ripe)
            data = {
                "network_cidr": network_cidr,
                "network_name": clean_optional(rdap.get("name") or rdap.get("handle"), 255),
                "asn": asn,
                "asn_holder": clean_optional(asn_holder, 255),
                "abuse_emails": abuse_emails,
                "raw": {"rdap": rdap, "ripe": ripe},
            }
            data["network_class"] = self.network_class(asn)
            self.db.cache_put(source_ip, data, int(settings["cache_days"]))
            self._enrichment_results[source_ip] = dict(data)
            return data
        except Exception as exc:
            message = str(exc)
            self._enrichment_errors[source_ip] = message
            if isinstance(exc, CollectorError):
                raise
            raise CollectorError(message) from exc

    def network_class(self, asn: int | None) -> str:
        if asn is None:
            return "unknown"
        mapping = self.config["enrichment"].get("asn_classifications", {})
        value = str(mapping.get(str(asn), "unknown")).lower()
        return value if value in {"hosting", "retail", "mobile", "institutional", "unknown"} else "unknown"

    def fetch_json(self, url: str, optional: bool = False) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": str(self.config["enrichment"]["user_agent"])},
        )
        try:
            with urllib.request.urlopen(request, timeout=int(self.config["enrichment"]["timeout_seconds"])) as response:
                data = response.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024:
                    raise CollectorError("Enrichment response exceeded size limit")
                decoded = json.loads(data.decode("utf-8"))
                return decoded if isinstance(decoded, dict) else {}
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            socket.timeout,
            TimeoutError,
            ConnectionError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            if optional:
                return {}
            raise CollectorError(f"Enrichment request failed: {exc}") from exc

    def send_abuse_report(
        self,
        incident: sqlite3.Row,
        enrichment: Mapping[str, Any],
        recipients: Sequence[str],
    ) -> tuple[str, str, str | None]:
        settings = self.config["abuse_reporting"]
        if not settings.get("enabled"):
            return "disabled", "Abuse reporting disabled in configuration", None
        if not recipients:
            return "no-contact", "No valid abuse-report recipient was supplied", None
        protection, protection_detail = self.source_protection_status(str(incident["source_ip"]))
        if protection == "protected":
            return "suppressed", protection_detail, None
        if protection == "error":
            return "failed", f"Abuse report withheld: {protection_detail}", None

        evidence = self.db.incident_evidence(str(incident["incident_uuid"]))
        sites = self.db.incident_sites(str(incident["incident_uuid"]))
        message = EmailMessage()
        message["From"] = str(settings["from"])
        message["To"] = ", ".join(recipients)
        if str(settings.get("admin_copy", "")).strip():
            message["Bcc"] = str(settings["admin_copy"]).strip()
        generated = utc_now()
        message["Date"] = email.utils.format_datetime(generated)
        message_id = email.utils.make_msgid(domain=str(settings["message_id_domain"]))
        message["Message-ID"] = message_id
        test_label = " TEST" if settings.get("test_mode") else ""
        message["Subject"] = (
            f"{settings['subject_prefix']}{test_label} Automated WordPress credential spraying "
            f"from {incident['source_ip']}"
        )
        max_ids = int(settings["max_evidence_uuids"])
        event_ids = [str(row["event_uuid"]) for row in evidence[:max_ids]]
        agents: list[str] = []
        for row in evidence:
            agent = clean_optional(row["user_agent"], 180)
            if agent and agent not in agents:
                agents.append(agent)
            if len(agents) >= 2:
                break
        network_name = clean_optional(enrichment.get("network_name"), 255) or "unknown"
        body = [
            "This is an automated abuse report from a self-hosted server operator.",
            "",
            f"Report generated: {utc_text(generated)}",
            f"Source IP: {incident['source_ip']}",
            "Activity: Automated WordPress credential spraying",
            f"UTC interval: {incident['first_seen']} to {incident['last_seen']}",
            f"Failed attempts: {incident['event_count']}",
            f"Distinct targeted accounts: {incident['distinct_accounts']}",
            f"Affected WordPress sites: {incident['site_count']}",
            f"Affected site IDs: {', '.join(sites) if sites else 'unknown'}",
            f"Candidate aggregation CIDR: {incident['network_cidr'] or 'unknown'}",
            f"Registered network: {incident['registered_cidr'] or 'unknown'}",
            f"Network name: {network_name}",
            f"ASN: {incident['asn'] or 'unknown'} {incident['asn_holder'] or ''}".rstrip(),
            f"Action taken: CrowdSec decision status {incident['decision_status']}; configured duration {self.config['policy']['ban_duration']}",
            f"Incident UUID: {incident['incident_uuid']}",
        ]
        operator_contact = clean_optional(settings.get("operator_contact"), 254)
        if operator_contact:
            body.append(f"Operator contact: {operator_contact}")
        if settings.get("test_mode"):
            body.extend([
                "Test mode: enabled",
                "Provider recipient overridden; this message was not sent to the RDAP abuse contact.",
            ])
        body.extend([
            "",
            "Evidence event UUIDs:",
            *[f"  - {event_id}" for event_id in event_ids],
        ])
        if agents:
            body.extend(["", "Sanitized user-agent examples:", *[f"  - {agent}" for agent in agents]])
        body.extend([
            "",
            "No passwords, cookies, email addresses, or targeted usernames are included in this report.",
            "Please investigate the responsible host and take appropriate action.",
        ])
        message.set_content("\n".join(body) + "\n")
        sendmail = str(settings["sendmail_path"])
        try:
            result = subprocess.run(
                [sendmail, "-t", "-oi"],
                input=message.as_bytes(),
                capture_output=True,
                timeout=int(settings["send_timeout_seconds"]),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "failed", f"sendmail failed: {exc}", message_id
        if result.returncode != 0:
            detail = (
                clean_optional(result.stderr.decode("utf-8", "replace"), 1000)
                or f"sendmail exited {result.returncode}"
            )
            return "failed", detail, message_id
        return "sent", f"Report sent to {', '.join(recipients)}", message_id


def stat_is_regular(mode: int) -> bool:
    return stat.S_ISREG(mode)


def ripe_value(payload: Mapping[str, Any], key: str) -> Any:
    data = payload.get("data")
    return data.get(key) if isinstance(data, dict) else None


def ripe_asn_details(payload: Mapping[str, Any]) -> tuple[int | None, str | None]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return None, None
    holder = clean_optional(data.get("holder"), 255)
    values = data.get("asns")
    candidates = values if isinstance(values, list) else [values]
    for item in candidates:
        if isinstance(item, dict):
            raw_asn = item.get("asn", item.get("number"))
            item_holder = clean_optional(item.get("holder"), 255) or holder
        else:
            raw_asn = item
            item_holder = holder
        if raw_asn in (None, ""):
            continue
        try:
            return int(raw_asn), item_holder
        except (TypeError, ValueError):
            continue
    return None, holder


def rdap_network(payload: Mapping[str, Any]) -> str | None:
    start = payload.get("startAddress")
    end = payload.get("endAddress")
    if not isinstance(start, str) or not isinstance(end, str):
        return None
    try:
        networks = list(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
    except ValueError:
        return None
    return str(networks[0]) if len(networks) == 1 else None


def extract_abuse_emails(payload: Mapping[str, Any]) -> set[str]:
    found: set[str] = set()
    visited: set[int] = set()

    def walk(value: Any, inherited_abuse: bool = False) -> None:
        if isinstance(value, dict):
            identity = id(value)
            if identity in visited:
                return
            visited.add(identity)
            roles = value.get("roles")
            is_abuse = inherited_abuse or (
                isinstance(roles, list) and any(str(role).lower() == "abuse" for role in roles)
            )
            vcard = value.get("vcardArray")
            if is_abuse and isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and str(field[0]).lower() == "email":
                        address = str(field[3]).strip().lower()
                        if "@" in address and len(address) <= 254:
                            found.add(address)
            for child in value.values():
                walk(child, is_abuse)
        elif isinstance(value, list):
            for child in value:
                walk(child, inherited_abuse)

    walk(payload)
    return found


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def status_output(collector: Collector) -> dict[str, Any]:
    return {
        "counts": collector.db.counts(),
        "crowdsec_enabled": bool(collector.config["crowdsec"]["enabled"]),
        "abuse_reporting_enabled": bool(collector.config["abuse_reporting"]["enabled"]),
        "abuse_reporting_guardrails": {
            key: collector.config["abuse_reporting"][key]
            for key in (
                "test_mode",
                "max_reports_per_run",
                "max_report_age_hours",
                "recipient_cooldown_minutes",
                "max_reports_per_recipient_per_day",
                "report_not_before_utc",
                "retry_backoff_minutes",
            )
        },
        "policy": collector.config["policy"],
        "recent_incidents": [dict(row) for row in collector.db.recent_incidents(20)],
        "recent_report_attempts": [dict(row) for row in collector.db.recent_report_attempts(20)],
        "network_candidates": collector.db.network_candidates(collector.config["policy"]),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argent Sentinel host collector")
    parser.add_argument("--config", default="/etc/argent-sentinel/collector.json")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Import batches, evaluate policy, and retry actions")
    sub.add_parser("status", help="Print collector state and CIDR candidates")
    sub.add_parser("validate-config", help="Validate configuration and exit")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok"}, indent=2))
            return 0
        if args.command == "status":
            collector = Collector(config)
            try:
                print(json.dumps(status_output(collector), indent=2, sort_keys=True))
            finally:
                collector.close()
            return 0
        lock_path = Path(config["lock_file"])
        with process_lock(lock_path):
            collector = Collector(config)
            try:
                collector.run()
                print(json.dumps(status_output(collector), indent=2, sort_keys=True))
            finally:
                collector.close()
        return 0
    except CollectorError as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
