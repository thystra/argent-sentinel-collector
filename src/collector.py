#!/usr/bin/env python3
"""Argent Sentinel host collector.

Imports immutable WordPress and OpenSSH event batches, deduplicates events,
correlates credential-spray and SSH brute-force incidents, imports Nginx
abuse-context observations, correlates network tuples, and optionally submits
CrowdSec decisions and sanitized abuse reports.
"""

from __future__ import annotations

import argparse
import base64
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
import re
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
APP_VERSION = "0.5.3.0"
SCHEMA_VERSION = 8

DEFAULTS: dict[str, Any] = {
    "state_db": "/var/lib/argent-sentinel/collector/state.sqlite3",
    "node": {
        "id": "nidhoggur",
        "fqdn": "nidhoggur.argentwolf.org",
        "central_url": "https://sentinel.argentwolf.org/",
    },
    "lock_file": "/run/argent-sentinel/collector.lock",
    "incoming_globs": [
        "/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json",
        "/var/lib/argent-sentinel/drop/remote/*/events/incoming/*.json",
    ],
    "processing_dir": "/var/lib/argent-sentinel/collector/processing",
    "archive_dir": "/var/lib/argent-sentinel/collector/archive",
    "rejected_dir": "/var/lib/argent-sentinel/collector/rejected",
    "max_batch_bytes": 20 * 1024 * 1024,
    "abuse_context": {
        "enabled": False,
        "incoming_globs": [
            "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.jsonl",
            "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.json",
            "/var/lib/argent-sentinel/drop/remote/*/abuse-context/incoming/*.jsonl",
            "/var/lib/argent-sentinel/drop/remote/*/abuse-context/incoming/*.json",
        ],
        "processing_dir": "/var/lib/argent-sentinel/collector/abuse-context-processing",
        "archive_dir": "/var/lib/argent-sentinel/collector/abuse-context-archive",
        "rejected_dir": "/var/lib/argent-sentinel/collector/abuse-context-rejected",
        "max_file_bytes": 20 * 1024 * 1024,
        "max_line_bytes": 64 * 1024,
        "fallback_correlation_seconds": 2,
    },
    "network_reporting": {
        "enabled": True,
        "include_context_min_hostile_ips": 2,
        "max_tuple_evidence": 20,
        "automatic_cidr_blocking": False,
        "automatic_network_email": False,
    },
    "sshd_policy": {
        "enabled": True,
        "window_seconds": 3600,
        "failure_threshold": 1,
        "distinct_accounts": 1,
        "single_account_threshold": 1,
        "incident_merge_seconds": 86400,
    },
    "web_policy": {
        "enabled": True,
        "window_seconds": 600,
        "suspicious_threshold": 3,
        "distinct_targets": 1,
        "high_volume_threshold": 100,
        "high_volume_distinct_targets": 25,
        "incident_merge_seconds": 86400,
        "immediate_statuses": [444],
        "review_statuses": [429],
        "policy_denied_user_agents": ["meta-externalagent"],
    },
    "persistent_wordpress_policy": {
        "enabled": True,
        "window_seconds": 86400,
        "failure_threshold": 6,
        "distinct_accounts": 2,
        "single_account_threshold": 12,
        "incident_merge_seconds": 86400,
        "abuse_reporting_enabled": False,
    },
    "legacy_reporting": {
        "marker_state_dir": "/var/lib/nginx-abuse-drafts",
        "suppress_matching_markers": True,
    },
    "trusted_cidrs": ["127.0.0.0/8", "::1/128", "192.168.0.0/16"],
    "policy": {
        "window_seconds": 900,
        "failure_threshold": 5,
        "distinct_accounts": 2,
        "single_account_threshold": 10,
        "incident_merge_seconds": 86400,
        "max_enforcement_age_days": 7,
        "ban_duration": "720h",
        "reason_prefix": "argent-sentinel",
        "network_review_window_days": 7,
        "network_review_distinct_ips": 3,
        "network_escalation_distinct_ips": 5,
        "network_escalation_active_days": 3,
        "network_long_block_distinct_ips": 16,
        "network_long_block_incidents": 20,
        "network_long_block_active_days": 1,
        "network_long_block_days": 180,
        "network_severe_block_distinct_ips": 48,
        "network_severe_block_incidents": 48,
        "network_severe_block_days": 365,
        "network_block_min_ipv4_prefix_length": 24,
        "network_block_min_ipv6_prefix_length": 48,
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
        "user_agent": f"Argent-Sentinel/{APP_VERSION} (+self-hosted security abuse reporting)",
        "asn_classifications": {},
    },
    "report_batching": {
        "enabled": False,
        "state_file": "/var/lib/argent-sentinel/collector/report-batch-state.json",
        "grouping": {
            "minimum_ipv4_prefix_length": 24,
            "minimum_ipv6_prefix_length": 48,
        },
        "grace_minutes": 5,
        "max_candidate_incidents": 1000,
        "max_incidents_per_message": 50,
        "max_messages_per_run": 10,
        "ban_only": {
            "asns": [32934],
            "cidrs": ["2a03:2880::/32"],
            "user_agent_tokens": ["meta-externalagent"],
            "allow_user_agent_only": False,
        },
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
        "attach_xarf": True,
        "xarf_version": "4.2.0",
        "xarf_max_evidence_lines": 20,
        "resolve_target_dns": True,
        "resolve_source_rdns": True,
        "public_target_ips": [],
        "reporter_org": "",
        "reporter_org_domain": "",
        "reporter_contact_name": "",
    },
}


WEB_PROBE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("generic-root-php-backdoor", re.compile(
        r"^/(?:3PJcpMFsD8B|admin|adminfuns|ahax|bless|bolt|buy|classwithtostring|css|database|edit|file|filemanager|files|fm|goods|info|item|log|m|mah|mini|radio|root|simple|system|system_log|t|user|worksec|wp|wp-admin|wp-content|wp-file|wp-wlx|x|666|1|222|404|about|ab)\.php(?:\?|$)",
        re.IGNORECASE,
    )),
    ("wp-special-sensitive-php", re.compile(
        r"^/(?:wp-config-sample\.php|wp-content/plugins/hello\.php|wp-admin/includes/admin\.php)(?:\?|$)", re.IGNORECASE,
    )),
    ("wp-content-php-probe", re.compile(
        r"^/wp-content/(?:uploads|plugins|themes)/[^?\s]*\.php(?:\?|$)", re.IGNORECASE,
    )),
    ("wp-includes-php-probe", re.compile(r"^/wp-includes/[^?\s]*\.php(?:\?|$)", re.IGNORECASE)),
    ("wp-json-command-probe", re.compile(
        r"^/wp-json/wp/v2/posts[^?\s]*(?:\?.*)?(?:cmd=|exec=|system=|shell=|passthru=)", re.IGNORECASE,
    )),
    ("sensitive-file-probe", re.compile(
        r"(?:^|/)(?:\.env|\.git/config|\.git/HEAD|wp-config\.php|wp-config\.php\.bak|phpinfo\.php|server-status)(?:\?|$|/)", re.IGNORECASE,
    )),
    ("path-traversal-probe", re.compile(
        r"(?:\.\./|%2e%2e|%252e%252e|/etc/passwd|/proc/self/environ)", re.IGNORECASE,
    )),
    ("cgi-shell-probe", re.compile(
        r"^/cgi-bin/.*(?:/bin/sh|/bin/bash|cmd=|login\.cgi|upload\.php)", re.IGNORECASE,
    )),
)
SEARCH_BOT_UA_RE = re.compile(
    r"(?:Googlebot|bingbot|DuckDuckBot|Applebot|Slurp|YandexBot|Baiduspider)", re.IGNORECASE
)
NEXTCLOUD_CLIENT_UA_RE = re.compile(r"(?:Nextcloud|NextcloudTalk|mirall)", re.IGNORECASE)
NEXTCLOUD_DAV_METHODS = {"PUT", "MKCOL", "PROPFIND", "PROPPATCH", "MOVE", "COPY", "DELETE", "LOCK", "UNLOCK"}


def web_probe_category(path: str) -> str | None:
    for name, pattern in WEB_PROBE_PATTERNS:
        if pattern.search(path):
            return name
    return None


def is_authenticated_nextcloud_dav(raw: Mapping[str, Any], path: str, method: str, user_agent: str) -> bool:
    remote_user = str(first_value(raw, "remote_user", "authenticated_user") or "").strip()
    return bool(
        remote_user and remote_user != "-"
        and path.startswith("/remote.php/dav/files/")
        and method.upper() in NEXTCLOUD_DAV_METHODS
        and NEXTCLOUD_CLIENT_UA_RE.search(user_agent)
    )


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
        "network_long_block_distinct_ips",
        "network_long_block_incidents",
        "network_long_block_active_days",
        "network_long_block_days",
        "network_severe_block_distinct_ips",
        "network_severe_block_incidents",
        "network_severe_block_days",
        "network_block_min_ipv4_prefix_length",
        "network_block_min_ipv6_prefix_length",
    ):
        if int(policy[name]) < 1:
            raise CollectorError(f"policy.{name} must be positive")
    for name, maximum in (
        ("network_block_min_ipv4_prefix_length", 32),
        ("network_block_min_ipv6_prefix_length", 128),
    ):
        value = int(policy[name])
        if value > maximum:
            raise CollectorError(
                f"policy.{name} must be between 1 and {maximum}"
            )
    if not str(policy.get("ban_duration", "")).strip():
        raise CollectorError("policy.ban_duration is required")
    if not str(policy.get("reason_prefix", "")).strip():
        raise CollectorError("policy.reason_prefix is required")
    for cidr in config.get("trusted_cidrs", []):
        ipaddress.ip_network(str(cidr), strict=False)
    node = config.get("node", {})
    if not str(node.get("id", "")).strip():
        raise CollectorError("node.id is required")
    central_url = str(node.get("central_url", "")).strip()
    if central_url and urllib.parse.urlparse(central_url).scheme != "https":
        raise CollectorError("node.central_url must use https")
    context = config.get("abuse_context", {})
    for name in ("max_file_bytes", "max_line_bytes", "fallback_correlation_seconds"):
        if int(context.get(name, 0)) < 1:
            raise CollectorError(f"abuse_context.{name} must be positive")
    network_reporting = config.get("network_reporting", {})
    for name in ("include_context_min_hostile_ips", "max_tuple_evidence"):
        if int(network_reporting.get(name, 0)) < 1:
            raise CollectorError(f"network_reporting.{name} must be positive")
    if network_reporting.get("automatic_cidr_blocking"):
        raise CollectorError(
            "network_reporting.automatic_cidr_blocking remains disabled; "
            "0.5.3.0 supports only audited operator-initiated CIDR decisions"
        )
    sshd_policy = config.get("sshd_policy", {})
    for name in (
        "window_seconds", "failure_threshold", "distinct_accounts",
        "single_account_threshold", "incident_merge_seconds",
    ):
        if int(sshd_policy.get(name, 0)) < 1:
            raise CollectorError(f"sshd_policy.{name} must be positive")
    web_policy = config.get("web_policy", {})
    for name in (
        "window_seconds", "suspicious_threshold", "distinct_targets",
        "high_volume_threshold", "high_volume_distinct_targets", "incident_merge_seconds",
    ):
        if int(web_policy.get(name, 0)) < 1:
            raise CollectorError(f"web_policy.{name} must be positive")
    persistent_wordpress = config.get("persistent_wordpress_policy", {})
    for name in (
        "window_seconds",
        "failure_threshold",
        "distinct_accounts",
        "single_account_threshold",
        "incident_merge_seconds",
    ):
        if int(persistent_wordpress.get(name, 0)) < 1:
            raise CollectorError(
                f"persistent_wordpress_policy.{name} must be positive"
            )
    for name in ("enabled", "abuse_reporting_enabled"):
        if not isinstance(persistent_wordpress.get(name), bool):
            raise CollectorError(
                f"persistent_wordpress_policy.{name} must be boolean"
            )
    batching = config["report_batching"]
    if not isinstance(batching.get("enabled"), bool):
        raise CollectorError(
            "report_batching.enabled must be boolean"
        )
    for name in (
        "grace_minutes",
        "max_candidate_incidents",
        "max_incidents_per_message",
        "max_messages_per_run",
    ):
        if int(batching.get(name, 0)) < 1:
            raise CollectorError(
                f"report_batching.{name} must be positive"
            )
    state_file = str(batching.get("state_file", "")).strip()
    if not state_file:
        raise CollectorError(
            "report_batching.state_file is required"
        )
    grouping = batching.get("grouping", {})
    for name, maximum in (
        ("minimum_ipv4_prefix_length", 32),
        ("minimum_ipv6_prefix_length", 128),
    ):
        try:
            value = int(grouping.get(name, -1))
        except (TypeError, ValueError) as exc:
            raise CollectorError(
                f"report_batching.grouping.{name} must be an integer"
            ) from exc
        if value < 0 or value > maximum:
            raise CollectorError(
                f"report_batching.grouping.{name} must be between 0 "
                f"and {maximum}"
            )
    ban_only = batching.get("ban_only", {})
    for name in (
        "asns",
        "cidrs",
        "user_agent_tokens",
    ):
        if not isinstance(ban_only.get(name, []), list):
            raise CollectorError(
                f"report_batching.ban_only.{name} must be a list"
            )
    if not isinstance(
        ban_only.get("allow_user_agent_only", False),
        bool,
    ):
        raise CollectorError(
            "report_batching.ban_only.allow_user_agent_only "
            "must be boolean"
        )
    for value in ban_only.get("asns", []):
        if int(value) < 1:
            raise CollectorError(
                "report_batching.ban_only.asns values "
                "must be positive"
            )
    for value in ban_only.get("cidrs", []):
        ipaddress.ip_network(str(value), strict=False)

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
    if str(reporting.get("xarf_version", "4.2.0")) != "4.2.0":
        raise CollectorError(
            "abuse_reporting.xarf_version must be '4.2.0'"
        )
    if int(reporting.get("xarf_max_evidence_lines", 0)) < 1:
        raise CollectorError("abuse_reporting.xarf_max_evidence_lines must be positive")
    public_targets = reporting.get("public_target_ips", [])
    if not isinstance(public_targets, (list, Mapping)):
        raise CollectorError("abuse_reporting.public_target_ips must be a list or object")
    target_values: list[Any] = []
    if isinstance(public_targets, Mapping):
        for key, values in public_targets.items():
            if not isinstance(key, str) or not isinstance(values, list):
                raise CollectorError(
                    "abuse_reporting.public_target_ips object values must be lists"
                )
            target_values.extend(values)
    else:
        target_values.extend(public_targets)
    for value in target_values:
        try:
            ipaddress.ip_address(str(value))
        except ValueError as exc:
            raise CollectorError(
                f"abuse_reporting.public_target_ips contains invalid address: {value!r}"
            ) from exc
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


def backup_sqlite_database(source: Path, backup_dir: Path) -> Path | None:
    """Create a consistent SQLite backup before an in-place schema migration."""
    if not source.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    destination = backup_dir / source.name
    source_conn = sqlite3.connect(source)
    destination_conn = sqlite3.connect(destination)
    try:
        source_conn.execute("PRAGMA busy_timeout = 5000")
        source_conn.backup(destination_conn)
        destination_conn.commit()
    finally:
        destination_conn.close()
        source_conn.close()
    os.chmod(destination, 0o600)
    return destination


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
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
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
                service TEXT NOT NULL DEFAULT 'wordpress',
                event_type TEXT NOT NULL,
                outcome TEXT NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                transport_protocol TEXT,
                application_protocol TEXT,
                account_key TEXT,
                user_agent TEXT,
                request_method TEXT,
                request_path TEXT,
                request_id TEXT,
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
                site_id TEXT,
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
            CREATE INDEX IF NOT EXISTS incidents_registered_network_time
                ON incidents(registered_cidr, last_seen_epoch);
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
            CREATE TABLE IF NOT EXISTS observation_files (
                file_uuid TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL UNIQUE,
                source_host TEXT NOT NULL,
                original_path TEXT NOT NULL,
                archived_path TEXT,
                imported_at TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS network_observations (
                observation_uuid TEXT PRIMARY KEY,
                file_uuid TEXT NOT NULL REFERENCES observation_files(file_uuid),
                occurred_epoch INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                source_host TEXT NOT NULL,
                request_id TEXT,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                transport_protocol TEXT,
                application_protocol TEXT,
                tls_protocol TEXT,
                host TEXT,
                server_name TEXT,
                request_method TEXT,
                request_uri TEXT,
                http_status INTEGER,
                user_agent TEXT,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS observations_request_id
                ON network_observations(request_id, source_ip);
            CREATE INDEX IF NOT EXISTS observations_ip_time
                ON network_observations(source_ip, occurred_epoch);
            CREATE TABLE IF NOT EXISTS incident_network_observations (
                incident_uuid TEXT NOT NULL REFERENCES incidents(incident_uuid),
                observation_uuid TEXT NOT NULL REFERENCES network_observations(observation_uuid),
                correlation_method TEXT NOT NULL,
                correlated_at TEXT NOT NULL,
                PRIMARY KEY (incident_uuid, observation_uuid)
            );
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
            );
            CREATE TABLE IF NOT EXISTS network_case_incidents (
                network_cidr TEXT NOT NULL REFERENCES network_cases(network_cidr),
                incident_uuid TEXT NOT NULL REFERENCES incidents(incident_uuid),
                PRIMARY KEY (network_cidr, incident_uuid)
            );
            CREATE TABLE IF NOT EXISTS network_case_reports (
                report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_cidr TEXT NOT NULL REFERENCES network_cases(network_cidr),
                report_type TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                status TEXT NOT NULL,
                recipient TEXT,
                detail TEXT,
                message_id TEXT
            );
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
            CREATE TABLE IF NOT EXISTS legacy_reports (
                marker_key TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                report_date TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                marker_path TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS legacy_reports_ip_date
                ON legacy_reports(source_ip, report_date);
            """
        )
        self.ensure_column("events", "service", "TEXT NOT NULL DEFAULT 'wordpress'")
        self.ensure_column("events", "source_port", "INTEGER")
        self.ensure_column("events", "destination_ip", "TEXT")
        self.ensure_column("events", "destination_port", "INTEGER")
        self.ensure_column("events", "transport_protocol", "TEXT")
        self.ensure_column("events", "application_protocol", "TEXT")
        self.ensure_column("events", "request_method", "TEXT")
        self.ensure_column("events", "request_id", "TEXT")
        self.ensure_column("incidents", "site_id", "TEXT")
        self.ensure_column("incidents", "registered_cidr", "TEXT")
        self.ensure_column("incidents", "next_report_after_epoch", "INTEGER NOT NULL DEFAULT 0")
        self.ensure_column("incidents", "report_sent_epoch", "INTEGER")
        self.ensure_column("incidents", "report_recipient", "TEXT")
        self.ensure_column("incidents", "report_message_id", "TEXT")
        self.ensure_column("incidents", "review_status", "TEXT NOT NULL DEFAULT 'open'")
        self.ensure_column("incidents", "review_disposition", "TEXT")
        self.ensure_column("incidents", "review_note", "TEXT")
        self.ensure_column("incidents", "review_updated_epoch", "INTEGER")
        self.ensure_column("incidents", "review_updated_at", "TEXT")
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS incidents_ip_rule_site_time
               ON incidents(source_ip, rule_id, site_id, last_seen_epoch)"""
        )
        self.ensure_column(
            "network_cases", "suggested_block_days",
            "INTEGER NOT NULL DEFAULT 0",
        )
        self.ensure_column(
            "network_cases", "grouping_basis",
            "TEXT NOT NULL DEFAULT 'fallback'",
        )
        self.ensure_column("network_cases", "asns", "TEXT")
        self.ensure_column("network_cases", "network_classes", "TEXT")
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
            self.ensure_column("network_cases", name, definition)
        self.conn.execute(
            """INSERT INTO schema_meta (key, value, updated_at)
               VALUES ('schema_version', ?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (str(SCHEMA_VERSION), utc_text()),
        )
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
                     site_id, source_host, service, event_type, outcome, source_ip,
                     source_port, destination_ip, destination_port, transport_protocol,
                     application_protocol, account_key, user_agent, request_method,
                     request_path, request_id, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event["event_uuid"],
                        batch["batch_uuid"],
                        event["occurred_epoch"],
                        event["occurred_at"],
                        event.get("recorded_at"),
                        source["site_id"],
                        source["host"],
                        source["service"],
                        event["event_type"],
                        event["outcome"],
                        event.get("source_ip"),
                        event.get("source_port"),
                        event.get("destination_ip"),
                        event.get("destination_port"),
                        event.get("transport_protocol"),
                        event.get("application_protocol"),
                        event.get("account_key") or event.get("account_hash"),
                        event.get("user_agent"),
                        event.get("request_method"),
                        event.get("request_path"),
                        event.get("request_id"),
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
                          user_agent, request_method, request_path, request_id
                   FROM events
                   WHERE source_ip = ?
                     AND event_type = 'login_failed'
                     AND outcome = 'denied'
                     AND occurred_epoch BETWEEN ? AND ?
                   ORDER BY occurred_epoch ASC, event_uuid ASC""",
                (source_ip, start_epoch, end_epoch),
            )
        )

    def persistent_wordpress_sources(
        self,
        start_epoch: int,
        end_epoch: int,
    ) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT e.site_id, e.source_ip,
                          COUNT(*) AS failures,
                          COUNT(DISTINCT e.account_key) AS accounts,
                          MAX(e.occurred_epoch) AS last_epoch
                   FROM events e
                   WHERE e.service = 'wordpress'
                     AND e.event_type = 'login_failed'
                     AND e.outcome = 'denied'
                     AND e.source_ip IS NOT NULL
                     AND e.occurred_epoch BETWEEN ? AND ?
                     AND NOT EXISTS (
                         SELECT 1
                         FROM incident_events ie
                         JOIN incidents i
                           ON i.incident_uuid = ie.incident_uuid
                         WHERE ie.event_uuid = e.event_uuid
                           AND i.rule_id IN (
                               'wordpress-credential-spray',
                               'wordpress-single-account-bruteforce'
                           )
                     )
                   GROUP BY e.site_id, e.source_ip
                   ORDER BY e.site_id, e.source_ip""",
                (start_epoch, end_epoch),
            )
        )
    def persistent_login_failures(
        self,
        source_ip: str,
        site_id: str,
        start_epoch: int,
        end_epoch: int,
    ) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT e.event_uuid, e.occurred_epoch, e.occurred_at,
                          e.site_id, e.account_key, e.user_agent,
                          e.request_method, e.request_path, e.request_id
                   FROM events e
                   WHERE e.source_ip = ?
                     AND e.site_id = ?
                     AND e.service = 'wordpress'
                     AND e.event_type = 'login_failed'
                     AND e.outcome = 'denied'
                     AND e.occurred_epoch BETWEEN ? AND ?
                     AND NOT EXISTS (
                         SELECT 1
                         FROM incident_events ie
                         JOIN incidents i
                           ON i.incident_uuid = ie.incident_uuid
                         WHERE ie.event_uuid = e.event_uuid
                           AND i.rule_id IN (
                               'wordpress-credential-spray',
                               'wordpress-single-account-bruteforce'
                           )
                     )
                   ORDER BY e.occurred_epoch ASC, e.event_uuid ASC""",
                (source_ip, site_id, start_epoch, end_epoch),
            )
        )
    def ssh_failures(self, source_ip: str, start_epoch: int, end_epoch: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT event_uuid, occurred_epoch, occurred_at, site_id, account_key,
                          source_port, destination_ip, destination_port,
                          transport_protocol, application_protocol, metadata_json
                   FROM events
                   WHERE source_ip = ?
                     AND service = 'sshd'
                     AND event_type = 'ssh_auth_failed'
                     AND outcome = 'denied'
                     AND occurred_epoch BETWEEN ? AND ?
                   ORDER BY occurred_epoch ASC, event_uuid ASC""",
                (source_ip, start_epoch, end_epoch),
            )
        )

    def web_probe_events(self, source_ip: str, start_epoch: int, end_epoch: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT event_uuid, occurred_epoch, occurred_at, site_id, account_key,
                          source_port, destination_ip, destination_port, transport_protocol,
                          application_protocol, request_method, request_path, request_id,
                          user_agent, metadata_json
                   FROM events
                   WHERE source_ip = ?
                     AND service = 'nginx'
                     AND event_type = 'web_probe'
                     AND outcome = 'denied'
                     AND occurred_epoch BETWEEN ? AND ?
                   ORDER BY occurred_epoch ASC, event_uuid ASC""",
                (source_ip, start_epoch, end_epoch),
            )
        )

    def materialize_web_probe_events(
        self,
        file_uuid: str,
        source_host: str,
        observations: Sequence[Mapping[str, Any]],
        policy: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        if not policy.get("enabled"):
            return []
        by_ip: dict[str, list[Mapping[str, Any]]] = {}
        for item in observations:
            by_ip.setdefault(str(item["source_ip"]), []).append(item)
        selected: list[tuple[Mapping[str, Any], str]] = []
        policy_denied_user_agents = tuple(
            str(value).strip().lower()
            for value in policy.get(
                "policy_denied_user_agents",
                ["meta-externalagent"],
            )
            if str(value).strip()
        )
        for source_ip, rows in by_ip.items():
            suspicious: list[tuple[Mapping[str, Any], str]] = []
            error_rows: list[Mapping[str, Any]] = []
            user_agents: dict[str, int] = {}
            targets: set[str] = set()
            for item in rows:
                raw = item.get("raw", {}) if isinstance(item.get("raw"), Mapping) else {}
                path = str(item.get("request_uri") or "")
                method = str(item.get("request_method") or "")
                user_agent = str(item.get("user_agent") or "")
                status = item.get("http_status")
                if is_authenticated_nextcloud_dav(raw, path, method, user_agent):
                    continue
                category = web_probe_category(path)
                if status == 444 and not category:
                    category = "nginx-denied-444"
                if category:
                    suspicious.append((item, category))
                if isinstance(status, int) and 400 <= status <= 599 and status not in {429, 444}:
                    error_rows.append(item)
                    targets.add(path)
                    user_agents[user_agent] = user_agents.get(user_agent, 0) + 1
            selected.extend(suspicious)
            dominant_ua = max(user_agents, key=user_agents.get) if user_agents else ""
            high_volume = (
                len(error_rows) >= int(policy["high_volume_threshold"])
                and len(targets) >= int(policy["high_volume_distinct_targets"])
                and not SEARCH_BOT_UA_RE.search(dominant_ua)
                and not any(
                    token in dominant_ua.lower()
                    for token in policy_denied_user_agents
                )
            )
            if high_volume:
                already = {str(item["observation_uuid"]) for item, _ in suspicious}
                selected.extend(
                    (item, "high-volume-web-scanner")
                    for item in error_rows[:500]
                    if str(item["observation_uuid"]) not in already
                )
        if not selected:
            return []
        batch_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"argent-sentinel:web-observations:{file_uuid}"))
        if self.batch_exists(batch_uuid):
            return []
        site_id = f"nginx-{source_host}"[:255]
        batch = {
            "schema_version": 1,
            "batch_uuid": batch_uuid,
            "created_at": utc_text(),
            "source": {
                "host": source_host,
                "site_id": site_id,
                "site_url": f"https://{source_host}/",
                "service": "nginx",
                "plugin_version": APP_VERSION,
            },
        }
        events: list[dict[str, Any]] = []
        for item, category in selected:
            path = str(item.get("request_uri") or "")
            host = str(item.get("host") or item.get("server_name") or source_host)
            events.append({
                "event_uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"argent-sentinel:web-event:{item['observation_uuid']}")),
                "occurred_epoch": int(item["occurred_epoch"]),
                "occurred_at": str(item["occurred_at"]),
                "recorded_at": utc_text(),
                "event_type": "web_probe",
                "outcome": "denied",
                "source_ip": item.get("source_ip"),
                "source_port": item.get("source_port"),
                "destination_ip": item.get("destination_ip"),
                "destination_port": item.get("destination_port"),
                "transport_protocol": item.get("transport_protocol"),
                "application_protocol": item.get("application_protocol"),
                "account_key": f"{site_id}:probe:{category}",
                "user_agent": item.get("user_agent"),
                "request_method": item.get("request_method"),
                "request_path": path,
                "request_id": item.get("request_id"),
                "metadata": {
                    "probe_category": category,
                    "http_status": item.get("http_status"),
                    "host": host,
                    "observation_uuid": item.get("observation_uuid"),
                },
            })
        digest = hashlib.sha256((file_uuid + "\0web-events").encode()).hexdigest()
        return self.import_batch(batch, digest, Path(f"abuse-context:{file_uuid}"), events)

    def import_legacy_markers(self, state_dir: Path) -> dict[str, int]:
        imported = 0
        skipped = 0
        if not state_dir.exists():
            return {"imported": 0, "skipped": 0}
        for marker in sorted(state_dir.glob("*.sent"), key=str):
            name = marker.name[:-5]
            if len(name) < 12 or name[4:5] != "-" or name[7:8] != "-":
                skipped += 1
                continue
            report_date = name[:10]
            source_text = name[11:]
            try:
                dt.date.fromisoformat(report_date)
                try:
                    source_ip = str(ipaddress.ip_address(source_text))
                except ValueError:
                    # Some legacy report filenames sanitized IPv6 colons as
                    # underscores even though marker files normally retained
                    # the literal address.
                    source_ip = str(ipaddress.ip_address(source_text.replace("_", ":")))
            except (ValueError, TypeError):
                skipped += 1
                continue
            marker_key = hashlib.sha256(f"{report_date}\0{source_ip}".encode()).hexdigest()
            with self.conn:
                cursor = self.conn.execute(
                    """INSERT OR IGNORE INTO legacy_reports
                       (marker_key, source_ip, report_date, imported_at, marker_path)
                       VALUES (?, ?, ?, ?, ?)""",
                    (marker_key, source_ip, report_date, utc_text(), str(marker)),
                )
            imported += int(cursor.rowcount == 1)
        return {"imported": imported, "skipped": skipped}

    def legacy_report_match(self, source_ip: str, first_seen: str) -> sqlite3.Row | None:
        try:
            day = parse_time(first_seen).date()
        except CollectorError:
            return None
        dates = [(day + dt.timedelta(days=offset)).isoformat() for offset in (-1, 0, 1)]
        return self.conn.execute(
            """SELECT * FROM legacy_reports
               WHERE source_ip = ? AND report_date IN (?, ?, ?)
               ORDER BY report_date DESC LIMIT 1""",
            (source_ip, *dates),
        ).fetchone()

    def recent_incident(
        self,
        source_ip: str,
        rule_id: str,
        site_id: str | None = None,
    ) -> sqlite3.Row | None:
        if site_id is None:
            return self.conn.execute(
                """SELECT * FROM incidents
                   WHERE source_ip = ?
                     AND rule_id = ?
                     AND site_id IS NULL
                   ORDER BY last_seen_epoch DESC LIMIT 1""",
                (source_ip, rule_id),
            ).fetchone()
        return self.conn.execute(
            """SELECT * FROM incidents
               WHERE source_ip = ?
                 AND rule_id = ?
                 AND site_id = ?
               ORDER BY last_seen_epoch DESC LIMIT 1""",
            (source_ip, rule_id, site_id),
        ).fetchone()
    def create_or_merge_incident(
        self,
        source_ip: str,
        rule_id: str,
        rows: Sequence[sqlite3.Row],
        merge_seconds: int,
        *,
        site_id: str | None = None,
        initial_report_status: str = "pending",
        initial_report_detail: str | None = None,
    ) -> str:
        if not rows:
            raise CollectorError("Cannot create an incident without evidence")
        first_epoch = min(int(row["occurred_epoch"]) for row in rows)
        last_epoch = max(int(row["occurred_epoch"]) for row in rows)
        recent = self.recent_incident(source_ip, rule_id, site_id)
        if (
            recent is not None
            and first_epoch <= int(recent["last_seen_epoch"]) + merge_seconds
        ):
            incident_uuid = str(recent["incident_uuid"])
        else:
            incident_uuid = str(uuid.uuid4())
            now = utc_text()
            network = candidate_network(source_ip)
            with self.conn:
                self.conn.execute(
                    """INSERT INTO incidents
                    (incident_uuid, source_ip, rule_id, site_id,
                     first_seen_epoch, last_seen_epoch, first_seen, last_seen,
                     event_count, distinct_accounts, site_count,
                     network_cidr, decision_status, report_status, report_detail,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?,
                            'pending', ?, ?, ?, ?)""",
                    (
                        incident_uuid,
                        source_ip,
                        rule_id,
                        site_id,
                        first_epoch,
                        last_epoch,
                        epoch_text(first_epoch),
                        epoch_text(last_epoch),
                        network,
                        initial_report_status,
                        initial_report_detail,
                        now,
                        now,
                    ),
                )
        with self.conn:
            for row in rows:
                self.conn.execute(
                    "INSERT OR IGNORE INTO incident_events "
                    "(incident_uuid, event_uuid) VALUES (?, ?)",
                    (incident_uuid, row["event_uuid"]),
                )
            stats = self.conn.execute(
                """SELECT MIN(e.occurred_epoch) AS first_epoch,
                          MAX(e.occurred_epoch) AS last_epoch,
                          COUNT(*) AS event_count,
                          COUNT(DISTINCT e.account_key) AS distinct_accounts,
                          COUNT(DISTINCT e.site_id) AS site_count
                   FROM incident_events ie
                   JOIN events e ON e.event_uuid = ie.event_uuid
                   WHERE ie.incident_uuid = ?""",
                (incident_uuid,),
            ).fetchone()
            self.conn.execute(
                """UPDATE incidents SET
                    first_seen_epoch = ?, last_seen_epoch = ?,
                    first_seen = ?, last_seen = ?,
                    event_count = ?, distinct_accounts = ?, site_count = ?,
                    updated_at = ?
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
    def pending_incidents(
        self,
        retry_dry_run: bool,
        retry_disabled_reports: bool,
        include_reports: bool = True,
    ) -> list[sqlite3.Row]:
        decision_states = ["pending", "failed"]
        report_states = ["pending", "failed", "deferred"]
        if retry_dry_run:
            decision_states.append("dry-run")
        if retry_disabled_reports:
            report_states.extend(["disabled", "no-contact"])
        decision_marks = ",".join("?" for _ in decision_states)
        report_marks = ",".join("?" for _ in report_states)
        now_epoch = int(utc_now().timestamp())
        if include_reports:
            query = f"""SELECT * FROM incidents
                        WHERE decision_status IN ({decision_marks})
                           OR (
                                report_status IN ({report_marks})
                                AND COALESCE(next_report_after_epoch, 0) <= ?
                            )
                        ORDER BY created_at ASC"""
            parameters = tuple(
                decision_states + report_states + [now_epoch]
            )
        else:
            query = f"""SELECT * FROM incidents
                        WHERE decision_status IN ({decision_marks})
                        ORDER BY created_at ASC"""
            parameters = tuple(decision_states)
        return list(self.conn.execute(query, parameters))

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
            """SELECT COUNT(DISTINCT COALESCE(
                           message_id,
                           'attempt:' || attempt_id
                       )) AS sent_count,
                      MAX(attempted_epoch) AS last_sent_epoch,
                      MIN(attempted_epoch) AS oldest_sent_epoch
               FROM report_attempts
               WHERE recipient = ?
                 AND test_mode = ?
                 AND status = 'sent'
                 AND attempted_epoch >= ?""",
            (
                recipient.strip().lower(),
                1 if test_mode else 0,
                int(since_epoch),
            ),
        ).fetchone()
        count = int(row["sent_count"] or 0)
        last_epoch = (
            int(row["last_sent_epoch"])
            if row["last_sent_epoch"] is not None
            else None
        )
        oldest_epoch = (
            int(row["oldest_sent_epoch"])
            if row["oldest_sent_epoch"] is not None
            else None
        )
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

    def import_observations(
        self,
        file_uuid: str,
        digest: str,
        source_host: str,
        original_path: Path,
        observations: Sequence[Mapping[str, Any]],
    ) -> int:
        imported = 0
        with self.conn:
            existing = self.conn.execute(
                "SELECT file_uuid FROM observation_files WHERE sha256 = ?", (digest,)
            ).fetchone()
            if existing is not None:
                return 0
            self.conn.execute(
                """INSERT INTO observation_files
                (file_uuid, sha256, source_host, original_path, imported_at, observation_count)
                VALUES (?, ?, ?, ?, ?, 0)""",
                (file_uuid, digest, source_host, str(original_path), utc_text()),
            )
            for item in observations:
                cursor = self.conn.execute(
                    """INSERT OR IGNORE INTO network_observations
                    (observation_uuid, file_uuid, occurred_epoch, occurred_at, source_host,
                     request_id, source_ip, source_port, destination_ip, destination_port,
                     transport_protocol, application_protocol, tls_protocol, host, server_name,
                     request_method, request_uri, http_status, user_agent, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        item["observation_uuid"], file_uuid, item["occurred_epoch"],
                        item["occurred_at"], item["source_host"], item.get("request_id"),
                        item["source_ip"], item.get("source_port"), item.get("destination_ip"),
                        item.get("destination_port"), item.get("transport_protocol"),
                        item.get("application_protocol"), item.get("tls_protocol"),
                        item.get("host"), item.get("server_name"), item.get("request_method"),
                        item.get("request_uri"), item.get("http_status"), item.get("user_agent"),
                        json.dumps(item.get("raw", {}), sort_keys=True, separators=(",", ":")),
                    ),
                )
                imported += 1 if cursor.rowcount == 1 else 0
            self.conn.execute(
                "UPDATE observation_files SET observation_count = ? WHERE file_uuid = ?",
                (imported, file_uuid),
            )
        return imported

    def set_observation_archive_path(self, file_uuid: str, path: Path) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE observation_files SET archived_path = ? WHERE file_uuid = ?",
                (str(path), file_uuid),
            )

    def correlate_network_observations(self, fallback_seconds: int) -> int:
        linked = 0
        with self.conn:
            exact = self.conn.execute(
                """SELECT DISTINCT ie.incident_uuid, no.observation_uuid
                   FROM incident_events ie
                   JOIN events e ON e.event_uuid = ie.event_uuid
                   JOIN network_observations no
                     ON no.request_id = e.request_id AND no.source_ip = e.source_ip
                   WHERE e.request_id IS NOT NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM incident_network_observations ino
                         WHERE ino.incident_uuid = ie.incident_uuid
                           AND ino.observation_uuid = no.observation_uuid
                     )"""
            ).fetchall()
            for row in exact:
                self.conn.execute(
                    """INSERT OR IGNORE INTO incident_network_observations
                    (incident_uuid, observation_uuid, correlation_method, correlated_at)
                    VALUES (?, ?, 'request-id', ?)""",
                    (row["incident_uuid"], row["observation_uuid"], utc_text()),
                )
                linked += 1

            approximate = self.conn.execute(
                """SELECT DISTINCT ie.incident_uuid, no.observation_uuid
                   FROM incident_events ie
                   JOIN events e ON e.event_uuid = ie.event_uuid
                   JOIN network_observations no
                     ON no.source_ip = e.source_ip
                    AND ABS(no.occurred_epoch - e.occurred_epoch) <= ?
                    AND (e.request_path IS NULL OR no.request_uri IS NULL
                         OR no.request_uri = e.request_path
                         OR no.request_uri LIKE e.request_path || '?%')
                   WHERE e.request_id IS NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM incident_network_observations ino
                         WHERE ino.incident_uuid = ie.incident_uuid
                           AND ino.observation_uuid = no.observation_uuid
                     )""",
                (int(fallback_seconds),),
            ).fetchall()
            for row in approximate:
                self.conn.execute(
                    """INSERT OR IGNORE INTO incident_network_observations
                    (incident_uuid, observation_uuid, correlation_method, correlated_at)
                    VALUES (?, ?, 'timestamp-path', ?)""",
                    (row["incident_uuid"], row["observation_uuid"], utc_text()),
                )
                linked += 1
        return linked

    def incident_network_evidence(self, incident_uuid: str, limit: int = 20) -> list[sqlite3.Row]:
        bounded = max(1, min(100, int(limit)))
        return list(
            self.conn.execute(
                """SELECT no.*, ino.correlation_method
                   FROM incident_network_observations ino
                   JOIN network_observations no
                     ON no.observation_uuid = ino.observation_uuid
                   WHERE ino.incident_uuid = ?
                   ORDER BY no.occurred_epoch ASC, no.observation_uuid ASC
                   LIMIT ?""",
                (incident_uuid, bounded),
            )
        )

    def network_context(self, network_cidr: str, policy: Mapping[str, Any]) -> dict[str, Any]:
        cutoff = int(utc_now().timestamp()) - int(policy["network_review_window_days"]) * 86400
        effective = "COALESCE(NULLIF(registered_cidr, ''), network_cidr)"
        evidence_rows = list(
            self.conn.execute(
                f"""SELECT incident_uuid, source_ip, event_count,
                           first_seen, last_seen, last_seen_epoch
                    FROM incidents
                    WHERE {effective} = ? AND last_seen_epoch >= ?
                    ORDER BY last_seen_epoch, incident_uuid""",
                (network_cidr, cutoff),
            )
        )
        row = self.conn.execute(
            f"""SELECT COUNT(DISTINCT source_ip) AS hostile_ips,
                       COUNT(*) AS incident_count,
                       COALESCE(SUM(event_count), 0) AS event_count,
                       COUNT(DISTINCT substr(first_seen, 1, 10)) AS active_days,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen,
                       GROUP_CONCAT(DISTINCT asn) AS asns,
                       GROUP_CONCAT(DISTINCT network_class) AS network_classes,
                       MAX(CASE WHEN registered_cidr IS NOT NULL
                                     AND registered_cidr != ''
                                THEN 1 ELSE 0 END) AS has_registered
                FROM incidents
                WHERE {effective} = ? AND last_seen_epoch >= ?""",
            (network_cidr, cutoff),
        ).fetchone()
        hostile_ips = int(row["hostile_ips"] or 0)
        incident_count = int(row["incident_count"] or 0)
        active_days = int(row["active_days"] or 0)
        status, suggested_days, _ = network_case_recommendation(
            policy, hostile_ips, incident_count, active_days,
        )
        proposal = network_block_proposal(network_cidr, evidence_rows, policy)
        existing = self.conn.execute(
            "SELECT * FROM network_cases WHERE network_cidr = ?",
            (network_cidr,),
        ).fetchone()
        review_status = "open"
        review_disposition = None
        review_note = None
        review_updated_epoch = None
        review_updated_at = None
        if existing is not None:
            previous_status = str(existing["status"])
            previous_revision = str(existing["proposal_revision"] or "")
            same_revision = previous_revision == str(proposal["proposal_revision"])
            if previous_status == "blocked":
                status = previous_status
                review_status = str(existing["review_status"] or "closed")
                review_disposition = existing["review_disposition"]
            elif same_revision and str(existing["review_status"] or "open") == "closed":
                status = previous_status
                review_status = "closed"
                review_disposition = existing["review_disposition"]
            elif previous_revision and not same_revision:
                review_disposition = "proposal-updated"
            review_note = existing["review_note"]
            review_updated_epoch = existing["review_updated_epoch"]
            review_updated_at = existing["review_updated_at"]
        return {
            "network_cidr": network_cidr,
            "hostile_ips": hostile_ips,
            "incident_count": incident_count,
            "event_count": int(row["event_count"] or 0),
            "active_days": active_days,
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "status": status,
            "suggested_block_days": suggested_days,
            "grouping_basis": "registered" if int(row["has_registered"] or 0) else "fallback",
            "asns": row["asns"],
            "network_classes": row["network_classes"],
            "operator_note": existing["operator_note"] if existing is not None else None,
            **proposal,
            "review_status": review_status,
            "review_disposition": review_disposition,
            "review_note": review_note,
            "review_updated_epoch": review_updated_epoch,
            "review_updated_at": review_updated_at,
            "decision_cidr": existing["decision_cidr"] if existing is not None else None,
            "decision_status": existing["decision_status"] if existing is not None else None,
            "decision_detail": existing["decision_detail"] if existing is not None else None,
            "decision_duration_days": int(existing["decision_duration_days"] or 0) if existing is not None else 0,
            "decision_applied_at": existing["decision_applied_at"] if existing is not None else None,
        }
    def sync_network_cases(self, policy: Mapping[str, Any]) -> int:
        changed = 0
        candidates = self.network_candidates(policy)
        now = utc_text()
        effective = "COALESCE(NULLIF(registered_cidr, ''), network_cidr)"
        with self.conn:
            for candidate in candidates:
                context = self.network_context(str(candidate["network_cidr"]), policy)
                current = self.conn.execute(
                    "SELECT status FROM network_cases WHERE network_cidr = ?",
                    (context["network_cidr"],),
                ).fetchone()
                status = context["status"]
                if current is not None and str(current["status"]) == "blocked":
                    status = str(current["status"])
                self.conn.execute(
                    """INSERT INTO network_cases
                    (network_cidr, status, hostile_ips, incident_count, event_count,
                     active_days, first_seen, last_seen, suggested_block_days,
                     grouping_basis, asns, network_classes, operator_note,
                     proposal_cidr, proposal_revision, proposal_hostile_ips,
                     proposal_incident_count, proposal_event_count,
                     proposal_active_days, proposal_coverage_percent,
                     proposal_basis, review_status, review_disposition,
                     review_note, review_updated_epoch, review_updated_at,
                     decision_cidr, decision_status, decision_detail,
                     decision_duration_days, decision_applied_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(network_cidr) DO UPDATE SET
                     status=excluded.status,
                     hostile_ips=excluded.hostile_ips,
                     incident_count=excluded.incident_count,
                     event_count=excluded.event_count,
                     active_days=excluded.active_days,
                     first_seen=excluded.first_seen,
                     last_seen=excluded.last_seen,
                     suggested_block_days=excluded.suggested_block_days,
                     grouping_basis=excluded.grouping_basis,
                     asns=excluded.asns,
                     network_classes=excluded.network_classes,
                     operator_note=excluded.operator_note,
                     proposal_cidr=excluded.proposal_cidr,
                     proposal_revision=excluded.proposal_revision,
                     proposal_hostile_ips=excluded.proposal_hostile_ips,
                     proposal_incident_count=excluded.proposal_incident_count,
                     proposal_event_count=excluded.proposal_event_count,
                     proposal_active_days=excluded.proposal_active_days,
                     proposal_coverage_percent=excluded.proposal_coverage_percent,
                     proposal_basis=excluded.proposal_basis,
                     review_status=excluded.review_status,
                     review_disposition=excluded.review_disposition,
                     review_note=excluded.review_note,
                     review_updated_epoch=excluded.review_updated_epoch,
                     review_updated_at=excluded.review_updated_at,
                     decision_cidr=excluded.decision_cidr,
                     decision_status=excluded.decision_status,
                     decision_detail=excluded.decision_detail,
                     decision_duration_days=excluded.decision_duration_days,
                     decision_applied_at=excluded.decision_applied_at,
                     updated_at=excluded.updated_at""",
                    (
                        context["network_cidr"], status, context["hostile_ips"],
                        context["incident_count"], context["event_count"],
                        context["active_days"], context["first_seen"],
                        context["last_seen"], context["suggested_block_days"],
                        context["grouping_basis"], context["asns"],
                        context["network_classes"], context["operator_note"],
                        context["proposal_cidr"], context["proposal_revision"],
                        context["proposal_hostile_ips"],
                        context["proposal_incident_count"],
                        context["proposal_event_count"],
                        context["proposal_active_days"],
                        context["proposal_coverage_percent"],
                        context["proposal_basis"], context["review_status"],
                        context["review_disposition"], context["review_note"],
                        context["review_updated_epoch"],
                        context["review_updated_at"], context["decision_cidr"],
                        context["decision_status"], context["decision_detail"],
                        context["decision_duration_days"],
                        context["decision_applied_at"], now,
                    ),
                )
                self.conn.execute(
                    f"""INSERT OR IGNORE INTO network_case_incidents(network_cidr, incident_uuid)
                        SELECT ?, incident_uuid FROM incidents WHERE {effective} = ?""",
                    (context["network_cidr"], context["network_cidr"]),
                )
                changed += 1
        return changed
    def network_cases(self, limit: int = 100) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            """SELECT * FROM network_cases
               ORDER BY CASE status WHEN 'blocked' THEN 0
                                    WHEN 'long-block-review' THEN 1
                                    WHEN 'escalation-review' THEN 2
                                    WHEN 'review' THEN 3 ELSE 4 END,
                        hostile_ips DESC, last_seen DESC LIMIT ?""",
            (max(1, min(500, int(limit))),),
        ))
    def set_network_case(self, network_cidr: str, status: str, note: str | None) -> None:
        normalized = str(ipaddress.ip_network(network_cidr, strict=False))
        allowed = {"observing", "review", "escalation-review", "long-block-review", "blocked", "closed"}
        if status not in allowed:
            raise CollectorError(f"Unsupported network case status: {status}")
        context = self.network_context(normalized, DEFAULTS["policy"])
        with self.conn:
            self.conn.execute(
                """INSERT INTO network_cases
                (network_cidr, status, hostile_ips, incident_count, event_count,
                 active_days, first_seen, last_seen, suggested_block_days,
                 grouping_basis, asns, network_classes, operator_note, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_cidr) DO UPDATE SET
                 status=excluded.status,
                 suggested_block_days=excluded.suggested_block_days,
                 grouping_basis=excluded.grouping_basis,
                 asns=excluded.asns,
                 network_classes=excluded.network_classes,
                 operator_note=excluded.operator_note,
                 updated_at=excluded.updated_at""",
                (
                    normalized, status, context["hostile_ips"], context["incident_count"],
                    context["event_count"], context["active_days"], context["first_seen"],
                    context["last_seen"], context["suggested_block_days"],
                    context["grouping_basis"], context["asns"], context["network_classes"],
                    clean_optional(note, 2000), utc_text(),
                ),
            )
    def network_case_incidents(self, network_cidr: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            """SELECT i.* FROM network_case_incidents nci
               JOIN incidents i ON i.incident_uuid = nci.incident_uuid
               WHERE nci.network_cidr = ?
               ORDER BY i.last_seen_epoch DESC""",
            (network_cidr,),
        ))

    def network_report_sent(self, network_cidr: str, report_type: str) -> bool:
        return self.conn.execute(
            """SELECT 1 FROM network_case_reports
               WHERE network_cidr=? AND report_type=? AND status='sent' LIMIT 1""",
            (network_cidr, report_type),
        ).fetchone() is not None

    def network_report_sent_today(self, network_cidr: str, report_type: str) -> bool:
        return self.conn.execute(
            """SELECT 1 FROM network_case_reports
               WHERE network_cidr=? AND report_type=? AND status='sent'
                 AND substr(attempted_at, 1, 10) = substr(?, 1, 10)
               LIMIT 1""",
            (network_cidr, report_type, utc_text()),
        ).fetchone() is not None

    def record_network_report(
        self,
        network_cidr: str,
        report_type: str,
        status: str,
        recipient: str | None,
        detail: str,
        message_id: str | None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO network_case_reports
                   (network_cidr, report_type, attempted_at, status, recipient, detail, message_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    network_cidr, report_type, utc_text(), status,
                    clean_optional(recipient, 1000), clean_optional(detail, 2000),
                    clean_optional(message_id, 255),
                ),
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
        for table in ("batches", "events", "incidents", "network_observations", "network_cases"):
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
                """SELECT incident_uuid, source_ip, rule_id, site_id, first_seen, last_seen,
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
        effective = "COALESCE(NULLIF(registered_cidr, ''), network_cidr)"
        rows = self.conn.execute(
            f"""SELECT {effective} AS network_cidr,
                       COUNT(DISTINCT source_ip) AS hostile_ips,
                       COUNT(*) AS incident_count,
                       COALESCE(SUM(event_count), 0) AS event_count,
                       COUNT(DISTINCT substr(first_seen, 1, 10)) AS active_days,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen,
                       GROUP_CONCAT(DISTINCT asn) AS asns,
                       GROUP_CONCAT(DISTINCT network_class) AS network_classes,
                       MAX(CASE WHEN registered_cidr IS NOT NULL AND registered_cidr != ''
                                THEN 1 ELSE 0 END) AS has_registered
                FROM incidents
                WHERE {effective} IS NOT NULL AND last_seen_epoch >= ?
                GROUP BY {effective}
                HAVING COUNT(DISTINCT source_ip) >= ?
                ORDER BY hostile_ips DESC, active_days DESC, last_seen DESC""",
            (cutoff, review_ips),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            status, days, detail = network_case_recommendation(
                policy, int(row["hostile_ips"]), int(row["incident_count"]), int(row["active_days"]),
            )
            item["recommendation"] = status
            item["suggested_block_days"] = days
            item["recommendation_detail"] = detail
            item["grouping_basis"] = "registered" if int(row["has_registered"] or 0) else "fallback"
            item["automatic_block"] = False
            result.append(item)
        return result

def network_case_recommendation(
    policy: Mapping[str, Any], hostile_ips: int, incident_count: int, active_days: int,
) -> tuple[str, int, str]:
    if (
        hostile_ips >= int(policy["network_severe_block_distinct_ips"])
        and incident_count >= int(policy["network_severe_block_incidents"])
    ):
        days = int(policy["network_severe_block_days"])
        return "long-block-review", days, f"Severe distributed hostility; operator review required before a {days}-day block."
    if (
        hostile_ips >= int(policy["network_long_block_distinct_ips"])
        and incident_count >= int(policy["network_long_block_incidents"])
        and active_days >= int(policy["network_long_block_active_days"])
    ):
        days = int(policy["network_long_block_days"])
        return "long-block-review", days, f"Distributed or sequential hostility; operator review required before a {days}-day block."
    if hostile_ips >= int(policy["network_escalation_distinct_ips"]) or active_days >= int(policy["network_escalation_active_days"]):
        return "escalation-review", 0, "Network escalation criteria reached."
    if hostile_ips >= int(policy["network_review_distinct_ips"]):
        return "review", 0, "Network review threshold reached."
    return "observing", 0, "Below network review threshold."


def network_block_proposal(
    network_cidr: str,
    evidence_rows: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the strongest bounded, most-specific hostile CIDR proposal."""

    registered = ipaddress.ip_network(str(network_cidr), strict=False)
    boundary_prefix = int(
        policy[
            "network_block_min_ipv4_prefix_length"
            if registered.version == 4
            else "network_block_min_ipv6_prefix_length"
        ]
    )
    boundary_prefix = max(boundary_prefix, registered.prefixlen)
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in evidence_rows:
        try:
            address = ipaddress.ip_address(str(row["source_ip"]))
        except (ValueError, KeyError, TypeError):
            continue
        if address.version != registered.version or address not in registered:
            continue
        bounded = ipaddress.ip_network(
            f"{address}/{boundary_prefix}",
            strict=False,
        )
        groups.setdefault(str(bounded), []).append(row)

    if not groups:
        revision_payload = {
            "network_cidr": str(registered),
            "proposal_cidr": None,
            "source_ips": [],
            "incident_uuids": [],
        }
        revision = hashlib.sha256(
            json.dumps(revision_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return {
            "proposal_cidr": None,
            "proposal_revision": revision,
            "proposal_hostile_ips": 0,
            "proposal_incident_count": 0,
            "proposal_event_count": 0,
            "proposal_active_days": 0,
            "proposal_coverage_percent": 0.0,
            "proposal_basis": f"bounded-/{boundary_prefix}-no-evidence",
        }

    def group_score(item: tuple[str, list[Mapping[str, Any]]]) -> tuple[Any, ...]:
        cidr, rows = item
        sources = {str(row["source_ip"]) for row in rows}
        active_days = {
            value
            for row in rows
            for value in (
                str(row["first_seen"])[:10],
                str(row["last_seen"])[:10],
            )
            if value
        }
        last_epoch = max(int(row["last_seen_epoch"] or 0) for row in rows)
        return (len(sources), len(rows), len(active_days), last_epoch, cidr)

    bounded_cidr, selected = max(groups.items(), key=group_score)
    addresses = sorted(
        {
            ipaddress.ip_address(str(row["source_ip"]))
            for row in selected
        },
        key=int,
    )
    minimum = int(addresses[0])
    maximum = int(addresses[-1])
    width = addresses[0].max_prefixlen
    common_prefix = width - (minimum ^ maximum).bit_length()
    proposal_prefix = max(boundary_prefix, common_prefix, registered.prefixlen)
    proposal = ipaddress.ip_network((minimum, proposal_prefix), strict=False)
    if not proposal.subnet_of(registered):
        proposal = registered

    incident_ids = sorted(
        {str(row["incident_uuid"]) for row in selected}
    )
    source_ips = [str(address) for address in addresses]
    event_count = sum(int(row["event_count"] or 0) for row in selected)
    active_days = len(
        {
            value
            for row in selected
            for value in (
                str(row["first_seen"])[:10],
                str(row["last_seen"])[:10],
            )
            if value
        }
    )
    first_seen = min(str(row["first_seen"]) for row in selected)
    last_seen = max(str(row["last_seen"]) for row in selected)
    coverage = (len(addresses) / int(proposal.num_addresses)) * 100.0
    revision_payload = {
        "network_cidr": str(registered),
        "bounded_cidr": bounded_cidr,
        "proposal_cidr": str(proposal),
        "source_ips": source_ips,
        "incident_uuids": incident_ids,
        "event_count": event_count,
        "active_days": active_days,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }
    revision = hashlib.sha256(
        json.dumps(revision_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "proposal_cidr": str(proposal),
        "proposal_revision": revision,
        "proposal_hostile_ips": len(addresses),
        "proposal_incident_count": len(selected),
        "proposal_event_count": event_count,
        "proposal_active_days": active_days,
        "proposal_coverage_percent": round(coverage, 8),
        "proposal_basis": (
            f"strongest-bounded-/{boundary_prefix}; source={bounded_cidr}"
        ),
    }


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
    if normalized_source["service"] not in {"wordpress", "sshd", "fail2ban"}:
        raise CollectorError("Unsupported batch source service")
    raw_events = raw.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise CollectorError("Batch events must be a non-empty array")
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_event in raw_events:
        event = normalize_event(raw_event, normalized_source["site_id"], normalized_source["service"])
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


def normalize_event(raw: Any, site_id: str, service: str = "wordpress") -> dict[str, Any]:
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
    if service == "wordpress":
        if user_id is not None:
            try:
                numeric_id = int(user_id)
            except (TypeError, ValueError) as exc:
                raise CollectorError("wordpress_user_id must be an integer") from exc
            if numeric_id > 0:
                account_key = f"{site_id}:user:{numeric_id}"
        elif isinstance(username, str) and username.strip():
            account_key = f"{site_id}:login:{username.strip().casefold()}"
    else:
        account_token = str(
            raw.get("account_key")
            or raw.get("account_hash")
            or ""
        ).strip().lower()
        if account_token:
            if not re.fullmatch(r"[0-9a-f]{64}", account_token):
                raise CollectorError(
                    "Non-WordPress account token must be a SHA-256 hex value"
                )
            account_key = f"{site_id}:account:{account_token}"
    request = raw.get("request") if isinstance(raw.get("request"), dict) else {}
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    return {
        "event_uuid": event_uuid,
        "site_id": site_id,
        "service": service,
        "occurred_epoch": int(occurred.timestamp()),
        "occurred_at": utc_text(occurred),
        "recorded_at": recorded,
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": source_ip,
        "source_port": normalize_port(raw.get("source_port")),
        "destination_ip": normalize_ip_optional(raw.get("destination_ip")),
        "destination_port": normalize_port(raw.get("destination_port")),
        "transport_protocol": clean_protocol(raw.get("transport_protocol")),
        "application_protocol": clean_protocol(raw.get("application_protocol")),
        "account_key": account_key,
        "user_agent": clean_optional(raw.get("user_agent"), 512),
        "request_method": clean_optional(request.get("method"), 16),
        "request_path": clean_optional(request.get("path"), 1024),
        "request_id": normalize_request_id(request.get("request_id") or metadata.get("request_id")),
        "metadata": metadata,
    }


def normalize_network_observation(raw: Any, default_source_host: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CollectorError("Abuse-context observation must be an object")
    timestamp = first_value(raw, "occurred_at", "timestamp", "time", "time_iso8601", "@timestamp")
    occurred = parse_time(timestamp)
    source_value = first_value(raw, "source_ip", "remote_addr", "client_ip")
    if source_value is None:
        raise CollectorError("Abuse-context observation is missing source_ip")
    try:
        source_ip = str(ipaddress.ip_address(str(source_value)))
    except ValueError as exc:
        raise CollectorError("Abuse-context observation contains malformed source_ip") from exc
    destination_ip = None
    destination_value = first_value(raw, "destination_ip", "server_addr", "local_addr")
    if destination_value is not None:
        try:
            destination_ip = str(ipaddress.ip_address(str(destination_value)))
        except ValueError as exc:
            raise CollectorError("Abuse-context observation contains malformed destination_ip") from exc
    status_value = first_value(raw, "http_status", "status")
    try:
        http_status = int(status_value) if status_value not in (None, "", "-") else None
    except (TypeError, ValueError):
        http_status = None
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "observation_uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"argent-sentinel:{fingerprint}")),
        "occurred_epoch": int(occurred.timestamp()),
        "occurred_at": utc_text(occurred),
        "source_host": clean_optional(first_value(raw, "source_host", "node_id"), 255) or default_source_host,
        "request_id": normalize_request_id(first_value(raw, "request_id", "requestid", "nginx_request_id")),
        "source_ip": source_ip,
        "source_port": normalize_port(first_value(raw, "source_port", "remote_port", "client_port")),
        "destination_ip": destination_ip,
        "destination_port": normalize_port(first_value(raw, "destination_port", "server_port", "local_port")),
        "transport_protocol": (clean_optional(first_value(raw, "transport_protocol", "transport"), 16) or "TCP").upper(),
        "application_protocol": clean_optional(first_value(raw, "application_protocol", "server_protocol", "protocol"), 64),
        "tls_protocol": clean_optional(first_value(raw, "tls_protocol", "ssl_protocol"), 64),
        "host": clean_optional(first_value(raw, "host", "http_host"), 255),
        "server_name": clean_optional(first_value(raw, "server_name", "vhost"), 255),
        "request_method": clean_optional(first_value(raw, "request_method", "method"), 16),
        "request_uri": clean_optional(first_value(raw, "request_uri", "uri", "request_path"), 2048),
        "http_status": http_status,
        "user_agent": clean_optional(first_value(raw, "user_agent", "http_user_agent"), 512),
        "raw": raw,
    }


def normalize_request_id(value: Any) -> str | None:
    cleaned = clean_optional(value, 128)
    if cleaned is None:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:")
    if len(cleaned) < 8 or any(character not in allowed for character in cleaned):
        return None
    return cleaned


def normalize_port(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def normalize_ip_optional(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise CollectorError("Malformed destination_ip") from exc


def clean_protocol(value: Any) -> str | None:
    cleaned = clean_optional(value, 32)
    return cleaned.upper() if cleaned else None


def first_value(raw: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, "", "-"):
            return raw[key]
    return None


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
        self.evaluate_persistent_wordpress_recent()
        context_files = self.import_abuse_context_files()
        linked = self.db.correlate_network_observations(
            int(self.config["abuse_context"]["fallback_correlation_seconds"])
        )
        self.db.sync_network_cases(self.config["policy"])
        self.retry_pending_incidents()
        LOG.info(
            "Collector run complete: %d event batch files, %d abuse-context files, %d tuple links",
            imported_files, context_files, linked,
        )
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

    def abuse_context_files(self) -> list[Path]:
        if not self.config["abuse_context"].get("enabled"):
            return []
        paths: set[Path] = set()
        for pattern in self.config["abuse_context"].get("incoming_globs", []):
            for value in glob.glob(str(pattern)):
                path = Path(value)
                if path.name.startswith(".") or path.suffix.lower() not in {".json", ".jsonl", ".ndjson"}:
                    continue
                paths.add(path)
        return sorted(paths, key=lambda item: str(item))

    def import_abuse_context_files(self) -> int:
        imported_files = 0
        for original in self.abuse_context_files():
            claimed: Path | None = None
            try:
                claimed = self.claim_context_file(original)
                self.process_abuse_context_file(claimed, original)
                imported_files += 1
            except Exception as exc:
                LOG.exception("Rejecting abuse-context file %s: %s", original, exc)
                self.reject_context_file(claimed or original, str(exc))
        return imported_files

    def claim_context_file(self, path: Path) -> Path:
        initial = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise CollectorError("Abuse-context input must be a regular, non-symlink file")
        if initial.st_size <= 0 or initial.st_size > int(self.config["abuse_context"]["max_file_bytes"]):
            raise CollectorError("Abuse-context file size is outside configured limits")
        processing = Path(self.config["abuse_context"]["processing_dir"])
        processing.mkdir(parents=True, exist_ok=True, mode=0o750)
        claimed = processing / f"{uuid.uuid4()}-{path.name}"
        self.move_regular_file(path, claimed, initial)
        if os.geteuid() == 0:
            os.chown(claimed, 0, 0)
        os.chmod(claimed, 0o400)
        return claimed

    def process_abuse_context_file(self, path: Path, original_path: Path) -> None:
        data = path.read_bytes()
        if not data or len(data) > int(self.config["abuse_context"]["max_file_bytes"]):
            raise CollectorError("Abuse-context file size is outside configured limits")
        digest = hashlib.sha256(data).hexdigest()
        raw_items: list[Any] = []
        stripped = data.lstrip()
        if stripped.startswith(b"["):
            try:
                parsed = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CollectorError(f"Abuse-context JSON is invalid: {exc}") from exc
            if not isinstance(parsed, list):
                raise CollectorError("Abuse-context JSON root must be an array")
            raw_items = parsed
        else:
            for number, line in enumerate(data.splitlines(), 1):
                if not line.strip():
                    continue
                if len(line) > int(self.config["abuse_context"]["max_line_bytes"]):
                    raise CollectorError(f"Abuse-context line {number} exceeds max_line_bytes")
                try:
                    raw_items.append(json.loads(line.decode("utf-8")))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CollectorError(f"Abuse-context line {number} is invalid JSON: {exc}") from exc
        source_host = str(self.config["node"]["id"])
        observations = [normalize_network_observation(item, source_host) for item in raw_items]
        file_uuid = str(uuid.uuid4())
        imported = self.db.import_observations(
            file_uuid, digest, source_host, original_path, observations
        )
        web_events = self.db.materialize_web_probe_events(
            file_uuid, source_host, observations, self.config["web_policy"]
        )
        if web_events:
            self.evaluate_new_events(web_events)
        archive = self.archive_context_file(path, original_path.name, file_uuid)
        self.db.set_observation_archive_path(file_uuid, archive)
        LOG.info("Imported abuse-context file %s: %d observations, %d web events", original_path, imported, len(web_events))

    def archive_context_file(self, path: Path, original_name: str, file_uuid: str) -> Path:
        now = utc_now()
        destination = Path(self.config["abuse_context"]["archive_dir"]) / f"{now:%Y}" / f"{now:%m}" / f"{now:%d}"
        destination.mkdir(parents=True, exist_ok=True, mode=0o750)
        final = destination / Path(original_name).name
        if final.exists():
            final = destination / f"{Path(original_name).stem}-{file_uuid}{Path(original_name).suffix}"
        self.move_regular_file(path, final)
        os.chmod(final, 0o640)
        return final

    def reject_context_file(self, path: Path, error: str) -> None:
        if not path.exists() or path.is_symlink():
            return
        destination = Path(self.config["abuse_context"]["rejected_dir"]) / f"{utc_now():%Y-%m-%d}"
        destination.mkdir(parents=True, exist_ok=True, mode=0o750)
        final = destination / path.name
        if final.exists():
            final = destination / f"{path.stem}-{uuid.uuid4()}{path.suffix}"
        self.move_regular_file(path, final)
        os.chmod(final, 0o640)
        final.with_suffix(final.suffix + ".error.txt").write_text(
            clean_optional(error, 2000) or "Unknown error", encoding="utf-8"
        )

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

    def evaluate_persistent_wordpress_recent(
        self,
        now_epoch: int | None = None,
    ) -> int:
        policy = self.config.get("persistent_wordpress_policy", {})
        if not policy.get("enabled"):
            return 0
        end_epoch = int(
            now_epoch if now_epoch is not None else utc_now().timestamp()
        )
        start_epoch = end_epoch - int(policy["window_seconds"])
        changed_incidents: set[str] = set()
        report_enabled = bool(policy.get("abuse_reporting_enabled"))
        report_status = "pending" if report_enabled else "suppressed"
        report_detail = None if report_enabled else (
            'Persistent WordPress policy reporting disabled pending production review'
        )
        for source in self.db.persistent_wordpress_sources(
            start_epoch,
            end_epoch,
        ):
            source_ip = str(source["source_ip"])
            site_id = str(source["site_id"])
            try:
                if self.trusted_ip(source_ip):
                    continue
            except ValueError:
                continue
            rows = self.db.persistent_login_failures(
                source_ip,
                site_id,
                start_epoch,
                end_epoch,
            )
            candidate = self.qualify_persistent_wordpress(rows)
            if candidate is None:
                continue
            rule_id, evidence = candidate
            prior = self.db.recent_incident(source_ip, rule_id, site_id)
            prior_count = int(prior["event_count"]) if prior is not None else -1
            incident_uuid = self.db.create_or_merge_incident(
                source_ip,
                rule_id,
                evidence,
                int(policy["incident_merge_seconds"]),
                site_id=site_id,
                initial_report_status=report_status,
                initial_report_detail=report_detail,
            )
            incident = self.db.incident(incident_uuid)
            if prior is None or int(incident["event_count"]) != prior_count:
                changed_incidents.add(incident_uuid)
                LOG.warning(
                    "Persistent WordPress authentication incident %s: "
                    "site=%s ip=%s rule=%s events=%d accounts=%d",
                    incident_uuid,
                    site_id,
                    source_ip,
                    rule_id,
                    int(incident["event_count"]),
                    int(incident["distinct_accounts"]),
                )
        return len(changed_incidents)
    def evaluate_new_events(self, events: Sequence[Mapping[str, Any]]) -> None:
        wordpress_events = [
            event for event in events
            if event.get("event_type") == "login_failed"
            and event.get("outcome") == "denied"
            and event.get("source_ip")
        ]
        by_ip: dict[str, list[Mapping[str, Any]]] = {}
        for event in wordpress_events:
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
                    "WordPress authentication incident %s: ip=%s rule=%s events=%d accounts=%d",
                    incident_uuid,
                    source_ip,
                    rule_id,
                    len(evidence),
                    len({row["account_key"] for row in evidence if row["account_key"]}),
                )

        if self.config.get("web_policy", {}).get("enabled"):
            web_events = [
                event for event in events
                if event.get("event_type") == "web_probe"
                and event.get("outcome") == "denied"
                and event.get("source_ip")
            ]
            web_by_ip: dict[str, list[Mapping[str, Any]]] = {}
            for event in web_events:
                web_by_ip.setdefault(str(event["source_ip"]), []).append(event)
            web_policy = self.config["web_policy"]
            web_window = int(web_policy["window_seconds"])
            for source_ip, new_rows in web_by_ip.items():
                earliest = min(int(item["occurred_epoch"]) for item in new_rows) - web_window
                latest = max(int(item["occurred_epoch"]) for item in new_rows) + web_window
                rows = self.db.web_probe_events(source_ip, earliest, latest)
                for candidate in self.find_web_probe_candidates(rows):
                    incident_uuid = self.db.create_or_merge_incident(
                        source_ip,
                        "nginx-hostile-web-probing",
                        candidate,
                        int(web_policy["incident_merge_seconds"]),
                    )
                    LOG.warning(
                        "Nginx hostile probing incident %s: ip=%s events=%d targets=%d",
                        incident_uuid, source_ip, len(candidate),
                        len({row["request_path"] for row in candidate if row["request_path"]}),
                    )

        if not self.config.get("sshd_policy", {}).get("enabled"):
            return
        ssh_events = [
            event for event in events
            if event.get("event_type") == "ssh_auth_failed"
            and event.get("outcome") == "denied"
            and event.get("source_ip")
        ]
        ssh_by_ip: dict[str, list[Mapping[str, Any]]] = {}
        for event in ssh_events:
            ssh_by_ip.setdefault(str(event["source_ip"]), []).append(event)
        ssh_policy = self.config["sshd_policy"]
        ssh_window = int(ssh_policy["window_seconds"])
        for source_ip, new_rows in ssh_by_ip.items():
            earliest = min(int(item["occurred_epoch"]) for item in new_rows) - ssh_window
            latest = max(int(item["occurred_epoch"]) for item in new_rows) + ssh_window
            rows = self.db.ssh_failures(source_ip, earliest, latest)
            for rule_id, evidence in self.find_ssh_candidates(rows):
                incident_uuid = self.db.create_or_merge_incident(
                    source_ip,
                    rule_id,
                    evidence,
                    int(ssh_policy["incident_merge_seconds"]),
                )
                LOG.warning(
                    "OpenSSH authentication incident %s: ip=%s rule=%s events=%d accounts=%d",
                    incident_uuid,
                    source_ip,
                    rule_id,
                    len(evidence),
                    len({row["account_key"] for row in evidence if row["account_key"]}),
                )

    def qualify_persistent_wordpress(
        self,
        rows: Sequence[sqlite3.Row],
    ) -> tuple[str, list[sqlite3.Row]] | None:
        if not rows:
            return None
        policy = self.config["persistent_wordpress_policy"]
        accounts = {
            str(row["account_key"])
            for row in rows
            if row["account_key"]
        }
        if (
            len(rows) >= int(policy["failure_threshold"])
            and len(accounts) >= int(policy["distinct_accounts"])
        ):
            return "wordpress-persistent-credential-spray", list(rows)
        per_account: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            if row["account_key"]:
                per_account.setdefault(
                    str(row["account_key"]),
                    [],
                ).append(row)
        if per_account:
            evidence = max(
                per_account.values(),
                key=len,
            )
            if len(evidence) >= int(policy["single_account_threshold"]):
                return (
                    "wordpress-persistent-single-account-bruteforce",
                    evidence,
                )
        return None
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

    def find_web_probe_candidates(
        self,
        rows: Sequence[sqlite3.Row],
    ) -> list[list[sqlite3.Row]]:
        if not rows:
            return []
        window = int(self.config["web_policy"]["window_seconds"])
        candidates: list[list[sqlite3.Row]] = []
        segment: list[sqlite3.Row] = []
        previous_epoch: int | None = None
        for row in rows:
            current = int(row["occurred_epoch"])
            if previous_epoch is not None and current - previous_epoch > window:
                candidate = self.qualify_web_probe_segment(segment)
                if candidate is not None:
                    candidates.append(candidate)
                segment = []
            segment.append(row)
            previous_epoch = current
        candidate = self.qualify_web_probe_segment(segment)
        if candidate is not None:
            candidates.append(candidate)
        return candidates

    def qualify_web_probe_segment(
        self,
        rows: Sequence[sqlite3.Row],
    ) -> list[sqlite3.Row] | None:
        if not rows:
            return None
        policy = self.config["web_policy"]
        window = int(policy["window_seconds"])
        threshold = int(policy["suspicious_threshold"])
        distinct_targets = int(policy["distinct_targets"])
        immediate_statuses = {
            int(value) for value in policy.get("immediate_statuses", [444])
        }
        active: deque[sqlite3.Row] = deque()
        evidence_start_epoch: int | None = None
        for row in rows:
            current = int(row["occurred_epoch"])
            while active and int(active[0]["occurred_epoch"]) < current - window:
                active.popleft()
            active.append(row)
            categories = set()
            targets = set()
            for item in active:
                targets.add(str(item["request_path"] or ""))
                try:
                    metadata = json.loads(str(item["metadata_json"] or "{}"))
                except json.JSONDecodeError:
                    metadata = {}
                categories.add(str(metadata.get("probe_category", "")))
            high_volume = "high-volume-web-scanner" in categories
            immediate_status = False
            suspicious_server_error = False
            for item in active:
                try:
                    metadata = json.loads(str(item["metadata_json"] or "{}"))
                except json.JSONDecodeError:
                    metadata = {}
                status = metadata.get("http_status")
                if isinstance(status, int) and status in immediate_statuses:
                    immediate_status = True
                if (
                    metadata.get("probe_category") != "high-volume-web-scanner"
                    and isinstance(status, int)
                    and 500 <= status <= 599
                ):
                    suspicious_server_error = True
                    break
            if evidence_start_epoch is None and (
                immediate_status
                or high_volume
                or suspicious_server_error
                or (
                    len(active) >= threshold
                    and len(targets) >= distinct_targets
                )
            ):
                evidence_start_epoch = int(active[0]["occurred_epoch"])

        if evidence_start_epoch is None:
            return None
        return [
            row
            for row in rows
            if int(row["occurred_epoch"]) >= evidence_start_epoch
        ]

    def find_ssh_candidates(self, rows: Sequence[sqlite3.Row]) -> list[tuple[str, list[sqlite3.Row]]]:
        policy = self.config["sshd_policy"]
        window_seconds = int(policy["window_seconds"])
        candidates: list[tuple[str, list[sqlite3.Row]]] = []
        segment: list[sqlite3.Row] = []
        previous_epoch: int | None = None
        for row in rows:
            current = int(row["occurred_epoch"])
            if previous_epoch is not None and current - previous_epoch > window_seconds:
                candidate = self.qualify_ssh_segment(segment)
                if candidate is not None:
                    candidates.append(candidate)
                segment = []
            segment.append(row)
            previous_epoch = current
        candidate = self.qualify_ssh_segment(segment)
        if candidate is not None:
            candidates.append(candidate)
        return candidates

    def qualify_ssh_segment(self, segment: Sequence[sqlite3.Row]) -> tuple[str, list[sqlite3.Row]] | None:
        if not segment:
            return None
        policy = self.config["sshd_policy"]
        window_seconds = int(policy["window_seconds"])
        threshold = int(policy["failure_threshold"])
        distinct_required = int(policy["distinct_accounts"])
        single_threshold = int(policy["single_account_threshold"])
        active: deque[sqlite3.Row] = deque()
        primary = False
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
            if counts:
                key = max(counts, key=counts.get)
                if counts[key] >= single_threshold:
                    single_key = key
                    break
        if primary:
            return "sshd-credential-spray", list(segment)
        if single_key is not None:
            return (
                "sshd-single-account-bruteforce",
                [
                    item
                    for item in segment
                    if item["account_key"] == single_key
                ],
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
            include_reports=not bool(
                self.config["report_batching"].get("enabled")
            ),
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
            if self.config["report_batching"].get("enabled"):
                # Enforcement is immediate; provider communication is handled by the hourly
                # CIDR report-batch service. Leave report_status queued.
                continue
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
            except Exception as exc:
                if reporting.get("test_mode"):
                    detail = f"Enrichment unavailable in test mode: {exc}"
                    try:
                        fallback_cidr = candidate_network(str(incident["source_ip"]))
                    except ValueError:
                        fallback_cidr = incident["network_cidr"]
                    enrichment = {
                        "network_cidr": (
                            incident["registered_cidr"]
                            or incident["network_cidr"]
                            or fallback_cidr
                        ),
                        "network_name": None,
                        "asn": incident["asn"],
                        "asn_holder": incident["asn_holder"],
                        "abuse_emails": [],
                        "network_class": incident["network_class"] or "unknown",
                        "_test_enrichment_error": detail,
                    }
                    LOG.warning(
                        "Enrichment failed for %s; continuing in test mode: %s",
                        incident["source_ip"],
                        exc,
                    )
                else:
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
                        test_mode=False,
                    )
                    LOG.warning("Enrichment failed for %s: %s", incident["source_ip"], exc)
                    continue
            self.db.update_incident(
                incident_uuid,
                registered_cidr=enrichment.get("network_cidr"),
                asn=enrichment.get("asn"),
                asn_holder=enrichment.get("asn_holder"),
                network_class=enrichment.get("network_class", "unknown"),
            )
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
                    f"Incident last_seen={incident['last_seen']} predates report_not_before_utc={utc_text(parse_time(cutoff))}",
                )
        legacy = self.config.get("legacy_reporting", {})
        if legacy.get("suppress_matching_markers"):
            marker = self.db.legacy_report_match(str(incident["source_ip"]), str(incident["first_seen"]))
            if marker is not None:
                return (
                    "suppressed",
                    f"Legacy reporter marker already covers {marker['source_ip']} on {marker['report_date']}",
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

    def send_network_report(
        self,
        network_cidr: str,
        report_type: str = "network_escalation",
    ) -> tuple[str, str, str | None]:
        normalized = str(ipaddress.ip_network(network_cidr, strict=False))
        if report_type == "network_escalation" and self.db.network_report_sent(normalized, report_type):
            return "suppressed", "Network escalation report was already sent", None
        if report_type == "network_update" and self.db.network_report_sent_today(normalized, report_type):
            return "suppressed", "A network update was already sent today", None
        case = self.db.conn.execute(
            "SELECT * FROM network_cases WHERE network_cidr=?", (normalized,)
        ).fetchone()
        if case is None:
            raise CollectorError(f"Network case not found: {normalized}")
        if report_type == "network_escalation" and str(case["status"]) != "blocked":
            raise CollectorError("Network escalation mail requires the case to be marked blocked")
        incidents = self.db.network_case_incidents(normalized)
        if not incidents:
            raise CollectorError("Network case has no qualifying incidents")
        representative = incidents[0]
        enrichment = self.enrich(str(representative["source_ip"]))
        recipients = self.report_recipients(enrichment)
        if not recipients:
            detail = "No RDAP abuse email was found for network case"
            self.db.record_network_report(normalized, report_type, "no-contact", None, detail, None)
            return "no-contact", detail, None
        settings = self.config["abuse_reporting"]
        if not settings.get("enabled"):
            return "disabled", "Abuse reporting disabled in configuration", None
        recipient_gate = self.report_recipient_gate(recipients)
        if recipient_gate is not None:
            status, detail, _ = recipient_gate
            self.db.record_network_report(normalized, report_type, status, ", ".join(recipients), detail, None)
            return status, detail, None
        unique_ips = sorted({str(row["source_ip"]) for row in incidents})
        message = EmailMessage()
        message["From"] = str(settings["from"])
        message["To"] = ", ".join(recipients)
        if not settings.get("test_mode") and str(settings.get("admin_copy", "")).strip():
            message["Bcc"] = str(settings["admin_copy"]).strip()
        message["Date"] = email.utils.format_datetime(utc_now())
        message_id = email.utils.make_msgid(domain=str(settings["message_id_domain"]))
        message["Message-ID"] = message_id
        label = " TEST" if settings.get("test_mode") else ""
        action = "blocked" if str(case["status"]) == "blocked" else str(case["status"])
        message["Subject"] = f"{settings['subject_prefix']}{label} Network escalation for {normalized}"
        body = [
            "This is an automated network-level abuse escalation from a self-hosted server operator.",
            "",
            f"Network CIDR: {normalized}",
            f"Network case status: {case['status']}",
            f"Action taken: the CIDR has been {action} by operator policy",
            f"Distinct hostile source IPs: {case['hostile_ips']}",
            f"Qualifying incidents: {case['incident_count']}",
            f"Qualifying hostile events: {case['event_count']}",
            f"Active days: {case['active_days']}",
            f"Observed interval: {case['first_seen'] or 'unknown'} to {case['last_seen'] or 'unknown'}",
            f"Representative hostile IPs: {', '.join(unique_ips[:20])}",
            f"Registered network: {enrichment.get('network_cidr') or 'unknown'}",
            f"Network name: {enrichment.get('network_name') or 'unknown'}",
            f"ASN: {enrichment.get('asn') or 'unknown'} {enrichment.get('asn_holder') or ''}".rstrip(),
            "",
            "Only independently qualifying Argent Sentinel incidents are included in these totals.",
            "Please investigate the responsible systems or customers and take appropriate action.",
        ]
        if settings.get("test_mode"):
            body.extend([
                "",
                "TEST MODE: This report was sent only to the configured recipient override.",
                "No provider abuse contact or administrative Bcc recipient received this message.",
            ])
        message.set_content("\n".join(body) + "\n")
        try:
            result = subprocess.run(
                [str(settings["sendmail_path"]), "-t", "-oi"],
                input=message.as_bytes(), capture_output=True,
                timeout=int(settings["send_timeout_seconds"]), check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            status, detail = "failed", f"sendmail failed: {exc}"
        else:
            if result.returncode == 0:
                status, detail = "sent", f"Network report sent to {', '.join(recipients)}"
            else:
                status = "failed"
                detail = clean_optional(result.stderr.decode("utf-8", "replace"), 1000) or f"sendmail exited {result.returncode}"
        self.db.record_network_report(
            normalized, report_type, status, ", ".join(recipients), detail, message_id
        )
        return status, detail, message_id

    @staticmethod
    def _report_value(row: Any, key: str, default: Any = None) -> Any:
        if isinstance(row, Mapping):
            return row.get(key, default)
        try:
            return row[key]
        except (KeyError, IndexError, TypeError):
            return default

    @staticmethod
    def _report_metadata(row: Any) -> dict[str, Any]:
        raw = Collector._report_value(row, "metadata_json", "{}")
        if isinstance(raw, Mapping):
            return dict(raw)
        try:
            parsed = json.loads(str(raw or "{}"))
        except (TypeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _report_unique(values: Sequence[Any]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for value in values:
            cleaned = clean_optional(value, 2048)
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            result.append(cleaned)
        return result

    @staticmethod
    def _report_host(value: Any) -> str | None:
        cleaned = clean_optional(value, 255)
        if not cleaned or cleaned in {"_", "-"}:
            return None
        if cleaned.startswith("[") and "]" in cleaned:
            cleaned = cleaned[1:cleaned.index("]")]
        elif cleaned.count(":") == 1:
            candidate, port = cleaned.rsplit(":", 1)
            if port.isdigit():
                cleaned = candidate
        return cleaned.rstrip(".").lower() or None

    def _report_target_hosts(
        self,
        evidence: Sequence[Any],
        network_evidence: Sequence[Any],
    ) -> list[str]:
        values: list[Any] = []
        for row in network_evidence:
            values.extend((
                self._report_value(row, "host"),
                self._report_value(row, "server_name"),
            ))
        for row in evidence:
            metadata = self._report_metadata(row)
            values.append(metadata.get("host"))
        hosts: list[str] = []
        seen: set[str] = set()
        for value in values:
            host = self._report_host(value)
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append(host)
        return hosts

    def _configured_public_targets(self, host: str | None = None) -> list[str]:
        configured = self.config["abuse_reporting"].get("public_target_ips", [])
        values: list[Any] = []
        if isinstance(configured, Mapping):
            values.extend(configured.get("*", []) if isinstance(configured.get("*"), list) else [])
            if host:
                host_values = configured.get(host, [])
                values.extend(host_values if isinstance(host_values, list) else [])
        elif isinstance(configured, list):
            values.extend(configured)
        result: list[str] = []
        for value in values:
            try:
                address = ipaddress.ip_address(str(value))
            except ValueError:
                continue
            normalized = str(address)
            if normalized not in result:
                result.append(normalized)
        return result

    def _resolve_public_targets(
        self,
        hosts: Sequence[str],
        observed_destinations: Sequence[Any],
    ) -> tuple[dict[str, dict[str, list[str]]], list[str]]:
        settings = self.config["abuse_reporting"]
        resolution: dict[str, dict[str, list[str]]] = {}
        all_targets: list[str] = []

        def add_target(host: str, value: Any) -> None:
            try:
                address = ipaddress.ip_address(str(value))
            except ValueError:
                return
            if not address.is_global:
                return
            normalized = str(address)
            family = "A" if address.version == 4 else "AAAA"
            bucket = resolution.setdefault(host, {"A": [], "AAAA": []})[family]
            if normalized not in bucket:
                bucket.append(normalized)
            if normalized not in all_targets:
                all_targets.append(normalized)

        for host in hosts:
            for value in self._configured_public_targets(host):
                add_target(host, value)

        for value in self._configured_public_targets(None):
            add_target("*", value)

        if settings.get("resolve_target_dns"):
            for host in hosts:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    pass
                else:
                    add_target(host, host)
                    continue
                try:
                    answers = socket.getaddrinfo(
                        host,
                        None,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    )
                except (OSError, socket.gaierror):
                    continue
                for answer in answers:
                    sockaddr = answer[4]
                    if sockaddr:
                        add_target(host, sockaddr[0])

        for value in observed_destinations:
            try:
                address = ipaddress.ip_address(str(value))
            except ValueError:
                continue
            if address.is_global:
                add_target("(observed destination)", address)

        return resolution, all_targets

    def _select_public_destination(
        self,
        observed_destination: Any,
        host: str | None,
        resolution: Mapping[str, Mapping[str, Sequence[str]]],
        all_targets: Sequence[str],
    ) -> str | None:
        observed: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        if observed_destination not in (None, ""):
            try:
                observed = ipaddress.ip_address(str(observed_destination))
            except ValueError:
                observed = None
        if observed is not None and observed.is_global:
            return str(observed)

        preferred_version = observed.version if observed is not None else None
        candidates: list[str] = []
        for key in (host, "*", "(observed destination)"):
            if not key or key not in resolution:
                continue
            record = resolution[key]
            if preferred_version == 4:
                candidates.extend(record.get("A", []))
            elif preferred_version == 6:
                candidates.extend(record.get("AAAA", []))
            candidates.extend(record.get("A", []))
            candidates.extend(record.get("AAAA", []))
        candidates.extend(all_targets)
        return self._report_unique(candidates)[0] if candidates else None

    def _source_reverse_dns(self, source_ip: str) -> str:
        if not self.config["abuse_reporting"].get("resolve_source_rdns"):
            return "(lookup disabled)"
        try:
            return socket.gethostbyaddr(source_ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            return "(none)"

    def _report_connections(
        self,
        incident: Any,
        evidence: Sequence[Any],
        network_evidence: Sequence[Any],
        resolution: Mapping[str, Mapping[str, Sequence[str]]],
        all_targets: Sequence[str],
    ) -> list[dict[str, Any]]:
        source_ip = str(self._report_value(incident, "source_ip", "unknown"))
        connections: list[dict[str, Any]] = []
        fingerprints: set[tuple[Any, ...]] = set()

        def append_connection(row: Any, *, network: bool) -> None:
            metadata = {} if network else self._report_metadata(row)
            host = self._report_host(
                self._report_value(row, "host")
                or self._report_value(row, "server_name")
                or metadata.get("host")
            )
            observed_destination = self._report_value(row, "destination_ip")
            destination_port = self._report_value(row, "destination_port")
            tls_protocol = self._report_value(row, "tls_protocol")
            application_protocol = self._report_value(row, "application_protocol")
            service = str(
                self._report_value(row, "service") or ""
            ).strip().lower()
            normalized_application = str(
                application_protocol or ""
            ).strip().lower()
            if (
                service == "sshd"
                or normalized_application.startswith("ssh")
            ):
                scheme = "ssh"
            elif (
                tls_protocol
                or destination_port == 443
                or normalized_application.startswith("https")
            ):
                scheme = "https"
            elif (
                service in {"nginx", "wordpress"}
                or normalized_application.startswith("http")
                or self._report_value(row, "request_method")
                or self._report_value(row, "request_uri")
                or self._report_value(row, "request_path")
            ):
                scheme = "http"
            else:
                scheme = normalized_application or None
            request_uri = (
                self._report_value(row, "request_uri")
                if network
                else self._report_value(row, "request_path")
            )
            http_status = (
                self._report_value(row, "http_status")
                if network
                else metadata.get("http_status")
            )
            category = metadata.get("probe_category")
            connection = {
                "occurred_at": clean_optional(
                    self._report_value(row, "occurred_at"), 64
                ),
                "source_ip": clean_optional(
                    self._report_value(row, "source_ip") or source_ip, 64
                ) or source_ip,
                "source_port": self._report_value(row, "source_port"),
                "observed_destination_ip": clean_optional(observed_destination, 64),
                "public_destination_ip": self._select_public_destination(
                    observed_destination, host, resolution, all_targets
                ),
                "destination_port": destination_port,
                "host": host,
                "server_name": self._report_host(
                    self._report_value(row, "server_name")
                ),
                "scheme": scheme,
                "transport_protocol": clean_optional(
                    self._report_value(row, "transport_protocol"), 32
                ),
                "application_protocol": clean_optional(application_protocol, 64),
                "tls_protocol": clean_optional(tls_protocol, 64),
                "request_method": clean_optional(
                    self._report_value(row, "request_method"), 16
                ),
                "request_uri": clean_optional(request_uri, 2048),
                "http_status": http_status,
                "probe_category": clean_optional(category, 128),
                "user_agent": clean_optional(
                    self._report_value(row, "user_agent"), 512
                ),
                "correlation_method": clean_optional(
                    self._report_value(row, "correlation_method"), 64
                ),
            }
            fingerprint = (
                connection["occurred_at"],
                connection["source_ip"],
                connection["source_port"],
                connection["observed_destination_ip"],
                connection["destination_port"],
                connection["request_method"],
                connection["request_uri"],
            )
            if fingerprint in fingerprints:
                return
            fingerprints.add(fingerprint)
            connections.append(connection)

        for row in network_evidence:
            append_connection(row, network=True)
        for row in evidence:
            append_connection(row, network=False)
        return connections

    @staticmethod
    def _count_values(values: Sequence[Any]) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for value in values:
            cleaned = clean_optional(value, 2048)
            if cleaned is None:
                continue
            counts[cleaned] = counts.get(cleaned, 0) + 1
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))

    @staticmethod
    def _format_endpoint(address: Any, port: Any) -> str:
        text = clean_optional(address, 128) or "unknown"
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.version == 6 and port:
            return f"[{text}]:{port}"
        return f"{text}:{port}" if port else text

    def _normalized_evidence_line(self, connection: Mapping[str, Any]) -> str:
        source = self._format_endpoint(
            connection.get("source_ip"), connection.get("source_port")
        )
        destination = self._format_endpoint(
            connection.get("public_destination_ip"),
            connection.get("destination_port"),
        )
        observed = self._format_endpoint(
            connection.get("observed_destination_ip"),
            connection.get("destination_port"),
        )
        request = " ".join(
            value for value in (
                clean_optional(connection.get("request_method"), 16),
                clean_optional(connection.get("request_uri"), 2048),
            ) if value
        ) or "request unavailable"
        pieces = [
            clean_optional(connection.get("occurred_at"), 64) or "time unknown",
            f'src="{source}"',
            f'dst="{destination}"',
        ]
        if connection.get("observed_destination_ip") and (
            connection.get("observed_destination_ip")
            != connection.get("public_destination_ip")
        ):
            pieces.append(f'observed_dst="{observed}"')
        if connection.get("host"):
            pieces.append(f'host="{connection["host"]}"')
        if connection.get("scheme"):
            pieces.append(f'scheme="{connection["scheme"]}"')
        pieces.append(f'request="{request}"')
        if connection.get("http_status") is not None:
            pieces.append(f'status="{connection["http_status"]}"')
        return " ".join(pieces)

    def _xarf_attachment(self, incident: Any, enrichment: Mapping[str, Any], activity: str, connections: Sequence[Mapping[str, Any]], sites: Sequence[str], generated: dt.datetime, evidence_lines: Sequence[str], public_targets: Sequence[str]) -> dict[str, Any]:
        """Build a rule-aware XARF v4.2 connection report."""
        settings = self.config['abuse_reporting']
        source_ip = str(self._report_value(incident, 'source_ip', 'unknown'))
        representative = connections[0] if connections else {}
        from_name, from_address = email.utils.parseaddr(str(settings.get('from', '')))
        operator_name, operator_address = email.utils.parseaddr(str(settings.get('operator_contact', '')))
        reporter_contact = operator_address or from_address
        reporter_domain = clean_optional(settings.get('reporter_org_domain'), 255) or clean_optional(settings.get('message_id_domain'), 255) or ''
        reporter_org = clean_optional(settings.get('reporter_org'), 200) or reporter_domain or str(self.config.get('node', {}).get('fqdn', '')) or 'Server operator'
        if not reporter_contact:
            reporter_contact = f'postmaster@{reporter_domain}'
        reporter = {'org': reporter_org, 'contact': reporter_contact, 'domain': reporter_domain}

        def valid_port(value: Any) -> int | None:
            try:
                port = int(value)
            except (TypeError, ValueError):
                return None
            return port if 1 <= port <= 65535 else None

        def evidence_item(description: str, payload_text: str, content_type: str) -> dict[str, Any]:
            raw = payload_text.encode('utf-8')
            return {'content_type': content_type, 'description': description, 'payload': base64.b64encode(raw).decode('ascii'), 'hash': f'sha256:{hashlib.sha256(raw).hexdigest()}', 'size': len(raw)}
        max_lines = int(settings.get('xarf_max_evidence_lines', 20))
        normalized_lines = list(evidence_lines[:max_lines])
        connection_tuples: list[dict[str, Any]] = []
        for item in connections:
            connection_tuples.append({'timestamp': item.get('occurred_at'), 'source_ip': item.get('source_ip'), 'source_port': valid_port(item.get('source_port')), 'destination_ip': item.get('public_destination_ip'), 'observed_destination_ip': item.get('observed_destination_ip'), 'destination_port': valid_port(item.get('destination_port')), 'destination_fqdn': item.get('host'), 'transport_protocol': clean_optional(item.get('transport_protocol'), 32), 'application_protocol': clean_optional(item.get('application_protocol'), 64), 'tls_protocol': clean_optional(item.get('tls_protocol'), 64), 'scheme': clean_optional(item.get('scheme'), 16), 'request_method': clean_optional(item.get('request_method'), 16), 'request_uri': clean_optional(item.get('request_uri'), 2048), 'http_status': item.get('http_status'), 'probe_category': clean_optional(item.get('probe_category'), 128), 'user_agent': clean_optional(item.get('user_agent'), 1024)})
        tuple_json = json.dumps(connection_tuples, indent=2, sort_keys=True, ensure_ascii=False)
        evidence: list[dict[str, Any]] = [evidence_item('Correlated HTTP connection tuples and request evidence', tuple_json, 'application/json')]
        if normalized_lines:
            evidence.insert(0, evidence_item('Sanitized normalized request evidence', '\n'.join(normalized_lines), 'text/plain'))
        source_port = valid_port(representative.get('source_port'))
        destination_ip = clean_optional(representative.get('public_destination_ip'), 128)
        destination_fqdn = clean_optional(representative.get('host'), 255)
        targeted_ports = sorted({port for item in connections if (port := valid_port(item.get('destination_port'))) is not None})
        targeted_services = self._report_unique([item.get('scheme') for item in connections])
        protocols = self._report_unique([str(item.get('transport_protocol') or '').lower() for item in connections])
        protocol = protocols[0] if len(protocols) == 1 else 'mixed'
        if protocol not in {'tcp', 'udp', 'icmp', 'mixed'}:
            protocol = 'tcp'
        request_paths = self._report_unique([item.get('request_uri') for item in connections])
        methods = self._report_unique([str(item.get('request_method') or '').upper() for item in connections])
        response_codes = sorted({int(item['http_status']) for item in connections if isinstance(item.get('http_status'), int)})
        probe_categories = self._report_unique([item.get('probe_category') for item in connections])
        user_agents = self._report_unique([item.get('user_agent') for item in connections])
        first_seen = clean_optional(self._report_value(incident, 'first_seen'), 64) or utc_text(generated)
        last_seen = clean_optional(self._report_value(incident, 'last_seen'), 64) or first_seen
        incident_uuid = str(self._report_value(incident, 'incident_uuid', uuid.uuid4()))
        rule_id = str(self._report_value(incident, 'rule_id', ''))
        if rule_id.startswith('sshd-'):
            report_type = 'login_attack'
            scan_type = 'credential_attack'
            service = 'ssh'
            tags = ['attack:login', 'service:ssh', f'rule:{rule_id}']
            tuple_description = 'Correlated SSH connection tuples and sanitized authentication evidence'
            normalized_description = 'Sanitized normalized SSH authentication evidence'
        elif rule_id.startswith('wordpress-'):
            report_type = 'login_attack'
            scan_type = 'credential_attack'
            service = 'wordpress'
            tags = ['attack:login', 'service:wordpress', f'rule:{rule_id}']
            tuple_description = 'Correlated WordPress connection tuples and sanitized authentication evidence'
            normalized_description = 'Sanitized normalized WordPress authentication evidence'
        else:
            report_type = 'vulnerability_scan'
            scan_type = 'web_vuln_scan'
            service = 'http'
            tags = ['scan:web_vuln_scan', 'source:nginx', f"rule:{rule_id or 'nginx-hostile-web-probing'}"]
            tuple_description = 'Correlated HTTP connection tuples and request evidence'
            normalized_description = 'Sanitized normalized request evidence'
        if evidence:
            evidence[-1]['description'] = tuple_description
            if normalized_lines:
                evidence[0]['description'] = normalized_description
        report: dict[str, Any] = {'xarf_version': str(settings.get('xarf_version', '4.2.0')), 'report_id': incident_uuid, 'timestamp': first_seen, 'reporter': reporter, 'sender': dict(reporter), 'source_identifier': source_ip, 'category': 'connection', 'type': report_type, 'evidence_source': 'automated_filter', 'scan_type': scan_type, 'service': service, 'protocol': protocol, 'first_seen': first_seen, 'last_seen': last_seen, 'total_requests': max(int(self._report_value(incident, 'event_count', 0) or 0), len(connections), 1), 'evidence': evidence, 'confidence': 1.0, 'description': activity, 'tags': tags, 'affected_sites': list(sites), 'destination_fqdns': list(self._report_unique([item.get('host') for item in connections])), 'public_target_ips': list(public_targets), 'observed_destination_ips': self._report_unique([item.get('observed_destination_ip') for item in connections]), 'registered_network': self._report_value(incident, 'registered_cidr') or enrichment.get('network_cidr'), 'network_name': enrichment.get('network_name'), 'asn': self._report_value(incident, 'asn') or enrichment.get('asn'), 'asn_holder': self._report_value(incident, 'asn_holder') or enrichment.get('asn_holder'), 'probe_categories': probe_categories, 'probed_resources': request_paths, 'http_methods': methods, 'response_codes': response_codes, 'connection_tuples': connection_tuples}
        if source_port is not None:
            report['source_port'] = source_port
        if destination_ip:
            report['destination_ip'] = destination_ip
        if destination_fqdn:
            report['destination_fqdn'] = destination_fqdn
        if targeted_ports:
            report['targeted_ports'] = targeted_ports
        if targeted_services:
            report['targeted_services'] = targeted_services
        if user_agents:
            report['user_agent'] = user_agents[0]
        return report

    def send_abuse_report(self, incident: sqlite3.Row, enrichment: Mapping[str, Any], recipients: Sequence[str]) -> tuple[str, str, str | None]:
        settings = self.config['abuse_reporting']
        if not settings.get('enabled'):
            return ('disabled', 'Abuse reporting disabled in configuration', None)
        if not recipients:
            return ('no-contact', 'No valid abuse-report recipient was supplied', None)
        test_mode = bool(settings.get('test_mode'))
        protection, protection_detail = self.source_protection_status(str(incident['source_ip']))
        production_disposition = f'Source protection check passed: {protection_detail}'
        if protection == 'protected':
            if not test_mode:
                return ('suppressed', protection_detail, None)
            production_disposition = f'Report would normally be suppressed: {protection_detail}'
        elif protection == 'error':
            if not test_mode:
                return ('failed', f'Abuse report withheld: {protection_detail}', None)
            production_disposition = f'Report would normally be withheld because source protection could not be verified: {protection_detail}'
        evidence = self.db.incident_evidence(str(incident['incident_uuid']))
        sites = self.db.incident_sites(str(incident['incident_uuid']))
        network_evidence = self.db.incident_network_evidence(str(incident['incident_uuid']), int(self.config['network_reporting']['max_tuple_evidence']))
        hosts = self._report_target_hosts(evidence, network_evidence)
        observed_destinations = [self._report_value(row, 'destination_ip') for row in [*network_evidence, *evidence] if self._report_value(row, 'destination_ip')]
        resolution, public_targets = self._resolve_public_targets(hosts, observed_destinations)
        connections = self._report_connections(incident, evidence, network_evidence, resolution, public_targets)
        message = EmailMessage()
        message['From'] = str(settings['from'])
        message['To'] = ', '.join(recipients)
        if not test_mode and str(settings.get('admin_copy', '')).strip():
            message['Bcc'] = str(settings['admin_copy']).strip()
        generated = utc_now()
        message['Date'] = email.utils.format_datetime(generated)
        message_id = email.utils.make_msgid(domain=str(settings['message_id_domain']))
        message['Message-ID'] = message_id
        test_label = ' TEST' if test_mode else ''
        rule_id = str(incident['rule_id'])
        if rule_id.startswith('sshd-'):
            activity = 'Automated OpenSSH authentication attacks'
        elif rule_id.startswith('nginx-'):
            activity = 'Automated hostile web probing and exploit scanning'
        else:
            activity = 'Automated WordPress credential spraying'
        message['Subject'] = f"{settings['subject_prefix']}{test_label} {activity} from {incident['source_ip']}"
        source_ip = str(incident['source_ip'])
        reverse_dns = self._source_reverse_dns(source_ip)
        metadata_rows = [self._report_metadata(row) for row in evidence]
        statuses = self._count_values([item.get('http_status') for item in connections if item.get('http_status') is not None])
        categories = self._count_values([metadata.get('probe_category') for metadata in metadata_rows])
        targets = self._count_values([item.get('request_uri') for item in connections])
        agents = self._count_values([item.get('user_agent') or '-' for item in connections])
        total_requests = max(int(incident['event_count']), len(connections))
        count_4xx = sum((1 for item in connections if isinstance(item.get('http_status'), int) and 400 <= int(item['http_status']) <= 499))
        count_5xx = sum((1 for item in connections if isinstance(item.get('http_status'), int) and 500 <= int(item['http_status']) <= 599))
        body: list[str] = []
        if test_mode:
            body.extend(['*** TEST MODE ***', 'This report was sent only to the configured recipient override.', 'No provider abuse contact or administrative Bcc recipient received it.', f'Production disposition: {production_disposition}'])
            enrichment_error = clean_optional(enrichment.get('_test_enrichment_error'), 1000)
            if enrichment_error:
                body.append(f'Enrichment note: {enrichment_error}')
            body.extend(['*** TEST MODE ***', ''])
        body.extend(['Hello,', ''])
        if rule_id.startswith('nginx-'):
            opening = 'I operate the affected web service(s) listed below. The source IP generated automated exploit-scanning traffic against my server, including requests for WordPress backdoor paths, plugin/theme PHP probes, sensitive configuration files, command-style REST probes, and/or other hostile web requests.'
        elif rule_id.startswith('sshd-'):
            opening = 'I operate the affected SSH service listed below. The source IP generated automated authentication attacks against my server.'
        else:
            opening = 'I operate the affected WordPress service(s) listed below. The source IP generated automated credential attacks against my server.'
        attach_xarf = bool(settings.get('attach_xarf', True))
        body.extend([opening, '', 'Please investigate this host/customer and take appropriate action.', '', f'Source IP: {source_ip}', f"Affected site(s): {(', '.join(hosts or sites) if hosts or sites else 'unknown')}", f"Observed timeframe (UTC): {incident['first_seen']} through {incident['last_seen']}", f'Reverse DNS: {reverse_dns}', '', 'Connection details:'])
        if connections:
            for count, connection in enumerate(connections, 1):
                source = self._format_endpoint(connection.get('source_ip'), connection.get('source_port'))
                destination = self._format_endpoint(connection.get('public_destination_ip'), connection.get('destination_port'))
                details = [f'src={source}', f'dst={destination}']
                observed = connection.get('observed_destination_ip')
                if observed and observed != connection.get('public_destination_ip'):
                    details.append('observed_dst=' + self._format_endpoint(observed, connection.get('destination_port')))
                if connection.get('host'):
                    details.append(f"host={connection['host']}")
                if connection.get('scheme'):
                    details.append(f"scheme={connection['scheme']}")
                if connection.get('transport_protocol'):
                    details.append(f"transport={connection['transport_protocol']}")
                body.append(f'  {count:>3}  ' + ' '.join(details))
        else:
            body.append('  (source/destination tuple unavailable)')
        body.extend(['', 'Public target IP resolution:'])
        if resolution:
            for host in sorted((key for key in resolution if not key.startswith('('))):
                record = resolution[host]
                body.append(f'  {host}')
                body.append('    A:    ' + (', '.join(record.get('A', [])) or '(none)'))
                body.append('    AAAA: ' + (', '.join(record.get('AAAA', [])) or '(none)'))
        elif public_targets:
            body.append('  Configured target IPs: ' + ', '.join(public_targets))
        else:
            body.append('  (no public target IP could be determined)')
        body.extend(['', 'Summary:', f'  Total matched/related requests: {total_requests}', f"  Suspicious requests:           {incident['event_count']}", f'  5xx responses:                 {count_5xx}', f'  4xx responses:                 {count_4xx}', f'  Distinct request targets:      {len(targets)}', '', 'Status counts:'])
        body.extend([f'  {status}: {count}' for status, count in statuses] or ['  (unavailable)'])
        body.extend(['', 'Suspicious categories:'])
        body.extend([f'  {category}: {count}' for category, count in categories] or ['  (unavailable)'])
        body.extend(['', 'Top request targets:'])
        body.extend([f'  {count:>5}  {target}' for target, count in targets[:20]] or ['  (unavailable)'])
        body.extend(['', 'User-Agent strings:'])
        body.extend([f'  {count:>5}  {agent}' for agent, count in agents[:20]] or ['  (unavailable)'])
        network_name = clean_optional(enrichment.get('network_name'), 255) or 'unknown'
        asn = incident['asn'] or enrichment.get('asn') or 'unknown'
        asn_holder = clean_optional(incident['asn_holder'] or enrichment.get('asn_holder'), 255) or 'unknown'
        body.extend(['', 'ASN / network lookup:', f'  AS:              {asn}', f"  Registered CIDR: {incident['registered_cidr'] or enrichment.get('network_cidr') or 'unknown'}", f'  Network name:    {network_name}', f'  AS holder:       {asn_holder}', '', 'WHOIS/RDAP abuse contact evidence:', f"  Abuse email(s):  {', '.join(enrichment.get('abuse_emails', [])) or '(none found)'}"])
        raw_enrichment = enrichment.get('raw')
        if isinstance(raw_enrichment, Mapping):
            rdap = raw_enrichment.get('rdap')
            if isinstance(rdap, Mapping):
                body.append(f"  Registry handle: {clean_optional(rdap.get('handle'), 255) or 'unknown'}")
                remarks = rdap.get('remarks')
                if isinstance(remarks, list):
                    descriptions: list[str] = []
                    for remark in remarks:
                        if not isinstance(remark, Mapping):
                            continue
                        value = remark.get('description')
                        if isinstance(value, list):
                            descriptions.extend((item for item in (clean_optional(part, 500) for part in value) if item))
                    for description in descriptions[:5]:
                        body.append(f'  Comment: {description}')
        evidence_lines = [self._normalized_evidence_line(item) for item in connections]
        body.extend(['', 'Sanitized request evidence (normalized from stored event data):', *evidence_lines[:int(settings.get('xarf_max_evidence_lines', 20))], '', 'No passwords, cookies, email addresses, or targeted usernames are included in this report.'])
        if attach_xarf:
            body.append('A machine-readable XARF JSON report is attached as xarf.json.')
        operator_contact = clean_optional(settings.get('operator_contact'), 254)
        if operator_contact:
            body.append(f'Operator contact: {operator_contact}')
        message.set_content('\n'.join(body) + '\n')
        if attach_xarf:
            xarf = self._xarf_attachment(incident, enrichment, activity, connections, hosts or sites, generated, evidence_lines, public_targets)
            message.add_attachment(json.dumps(xarf, indent=2, sort_keys=True, ensure_ascii=False).encode('utf-8'), maintype='application', subtype='json', filename='xarf.json')
        try:
            result = subprocess.run([str(settings['sendmail_path']), '-t', '-oi'], input=message.as_bytes(), capture_output=True, timeout=int(settings['send_timeout_seconds']), check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ('failed', f'sendmail failed: {exc}', message_id)
        if result.returncode != 0:
            detail = clean_optional(result.stderr.decode('utf-8', 'replace'), 1000) or f'sendmail exited {result.returncode}'
            return ('failed', detail, message_id)
        detail = f"Report sent to {', '.join(recipients)}"
        if test_mode:
            detail += f'; test bypass: {production_disposition}'
        return ('sent', detail, message_id)


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


REGISTRY_ABUSE_EMAILS = {
    "abuse@ripe.net", "abuse@arin.net", "abuse@apnic.net",
    "abuse@lacnic.net", "abuse@afrinic.net", "cert@cert.br",
    "search-apnic-not-arin@apnic.net",
}
REGISTRY_EMAIL_DOMAINS = {"ripe.net", "arin.net", "apnic.net", "lacnic.net", "afrinic.net"}


def usable_abuse_email(address: str) -> bool:
    value = address.strip().lower().strip("'\"<>.,;()[]")
    if not valid_email_header(value):
        return False
    if value in REGISTRY_ABUSE_EMAILS:
        return False
    domain = value.rsplit("@", 1)[-1]
    if domain in REGISTRY_EMAIL_DOMAINS:
        return False
    if value.startswith(("search-apnic-", "nobody@", "hostmaster@")):
        return False
    return True


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
                        if usable_abuse_email(address):
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
        "node": collector.config["node"],
        "abuse_context": {
            "enabled": bool(collector.config["abuse_context"]["enabled"]),
            "incoming_globs": collector.config["abuse_context"]["incoming_globs"],
            "fallback_correlation_seconds": collector.config["abuse_context"]["fallback_correlation_seconds"],
        },
        "network_reporting": collector.config["network_reporting"],
        "report_batching": collector.config["report_batching"],
        "sshd_policy": collector.config["sshd_policy"],
        "web_policy": collector.config["web_policy"],
        "legacy_reporting": collector.config["legacy_reporting"],
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
        "network_cases": [dict(row) for row in collector.db.network_cases(100)],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argent Sentinel host collector")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    parser.add_argument("--config", default="/etc/argent-sentinel/collector.json")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Import batches, evaluate policy, and retry actions")
    sub.add_parser("status", help="Print collector state and CIDR candidates")
    sub.add_parser("network-list", help="Print network case records")
    network_report = sub.add_parser("network-report", help="Send a manual network escalation/update report")
    network_report.add_argument("--cidr", required=True)
    network_report.add_argument("--type", default="network_escalation", choices=("network_escalation", "network_update"))
    network_set = sub.add_parser("network-set", help="Set a manual network-case status")
    network_set.add_argument("--cidr", required=True)
    network_set.add_argument(
        "--status", required=True,
        choices=("observing", "review", "escalation-review", "long-block-review", "blocked", "closed"),
    )
    network_set.add_argument("--note", default="")
    network_set.add_argument("--send-report", action="store_true", help="Send the provider escalation after marking blocked")
    legacy_import = sub.add_parser("legacy-import", help="Import legacy nginx-abuse .sent markers")
    legacy_import.add_argument("--state-dir", default="", help="Legacy marker directory")
    migrate = sub.add_parser("migrate", help="Back up and migrate the state database")
    migrate.add_argument("--backup-dir", default="", help="Optional directory for a consistent pre-migration backup")
    sub.add_parser("validate-config", help="Validate configuration and exit")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok", "version": APP_VERSION}, indent=2))
            return 0
        if args.command == "migrate":
            state_path = Path(config["state_db"])
            lock_path = Path(config["lock_file"])
            with process_lock(lock_path):
                backup_path = None
                if args.backup_dir:
                    backup_path = backup_sqlite_database(state_path, Path(args.backup_dir))
                database = StateDB(state_path)
                try:
                    row = database.conn.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()
                    schema_version = int(row[0]) if row else SCHEMA_VERSION
                finally:
                    database.close()
            print(json.dumps({
                "status": "ok",
                "version": APP_VERSION,
                "schema_version": schema_version,
                "database": str(state_path),
                "backup": str(backup_path) if backup_path else None,
            }, indent=2, sort_keys=True))
            return 0
        if args.command in {"status", "network-list", "network-set", "network-report", "legacy-import"}:
            collector = Collector(config)
            try:
                if args.command == "status":
                    print(json.dumps(status_output(collector), indent=2, sort_keys=True))
                elif args.command == "network-list":
                    collector.db.sync_network_cases(config["policy"])
                    print(json.dumps([dict(row) for row in collector.db.network_cases(500)], indent=2, sort_keys=True))
                elif args.command == "network-set":
                    collector.db.set_network_case(args.cidr, args.status, args.note)
                    result: dict[str, Any] = {
                        "network_cidr": str(ipaddress.ip_network(args.cidr, strict=False)),
                        "status": args.status,
                        "note": clean_optional(args.note, 2000),
                        "enforcement_changed": False,
                    }
                    send_report = bool(args.send_report) or (
                        args.status == "blocked"
                        and bool(config["network_reporting"].get("automatic_network_email"))
                    )
                    if send_report:
                        if args.status != "blocked":
                            raise CollectorError("--send-report requires --status blocked")
                        report_status, detail, message_id = collector.send_network_report(
                            args.cidr, "network_escalation"
                        )
                        result["report"] = {
                            "status": report_status, "detail": detail, "message_id": message_id
                        }
                    print(json.dumps(result, indent=2, sort_keys=True))
                elif args.command == "network-report":
                    status, detail, message_id = collector.send_network_report(args.cidr, args.type)
                    print(json.dumps({"status": status, "detail": detail, "message_id": message_id}, indent=2, sort_keys=True))
                    return 0 if status == "sent" else 1
                else:
                    state_dir = Path(args.state_dir or config["legacy_reporting"]["marker_state_dir"])
                    result = collector.db.import_legacy_markers(state_dir)
                    result["state_dir"] = str(state_dir)
                    print(json.dumps(result, indent=2, sort_keys=True))
            finally:
                collector.close()
            return 0
        lock_path = Path(config["lock_file"])
        with process_lock(lock_path):
            collector = Collector(config)
            try:
                collector.run()
                print(json.dumps({"status": "ok", "version": APP_VERSION, "counts": collector.db.counts()}, sort_keys=True))
            finally:
                collector.close()
        return 0
    except CollectorError as exc:
        if (
            args.command == "run"
            and str(exc) == "Another collector process is already running"
        ):
            LOG.info("Collector cycle skipped because the shared lock is busy")
            print(json.dumps({
                "status": "skipped",
                "reason": "lock-busy",
                "version": APP_VERSION,
            }, sort_keys=True))
            return 0
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
