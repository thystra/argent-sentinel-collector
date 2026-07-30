#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/review_processor.py
# Installed: /usr/lib/argent-sentinel/review_processor.py
"""Root-owned processor for audited dashboard review requests."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from typing import Any, Iterator, Mapping
import uuid

from review_queue import (
    CREDENTIAL_REVIEW_ACTIONS,
    CREDENTIAL_SPRAY_RULES,
    NETWORK_REVIEW_ACTIONS,
    REVIEW_ACTIONS,
    install_review_schema,
    network_available_actions,
    utc_text,
)

APP_VERSION = "0.5.3.0"
UTC = dt.timezone.utc
DEFAULTS: dict[str, Any] = {
    "state_db": "/var/lib/argent-sentinel/collector/state.sqlite3",
    "collector_config": "/etc/argent-sentinel/collector.json",
    "lock_file": "/run/argent-sentinel/collector.lock",
    "incoming_dir": "/var/spool/argent-sentinel/review/incoming",
    "processed_dir": "/var/spool/argent-sentinel/review/processed",
    "failed_dir": "/var/spool/argent-sentinel/review/failed",
    "note_max_chars": 2000,
    "operator_max_chars": 128,
    "max_request_bytes": 32768,
}


class ReviewError(RuntimeError):
    pass


def deep_merge(
    base: Mapping[str, Any],
    override: Mapping[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in base.items():
        result[key] = (
            deep_merge(value, {}) if isinstance(value, Mapping) else value
        )
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Path) -> dict[str, Any]:
    try:
        supplied = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReviewError(f"Configuration missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReviewError(f"Invalid configuration JSON: {exc}") from exc
    if not isinstance(supplied, dict):
        raise ReviewError("Configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    for key in (
        "state_db",
        "collector_config",
        "lock_file",
        "incoming_dir",
        "processed_dir",
        "failed_dir",
    ):
        if not str(config.get(key, "")).strip():
            raise ReviewError(f"{key} must be a non-empty path")
    for key in (
        "note_max_chars",
        "operator_max_chars",
        "max_request_bytes",
    ):
        if int(config.get(key, 0)) < 1:
            raise ReviewError(f"{key} must be positive")
    return config


def clean_text(value: Any, maximum: int, field: str) -> str:
    text = str(value or "").strip()
    if "\x00" in text:
        raise ReviewError(f"{field} contains a NUL byte")
    if len(text) > maximum:
        raise ReviewError(f"{field} exceeds {maximum} characters")
    return text


def valid_uuid(value: Any, field: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise ReviewError(f"{field} must be a UUID") from exc
    return str(parsed)


def validate_request(
    raw: Any,
    config: Mapping[str, Any],
) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ReviewError("Request root must be an object")
    request_uuid = valid_uuid(raw.get("request_uuid"), "request_uuid")
    action = clean_text(raw.get("action"), 64, "action")
    if action not in REVIEW_ACTIONS:
        raise ReviewError(f"Unsupported review action: {action!r}")
    operator = clean_text(
        raw.get("operator"),
        int(config["operator_max_chars"]),
        "operator",
    )
    if not operator:
        raise ReviewError("operator is required")
    note = clean_text(
        raw.get("note"),
        int(config["note_max_chars"]),
        "note",
    )
    expected_updated_at = clean_text(
        raw.get("expected_updated_at"),
        64,
        "expected_updated_at",
    )
    if not expected_updated_at:
        raise ReviewError("expected_updated_at is required")
    requested_at = clean_text(raw.get("requested_at"), 64, "requested_at")
    if not requested_at:
        raise ReviewError("requested_at is required")

    target_type = clean_text(raw.get("target_type"), 16, "target_type")
    if not target_type:
        target_type = "network" if raw.get("network_cidr") else "incident"
    if target_type == "incident":
        if action in NETWORK_REVIEW_ACTIONS:
            raise ReviewError("Network action supplied for an incident review")
        incident_uuid = valid_uuid(raw.get("incident_uuid"), "incident_uuid")
        return {
            "request_uuid": request_uuid,
            "target_type": "incident",
            "incident_uuid": incident_uuid,
            "action": action,
            "operator": operator,
            "note": note,
            "expected_updated_at": expected_updated_at,
            "requested_at": requested_at,
        }
    if target_type != "network":
        raise ReviewError(f"Unsupported target_type: {target_type!r}")
    if action not in NETWORK_REVIEW_ACTIONS:
        raise ReviewError("Incident action supplied for a network review")
    try:
        network_cidr = str(
            ipaddress.ip_network(str(raw.get("network_cidr") or ""), strict=False)
        )
    except ValueError as exc:
        raise ReviewError("network_cidr must be a valid CIDR") from exc
    proposal_revision = clean_text(
        raw.get("proposal_revision"), 128, "proposal_revision"
    )
    if not proposal_revision:
        raise ReviewError("proposal_revision is required")
    proposal_cidr = clean_text(raw.get("proposal_cidr"), 128, "proposal_cidr")
    if proposal_cidr:
        try:
            proposal_cidr = str(ipaddress.ip_network(proposal_cidr, strict=False))
        except ValueError as exc:
            raise ReviewError("proposal_cidr must be a valid CIDR") from exc
    if action in {"network-block-180", "network-block-365"} and not note:
        raise ReviewError("CIDR block actions require an operator justification")
    return {
        "request_uuid": request_uuid,
        "target_type": "network",
        "network_cidr": network_cidr,
        "proposal_cidr": proposal_cidr,
        "proposal_revision": proposal_revision,
        "action": action,
        "operator": operator,
        "note": note,
        "expected_updated_at": expected_updated_at,
        "requested_at": requested_at,
    }


@contextlib.contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def open_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA busy_timeout=10000")
    install_review_schema(connection)
    connection.commit()
    return connection


def append_note(existing: Any, note: str, operator: str, applied_at: str) -> str:
    current = str(existing or "").strip()
    if not note:
        return current
    addition = f"[{applied_at} {operator}] {note}"
    return f"{current}\n{addition}".strip()


def action_result(
    action: str,
    previous_report_status: str,
) -> tuple[str, str, str]:
    if action == "acknowledge":
        return previous_report_status, "closed", "acknowledged"
    if action == "retry":
        return "pending", "closed", "retry-requested"
    if action == "suppress":
        return "suppressed", "closed", "operator-suppressed"
    if action == "permanent-no-contact":
        return "suppressed", "closed", "permanent-no-contact"
    if action == "approve-report":
        return "pending", "closed", "credential-spray-approved"
    if action == "keep-suppressed":
        return "suppressed", "closed", "credential-spray-kept-suppressed"
    if action == "duplicate-subsumed":
        return "suppressed", "closed", "duplicate-subsumed"
    if action == "refresh-contact":
        return "no-contact", "closed", "contact-refresh-requested"
    if action == "note":
        return previous_report_status, "open", "note-added"
    raise ReviewError(f"Unsupported action: {action}")

def apply_incident_request(
    connection: sqlite3.Connection,
    request: Mapping[str, str],
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    existing_action = connection.execute(
        "SELECT action_id FROM review_actions WHERE request_uuid = ?",
        (request["request_uuid"],),
    ).fetchone()
    if existing_action is not None:
        return {
            "status": "duplicate",
            "action_id": int(existing_action[0]),
            "request_uuid": request["request_uuid"],
        }
    incident = connection.execute(
        """
        SELECT incident_uuid, source_ip, rule_id, report_status,
               report_detail, updated_at, review_status,
               review_disposition, review_note
        FROM incidents
        WHERE incident_uuid = ?
        """,
        (request["incident_uuid"],),
    ).fetchone()
    if incident is None:
        raise ReviewError("Incident no longer exists")
    if str(incident["updated_at"]) != request["expected_updated_at"]:
        raise ReviewError(
            "Stale review form: incident changed after the snapshot was built"
        )
    action = request["action"]
    if action in CREDENTIAL_REVIEW_ACTIONS:
        detail = str(incident["report_detail"] or "").lower()
        credential_review = (
            str(incident["rule_id"]) in CREDENTIAL_SPRAY_RULES
            and str(incident["report_status"]) == "suppressed"
            and (
                "pending production review" in detail
                or "contact refresh" in detail
                or str(incident["review_disposition"] or "")
                    in {"credential-spray-review", "contact-refreshed"}
            )
        )
        if not credential_review:
            raise ReviewError(
                f"Action {action!r} requires a suppressed credential-spray "
                "review item"
            )
    applied = (now or dt.datetime.now(UTC)).astimezone(UTC)
    applied_epoch = int(applied.timestamp())
    applied_at = utc_text(applied)
    previous_report_status = str(incident["report_status"])
    previous_review_status = str(incident["review_status"] or "open")
    new_report_status, new_review_status, disposition = action_result(
        action,
        previous_report_status,
    )
    review_note = append_note(
        incident["review_note"],
        request["note"],
        request["operator"],
        applied_at,
    )
    report_detail = str(incident["report_detail"] or "").strip()
    action_detail = (
        f"Operator review {disposition} by {request['operator']} at "
        f"{applied_at}"
    )
    if request["note"]:
        action_detail += f": {request['note']}"
    if action in {
        "retry",
        "suppress",
        "permanent-no-contact",
        "approve-report",
        "keep-suppressed",
        "duplicate-subsumed",
        "refresh-contact",
    }:
        report_detail = (
            f"{report_detail}; {action_detail}"
            if report_detail
            else action_detail
        )
    clear_delivery = action in {
        "retry",
        "approve-report",
        "refresh-contact",
    }
    with connection:
        if action == "refresh-contact":
            cache_exists = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'enrichment_cache'
                """
            ).fetchone()
            if cache_exists is not None:
                connection.execute(
                    "DELETE FROM enrichment_cache WHERE source_ip = ?",
                    (str(incident["source_ip"]),),
                )
        connection.execute(
            """
            UPDATE incidents
            SET report_status = ?,
                report_detail = ?,
                next_report_after_epoch = CASE
                    WHEN ? THEN 0
                    ELSE next_report_after_epoch
                END,
                report_recipient = CASE
                    WHEN ? THEN NULL
                    ELSE report_recipient
                END,
                report_message_id = CASE
                    WHEN ? THEN NULL
                    ELSE report_message_id
                END,
                report_sent_epoch = CASE
                    WHEN ? THEN NULL
                    ELSE report_sent_epoch
                END,
                review_status = ?,
                review_disposition = ?,
                review_note = ?,
                review_updated_epoch = ?,
                review_updated_at = ?,
                updated_at = ?
            WHERE incident_uuid = ?
            """,
            (
                new_report_status,
                report_detail or None,
                int(clear_delivery),
                int(clear_delivery),
                int(clear_delivery),
                int(clear_delivery),
                new_review_status,
                disposition,
                review_note or None,
                applied_epoch,
                applied_at,
                applied_at,
                request["incident_uuid"],
            ),
        )
        cursor = connection.execute(
            """
            INSERT INTO review_actions (
                request_uuid, incident_uuid, action, operator, note,
                previous_report_status, new_report_status,
                previous_review_status, new_review_status,
                disposition, requested_at, applied_epoch, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request["request_uuid"],
                request["incident_uuid"],
                action,
                request["operator"],
                request["note"] or None,
                previous_report_status,
                new_report_status,
                previous_review_status,
                new_review_status,
                disposition,
                request["requested_at"],
                applied_epoch,
                applied_at,
            ),
        )
    return {
        "status": "applied",
        "action_id": int(cursor.lastrowid),
        "request_uuid": request["request_uuid"],
        "incident_uuid": request["incident_uuid"],
        "action": action,
        "disposition": disposition,
        "report_status": new_report_status,
        "review_status": new_review_status,
        "applied_at": applied_at,
    }


def load_network_policy(config: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(str(config["collector_config"]))
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReviewError(f"Collector configuration missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReviewError(f"Invalid collector configuration JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReviewError("Collector configuration root must be an object")
    policy = raw.get("policy") if isinstance(raw.get("policy"), dict) else {}
    crowdsec = raw.get("crowdsec") if isinstance(raw.get("crowdsec"), dict) else {}
    trusted = raw.get("trusted_cidrs", [])
    if not isinstance(trusted, list):
        raise ReviewError("trusted_cidrs must be a list")
    return {
        "trusted_cidrs": [str(value) for value in trusted],
        "reason_prefix": str(policy.get("reason_prefix", "argent-sentinel")).rstrip("/"),
        "long_days": int(policy.get("network_long_block_days", 180)),
        "severe_days": int(policy.get("network_severe_block_days", 365)),
        "minimum_ipv4_prefix_length": int(
            policy.get("network_block_min_ipv4_prefix_length", 24)
        ),
        "minimum_ipv6_prefix_length": int(
            policy.get("network_block_min_ipv6_prefix_length", 48)
        ),
        "crowdsec_enabled": bool(crowdsec.get("enabled", False)),
        "cscli_path": str(crowdsec.get("cscli_path", "/usr/bin/cscli")),
        "command_timeout_seconds": int(crowdsec.get("command_timeout_seconds", 20)),
    }


def bounded_detail(value: Any, maximum: int = 2000) -> str:
    text = str(value or "").strip()
    return text[:maximum]


def validate_network_target(
    case_cidr: str,
    proposal_cidr: str,
    policy: Mapping[str, Any],
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        case = ipaddress.ip_network(case_cidr, strict=False)
        proposal = ipaddress.ip_network(proposal_cidr, strict=False)
    except ValueError as exc:
        raise ReviewError(f"Invalid network proposal: {exc}") from exc
    if case.version != proposal.version or not proposal.subnet_of(case):
        raise ReviewError("Proposed CIDR is not contained by the registered case")
    minimum = int(
        policy[
            "minimum_ipv4_prefix_length"
            if proposal.version == 4
            else "minimum_ipv6_prefix_length"
        ]
    )
    if proposal.prefixlen < minimum:
        raise ReviewError(
            f"Proposed CIDR /{proposal.prefixlen} is broader than the "
            f"configured /{minimum} safety boundary"
        )
    for value in policy["trusted_cidrs"]:
        try:
            trusted = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise ReviewError(f"Invalid trusted CIDR in collector config: {value}") from exc
        if trusted.version == proposal.version and trusted.overlaps(proposal):
            raise ReviewError(
                f"Proposed CIDR overlaps trusted network {trusted}"
            )
    return proposal


def crowdsec_decision_items(payload: Any) -> list[Mapping[str, Any]]:
    """Extract decision objects from current and wrapped cscli JSON shapes."""

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if not isinstance(payload, Mapping):
        return []
    lowered = {str(key).lower(): value for key, value in payload.items()}
    if "scope" in lowered and "value" in lowered:
        return [payload]
    result: list[Mapping[str, Any]] = []
    for key in ("decisions", "items", "results", "data"):
        value = lowered.get(key)
        if value is not None:
            result.extend(crowdsec_decision_items(value))
    return result


def crowdsec_range_exists(payload: Any, cidr: str) -> bool:
    target = str(ipaddress.ip_network(cidr, strict=False))
    for item in crowdsec_decision_items(payload):
        lowered = {str(key).lower(): value for key, value in item.items()}
        scope = str(lowered.get("scope") or "").lower()
        value = str(lowered.get("value") or "").strip()
        if scope not in {"range", "ranges"} or not value:
            continue
        try:
            normalized = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
        if normalized == target:
            return True
    return False


def crowdsec_range_decision(
    policy: Mapping[str, Any],
    cidr: str,
    *,
    action: str,
    duration_days: int = 0,
) -> tuple[str, str]:
    if not policy["crowdsec_enabled"]:
        return "dry-run", "CrowdSec enforcement disabled in collector configuration"
    cscli = str(policy["cscli_path"])
    timeout = int(policy["command_timeout_seconds"])
    list_command = [
        cscli,
        "decisions",
        "list",
        "--range",
        cidr,
        "--output",
        "json",
    ]
    try:
        listed = subprocess.run(
            list_command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "failed", f"CrowdSec range lookup failed: {exc}"
    list_output = bounded_detail(listed.stdout + "\n" + listed.stderr)
    if listed.returncode != 0:
        return "failed", list_output or f"cscli list exited {listed.returncode}"
    try:
        parsed = json.loads(listed.stdout or "[]")
    except json.JSONDecodeError:
        return "failed", "CrowdSec range lookup returned invalid JSON"
    existing = crowdsec_range_exists(parsed, cidr)
    if action == "add" and existing:
        return "existing", list_output or "CrowdSec range decision already exists"
    if action == "delete" and not existing:
        return "absent", "No CrowdSec range decision exists"

    if action == "add":
        command = [
            cscli,
            "decisions",
            "add",
            "--range",
            cidr,
            "--duration",
            f"{int(duration_days) * 24}h",
            "--reason",
            f"{policy['reason_prefix']}/network-review-{int(duration_days)}d",
        ]
        success_status = "applied"
    elif action == "delete":
        command = [cscli, "decisions", "delete", "--range", cidr]
        success_status = "removed"
    else:
        raise ReviewError(f"Unsupported CrowdSec range action: {action}")
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "failed", f"CrowdSec range command failed: {exc}"
    output = bounded_detail(result.stdout + "\n" + result.stderr)
    if result.returncode == 0:
        return success_status, output or f"CrowdSec range decision {success_status}"
    lowered = output.lower()
    if action == "add" and ("already" in lowered or "existing" in lowered):
        return "existing", output
    if action == "delete" and ("not found" in lowered or "no decision" in lowered):
        return "absent", output
    return "failed", output or f"cscli exited {result.returncode}"


def apply_network_request(
    connection: sqlite3.Connection,
    request: Mapping[str, str],
    config: Mapping[str, Any],
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    existing_action = connection.execute(
        "SELECT action_id FROM network_review_actions WHERE request_uuid = ?",
        (request["request_uuid"],),
    ).fetchone()
    if existing_action is not None:
        return {
            "status": "duplicate",
            "action_id": int(existing_action[0]),
            "request_uuid": request["request_uuid"],
        }
    case = connection.execute(
        "SELECT * FROM network_cases WHERE network_cidr = ?",
        (request["network_cidr"],),
    ).fetchone()
    if case is None:
        raise ReviewError("Network case no longer exists")
    if str(case["updated_at"]) != request["expected_updated_at"]:
        raise ReviewError(
            "Stale review form: network case changed after the snapshot was built"
        )
    if str(case["proposal_revision"] or "") != request["proposal_revision"]:
        raise ReviewError("Stale review form: proposal revision changed")
    if str(case["proposal_cidr"] or "") != request["proposal_cidr"]:
        raise ReviewError("Stale review form: proposed CIDR changed")
    action = request["action"]
    allowed = network_available_actions(dict(case))
    if action not in allowed:
        raise ReviewError(f"Action {action!r} is not available for this network case")

    policy = load_network_policy(config)
    applied = (now or dt.datetime.now(UTC)).astimezone(UTC)
    applied_epoch = int(applied.timestamp())
    applied_at = utc_text(applied)
    previous_status = str(case["status"] or "review")
    previous_review_status = str(case["review_status"] or "open")
    new_status = previous_status
    new_review_status = previous_review_status
    disposition = str(case["review_disposition"] or "")
    requested_days = 0
    decision_status = str(case["decision_status"] or "")
    decision_detail = str(case["decision_detail"] or "")
    decision_cidr = str(case["decision_cidr"] or "")
    decision_applied_at = case["decision_applied_at"]

    if action in {"network-block-180", "network-block-365"}:
        requested_days = (
            int(policy["long_days"])
            if action == "network-block-180"
            else int(policy["severe_days"])
        )
        expected_days = 180 if action == "network-block-180" else 365
        if requested_days != expected_days:
            raise ReviewError(
                f"Collector policy duration for {action} is {requested_days}, "
                f"expected {expected_days}"
            )
        proposal = validate_network_target(
            str(case["network_cidr"]),
            str(case["proposal_cidr"] or ""),
            policy,
        )
        decision_status, decision_detail = crowdsec_range_decision(
            policy,
            str(proposal),
            action="add",
            duration_days=requested_days,
        )
        decision_cidr = str(proposal)
        if decision_status in {"applied", "existing"}:
            new_status = "blocked"
            new_review_status = "closed"
            disposition = f"cidr-block-{requested_days}d"
            decision_applied_at = applied_at
        else:
            new_review_status = "open"
            disposition = "cidr-block-failed"
    elif action == "network-remove-block":
        target = str(case["decision_cidr"] or case["proposal_cidr"] or "")
        proposal = validate_network_target(
            str(case["network_cidr"]),
            target,
            policy,
        )
        decision_status, decision_detail = crowdsec_range_decision(
            policy,
            str(proposal),
            action="delete",
        )
        decision_cidr = str(proposal)
        if decision_status in {"removed", "absent"}:
            new_status = "review"
            new_review_status = "open"
            disposition = "cidr-block-removed"
            requested_days = 0
            decision_applied_at = applied_at
        else:
            new_review_status = "open"
            disposition = "cidr-remove-failed"
    elif action == "network-observe":
        new_status = "observing"
        new_review_status = "closed"
        disposition = "keep-observing"
    elif action == "network-reject":
        new_status = "closed"
        new_review_status = "closed"
        disposition = "recommendation-rejected"
    elif action == "network-note":
        disposition = "note-added"
    else:
        raise ReviewError(f"Unsupported network action: {action}")

    review_note = append_note(
        case["review_note"],
        request["note"],
        request["operator"],
        applied_at,
    )
    with connection:
        connection.execute(
            """
            UPDATE network_cases
            SET status = ?, review_status = ?, review_disposition = ?,
                review_note = ?, operator_note = ?,
                review_updated_epoch = ?, review_updated_at = ?,
                decision_cidr = ?, decision_status = ?, decision_detail = ?,
                decision_duration_days = ?, decision_applied_at = ?,
                updated_at = ?
            WHERE network_cidr = ?
            """,
            (
                new_status,
                new_review_status,
                disposition,
                review_note or None,
                review_note or None,
                applied_epoch,
                applied_at,
                decision_cidr or None,
                decision_status or None,
                decision_detail or None,
                requested_days,
                decision_applied_at,
                applied_at,
                request["network_cidr"],
            ),
        )
        cursor = connection.execute(
            """
            INSERT INTO network_review_actions (
                request_uuid, network_cidr, proposal_cidr, proposal_revision,
                action, operator, note, previous_status, new_status,
                previous_review_status, new_review_status, disposition,
                requested_duration_days, decision_status, decision_detail,
                requested_at, applied_epoch, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request["request_uuid"],
                request["network_cidr"],
                request["proposal_cidr"] or None,
                request["proposal_revision"],
                action,
                request["operator"],
                request["note"] or None,
                previous_status,
                new_status,
                previous_review_status,
                new_review_status,
                disposition,
                requested_days,
                decision_status or None,
                decision_detail or None,
                request["requested_at"],
                applied_epoch,
                applied_at,
            ),
        )
    return {
        "status": "applied",
        "action_id": int(cursor.lastrowid),
        "request_uuid": request["request_uuid"],
        "network_cidr": request["network_cidr"],
        "proposal_cidr": request["proposal_cidr"],
        "action": action,
        "disposition": disposition,
        "case_status": new_status,
        "review_status": new_review_status,
        "decision_status": decision_status,
        "applied_at": applied_at,
    }


def apply_request(
    connection: sqlite3.Connection,
    request: Mapping[str, str],
    config: Mapping[str, Any] | None = None,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    if str(request.get("target_type") or "incident") == "network":
        return apply_network_request(
            connection,
            request,
            config or DEFAULTS,
            now=now,
        )
    return apply_incident_request(connection, request, now=now)

def read_request(path: Path, config: Mapping[str, Any]) -> dict[str, str]:
    if path.stat().st_size > int(config["max_request_bytes"]):
        raise ReviewError("Review request exceeds configured size limit")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReviewError(f"Invalid request JSON: {exc}") from exc
    return validate_request(raw, config)


def archive_request(
    source: Path,
    destination_dir: Path,
    result: Mapping[str, Any],
) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = destination_dir / source.name
    os.replace(source, destination)
    result_path = destination.with_suffix(destination.suffix + ".result.json")
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(destination, 0o600)
    os.chmod(result_path, 0o600)
    return destination


def process_requests(config: Mapping[str, Any]) -> dict[str, Any]:
    incoming = Path(str(config["incoming_dir"]))
    processed = Path(str(config["processed_dir"]))
    failed = Path(str(config["failed_dir"]))
    incoming.mkdir(parents=True, exist_ok=True, mode=0o730)
    paths = sorted(incoming.glob("*.json"))
    counts = {"found": len(paths), "applied": 0, "duplicate": 0, "failed": 0}
    results: list[dict[str, Any]] = []
    if not paths:
        return {"status": "ok", "version": APP_VERSION, "counts": counts}

    with exclusive_lock(Path(str(config["lock_file"]))):
        connection = open_database(Path(str(config["state_db"])))
        try:
            for path in paths:
                try:
                    request = read_request(path, config)
                    result = apply_request(connection, request, config)
                    counts[str(result["status"])] += 1
                    archive_request(path, processed, result)
                    results.append(result)
                except (OSError, sqlite3.Error, ReviewError) as exc:
                    counts["failed"] += 1
                    result = {
                        "status": "failed",
                        "file": path.name,
                        "error": str(exc),
                    }
                    try:
                        archive_request(path, failed, result)
                    except OSError:
                        pass
                    results.append(result)
        finally:
            connection.close()
    return {
        "status": "ok" if counts["failed"] == 0 else "partial",
        "version": APP_VERSION,
        "counts": counts,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Process audited Argent Sentinel dashboard review actions"
    )
    parser.add_argument(
        "--config",
        default="/etc/argent-sentinel/review-processor.json",
    )
    parser.add_argument(
        "command",
        choices=("process", "validate-config"),
        nargs="?",
        default="process",
    )
    args = parser.parse_args(argv)
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok", "version": APP_VERSION}))
            return 0
        result = process_requests(config)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] in {"ok", "partial"} else 1
    except (OSError, sqlite3.Error, ReviewError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# EOF: /home/alan/src/argent-sentinel-collector/src/review_processor.py
