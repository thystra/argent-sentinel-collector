#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/reporting_view.py
# Installed: /usr/lib/argent-sentinel/reporting_view.py
"""Shared bounded-report grouping and dashboard projection helpers."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import sqlite3
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

UTC = dt.timezone.utc
REPORTABLE_STATES = ("pending", "failed", "deferred", "disabled", "no-contact")


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    current = (value or utc_now()).astimezone(UTC).replace(microsecond=0)
    return current.isoformat().replace("+00:00", "Z")


def report_family(rule_id: str) -> str:
    if rule_id.startswith("sshd-"):
        return "sshd"
    if rule_id.startswith("nginx-"):
        return "web"
    return "wordpress"


def _network(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if value in (None, ""):
        return None
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def bounded_report_networks(
    source_ip: str,
    registered_cidr: Any,
    fallback_cidr: Any,
    grouping: Mapping[str, Any],
) -> dict[str, Any]:
    """Return an evidence-sized batch prefix while preserving ownership scope."""

    address = ipaddress.ip_address(source_ip)
    minimum = int(
        grouping[
            "minimum_ipv4_prefix_length"
            if address.version == 4
            else "minimum_ipv6_prefix_length"
        ]
    )
    maximum = address.max_prefixlen
    if minimum < 0 or minimum > maximum:
        raise ValueError(
            f"Invalid minimum prefix length {minimum} for IPv{address.version}"
        )

    registered = _network(registered_cidr)
    if registered is not None and (
        registered.version != address.version or address not in registered
    ):
        registered = None

    fallback = _network(fallback_cidr)
    if fallback is not None and (
        fallback.version != address.version or address not in fallback
    ):
        fallback = None

    broad_registered = bool(
        registered is not None and registered.prefixlen < minimum
    )

    if registered is not None and registered.prefixlen >= minimum:
        batch = registered
        basis = "registered"
    elif registered is not None:
        batch = ipaddress.ip_network(
            f"{address}/{minimum}",
            strict=False,
        )
        basis = "bounded-registered"
    elif fallback is not None and fallback.prefixlen >= minimum:
        batch = fallback
        basis = "fallback"
    elif fallback is not None:
        batch = ipaddress.ip_network(
            f"{address}/{minimum}",
            strict=False,
        )
        basis = "bounded-fallback"
    else:
        default_prefix = 24 if address.version == 4 else 64
        selected_prefix = max(minimum, default_prefix)
        batch = ipaddress.ip_network(
            f"{address}/{selected_prefix}",
            strict=False,
        )
        basis = "candidate"

    return {
        "batch_cidr": str(batch),
        "registered_cidr": str(registered) if registered is not None else None,
        "broad_registered_allocation": broad_registered,
        "grouping_basis": basis,
        "minimum_prefix_length": minimum,
    }


def next_hourly_run(
    value: dt.datetime | None = None,
    *,
    minute: int = 5,
) -> str:
    current = (value or utc_now()).astimezone(UTC)
    candidate = current.replace(
        minute=minute,
        second=0,
        microsecond=0,
    )
    if candidate <= current:
        candidate += dt.timedelta(hours=1)
    return utc_text(candidate)


def atomic_write_state(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    payload = (
        json.dumps(value, indent=2, sort_keys=True, default=str) + "\n"
    ).encode("utf-8")
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.",
        dir=path.parent,
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(temporary, 0o640)
        if os.geteuid() == 0:
            os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_optional_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def _status_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        str(row["report_status"]): int(row["count"])
        for row in connection.execute(
            """SELECT report_status, COUNT(*) AS count
               FROM incidents
               GROUP BY report_status
               ORDER BY report_status"""
        )
    }


def _queued_groups(
    connection: sqlite3.Connection,
    batching: Mapping[str, Any],
    max_rows: int,
    now_epoch: int,
) -> list[dict[str, Any]]:
    marks = ",".join("?" for _ in REPORTABLE_STATES)
    cutoff_epoch = now_epoch - int(batching["grace_minutes"]) * 60
    rows = list(
        connection.execute(
            f"""SELECT incident_uuid, source_ip, rule_id, first_seen, last_seen,
                       event_count, registered_cidr, network_cidr,
                       report_recipient, report_status, report_detail,
                       next_report_after_epoch, asn, asn_holder
                FROM incidents
                WHERE report_status IN ({marks})
                  AND COALESCE(next_report_after_epoch, 0) <= ?
                  AND last_seen_epoch <= ?
                ORDER BY last_seen_epoch ASC, created_at ASC
                LIMIT ?""",
            (
                *REPORTABLE_STATES,
                now_epoch,
                cutoff_epoch,
                max(1, min(5000, int(batching["max_candidate_incidents"]))),
            ),
        )
    )
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    grouping = batching["grouping"]
    for row in rows:
        projected = bounded_report_networks(
            str(row["source_ip"]),
            row["registered_cidr"],
            row["network_cidr"],
            grouping,
        )
        recipient = str(row["report_recipient"] or "").strip()
        key = (
            str(projected["batch_cidr"]),
            report_family(str(row["rule_id"])),
            recipient,
        )
        group = grouped.setdefault(
            key,
            {
                "batch_cidr": projected["batch_cidr"],
                "registered_allocations": set(),
                "broad_registered_allocation": False,
                "grouping_basis": projected["grouping_basis"],
                "family": key[1],
                "recipients": recipient or "(resolved during batch preparation)",
                "incident_count": 0,
                "event_count": 0,
                "source_ips": set(),
                "rules": set(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        if projected["registered_cidr"]:
            group["registered_allocations"].add(
                projected["registered_cidr"]
            )
        group["broad_registered_allocation"] = bool(
            group["broad_registered_allocation"]
            or projected["broad_registered_allocation"]
        )
        group["incident_count"] += 1
        group["event_count"] += int(row["event_count"] or 0)
        group["source_ips"].add(str(row["source_ip"]))
        group["rules"].add(str(row["rule_id"]))
        first_seen = str(row["first_seen"])
        last_seen = str(row["last_seen"])
        group["first_seen"] = (
            first_seen
            if group["first_seen"] is None
            else min(str(group["first_seen"]), first_seen)
        )
        group["last_seen"] = (
            last_seen
            if group["last_seen"] is None
            else max(str(group["last_seen"]), last_seen)
        )

    result: list[dict[str, Any]] = []
    for group in grouped.values():
        item = dict(group)
        item["registered_allocations"] = sorted(
            group["registered_allocations"]
        )
        item["source_ips"] = sorted(
            group["source_ips"],
            key=ipaddress.ip_address,
        )[:25]
        item["rules"] = sorted(group["rules"])
        result.append(item)
    result.sort(
        key=lambda item: (
            not bool(item["broad_registered_allocation"]),
            -int(item["incident_count"]),
            str(item["batch_cidr"]),
        )
    )
    return result[:max_rows]


def _recent_messages(
    connection: sqlite3.Connection,
    max_rows: int,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            """SELECT message_id,
                      GROUP_CONCAT(DISTINCT recipient) AS recipients,
                      COUNT(DISTINCT incident_uuid) AS incident_count,
                      MIN(attempted_at) AS attempted_at,
                      GROUP_CONCAT(DISTINCT status) AS statuses,
                      MAX(detail) AS detail
               FROM report_attempts
               WHERE message_id IS NOT NULL
               GROUP BY message_id
               ORDER BY MAX(attempt_id) DESC
               LIMIT ?""",
            (max_rows,),
        )
    ]


def _ban_only_suppressions(
    connection: sqlite3.Connection,
    max_rows: int,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            """SELECT source_ip, rule_id, registered_cidr, network_cidr,
                      asn, asn_holder, last_seen, report_detail
               FROM incidents
               WHERE report_status = 'suppressed'
                 AND report_detail LIKE 'ban-only reporting policy matched%'
               ORDER BY last_seen_epoch DESC
               LIMIT ?""",
            (max_rows,),
        )
    ]


def build_reporting_snapshot(
    connection: sqlite3.Connection,
    collector_config: Mapping[str, Any],
    state_file: Path,
    max_rows: int,
    *,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    reporting = collector_config.get("abuse_reporting", {})
    batching = collector_config.get("report_batching", {})
    current_epoch = int(
        now_epoch
        if now_epoch is not None
        else utc_now().timestamp()
    )
    run_state = load_optional_json(state_file)
    return {
        "mode": (
            "test"
            if bool(reporting.get("test_mode"))
            else "production"
            if bool(reporting.get("enabled"))
            else "disabled"
        ),
        "reporting_enabled": bool(reporting.get("enabled")),
        "batching_enabled": bool(batching.get("enabled")),
        "production_cutoff": str(
            reporting.get("report_not_before_utc", "")
        ),
        "grouping": dict(batching.get("grouping", {})),
        "ban_only": dict(batching.get("ban_only", {})),
        "status_counts": _status_counts(connection),
        "queued_groups": _queued_groups(
            connection,
            batching,
            max_rows,
            current_epoch,
        )
        if batching.get("enabled") and batching.get("grouping")
        else [],
        "recent_messages": _recent_messages(connection, max_rows),
        "ban_only_suppressions": _ban_only_suppressions(
            connection,
            max_rows,
        ),
        "last_run": run_state,
        "next_scheduled_at": (
            run_state.get("next_scheduled_at")
            or next_hourly_run(
                dt.datetime.fromtimestamp(current_epoch, UTC)
            )
        ),
    }

# EOF: /home/alan/src/argent-sentinel-collector/src/reporting_view.py
