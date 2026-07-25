#!/usr/bin/env python3
"""Send the daily Argent Sentinel operator review digest."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
from email.message import EmailMessage
import email.utils
import fcntl
import ipaddress
import json
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
from typing import Any, Iterator, Mapping, Sequence
import urllib.parse

APP_VERSION = "0.4.10.1"
UTC = dt.timezone.utc
CRAWLER_IDENTITIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("crawler:meta-externalagent", re.compile(r"(?:meta-externalagent|facebookexternalhit)", re.I)),
    ("crawler:google", re.compile(r"(?:Googlebot|Google-InspectionTool)", re.I)),
    ("crawler:microsoft-bing", re.compile(r"(?:bingbot|BingPreview)", re.I)),
    ("crawler:apple", re.compile(r"Applebot", re.I)),
    ("crawler:duckduckgo", re.compile(r"DuckDuckBot", re.I)),
)


class DigestError(RuntimeError):
    pass


def parse_address(value: Any) -> str:
    _, address = email.utils.parseaddr(str(value or "").strip())
    return address if "@" in address else ""


def source_prefix(source_ip: str, ipv4_prefix: int = 24, ipv6_prefix: int = 48) -> str:
    address = ipaddress.ip_address(source_ip)
    prefix = ipv4_prefix if address.version == 4 else ipv6_prefix
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def client_identity(user_agent: str | None) -> str:
    value = str(user_agent or "-").strip()
    for identity, pattern in CRAWLER_IDENTITIES:
        if pattern.search(value):
            return identity
    lowered = value.lower()
    if value in ("", "-"):
        return "client:missing-user-agent"
    if "curl/" in lowered:
        return "client:curl"
    if "wget/" in lowered:
        return "client:wget"
    if "chrome/" in lowered or "chromium/" in lowered:
        return "browser:chromium-family"
    if "firefox/" in lowered:
        return "browser:firefox-family"
    if "safari/" in lowered:
        return "browser:safari-family"
    return "client:" + re.sub(r"\s+", " ", value)[:160]


def aggregate_429(
    rows: Sequence[Mapping[str, Any]],
    ipv4_prefix: int = 24,
    ipv6_prefix: int = 48,
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        prefix = source_prefix(str(row["source_ip"]), ipv4_prefix, ipv6_prefix)
        agent = str(row["user_agent"] or "-")
        identity = client_identity(agent)
        key = (prefix, identity)
        group = groups.setdefault(
            key,
            {
                "prefix": prefix,
                "identity": identity,
                "events": 0,
                "source_ips": set(),
                "hosts": set(),
                "paths": set(),
                "user_agents": set(),
                "first_epoch": int(row["occurred_epoch"]),
                "last_epoch": int(row["occurred_epoch"]),
            },
        )
        group["events"] += 1
        group["source_ips"].add(str(row["source_ip"]))
        group["user_agents"].add(agent)
        if row["host"]:
            group["hosts"].add(str(row["host"]))
        if row["request_uri"]:
            group["paths"].add(str(row["request_uri"]))
        group["first_epoch"] = min(group["first_epoch"], int(row["occurred_epoch"]))
        group["last_epoch"] = max(group["last_epoch"], int(row["occurred_epoch"]))
    result: list[dict[str, Any]] = []
    for group in groups.values():
        result.append(
            {
                **group,
                "distinct_ips": len(group["source_ips"]),
                "distinct_hosts": len(group["hosts"]),
                "distinct_paths": len(group["paths"]),
                "duration_seconds": group["last_epoch"] - group["first_epoch"],
            }
        )
    return sorted(
        result,
        key=lambda item: (item["events"], item["distinct_ips"], item["duration_seconds"]),
        reverse=True,
    )


def review_reasons(item: Mapping[str, Any], review: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    if (
        int(item["events"]) >= int(review.get("min_429_events", 10))
        and int(item["distinct_ips"]) >= int(review.get("min_429_distinct_ips", 3))
        and int(item["duration_seconds"]) >= int(review.get("min_429_duration_seconds", 300))
    ):
        reasons.append("distributed-prefix-pressure")
    if (
        int(item["events"]) >= int(review.get("min_429_single_ip_events", 50))
        and int(item["distinct_paths"]) >= int(review.get("min_429_single_ip_paths", 25))
        and int(item["duration_seconds"]) >= int(review.get("min_429_single_ip_duration_seconds", 600))
    ):
        reasons.append("sustained-path-enumeration")
    return reasons


@contextmanager
def open_review_database(config: Mapping[str, Any]) -> Iterator[sqlite3.Connection]:
    lock_path = Path(str(config.get("lock_file") or "/run/argent-sentinel/collector.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with lock_path.open("a+b") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_SH)
        database_path = Path(str(config["state_db"])).resolve()
        quoted = urllib.parse.quote(str(database_path), safe="/")
        connection = sqlite3.connect(f"file:{quoted}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA query_only=ON")
        try:
            yield connection
        finally:
            connection.close()
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def query_rows(connection: sqlite3.Connection, sql: str, parameters: Sequence[Any]) -> list[sqlite3.Row]:
    return list(connection.execute(sql, parameters))


def resolve_recipient(config: Mapping[str, Any]) -> str:
    review = config.get("daily_review", {})
    direct = parse_address(review.get("recipient"))
    if direct:
        return direct
    reporting = config.get("abuse_reporting", {})
    if reporting.get("test_mode"):
        override = parse_address(reporting.get("recipient_override"))
        if override:
            return override
    return parse_address(reporting.get("admin_copy"))


def render_digest(
    config: Mapping[str, Any],
    connection: sqlite3.Connection,
    start_epoch: int,
    end_epoch: int,
) -> str:
    review = config["daily_review"]
    rows_429 = query_rows(
        connection,
        """SELECT occurred_epoch, occurred_at, source_ip, host, request_uri, user_agent
           FROM network_observations
           WHERE http_status=429 AND occurred_epoch>=? AND occurred_epoch<?
           ORDER BY occurred_epoch""",
        (start_epoch, end_epoch),
    )
    grouped = aggregate_429(
        rows_429,
        int(review.get("ipv4_prefix", 24)),
        int(review.get("ipv6_prefix", 48)),
    )
    candidates = []
    for item in grouped:
        reasons = review_reasons(item, review)
        if reasons:
            candidates.append({**item, "review_reasons": reasons})

    fail2ban = query_rows(
        connection,
        """SELECT occurred_at, source_ip, metadata_json FROM events
           WHERE service='fail2ban' AND event_type='fail2ban_ban'
             AND occurred_epoch>=? AND occurred_epoch<? ORDER BY occurred_epoch""",
        (start_epoch, end_epoch),
    )
    incidents = query_rows(
        connection,
        """SELECT rule_id, report_status, COUNT(*) AS count FROM incidents
           WHERE last_seen_epoch>=? AND last_seen_epoch<?
           GROUP BY rule_id, report_status ORDER BY count DESC, rule_id""",
        (start_epoch, end_epoch),
    )
    attempts = query_rows(
        connection,
        """SELECT status, COUNT(*) AS count FROM report_attempts
           WHERE attempted_epoch>=? AND attempted_epoch<?
             AND status IN ('failed','deferred','suppressed','no-contact')
           GROUP BY status ORDER BY count DESC""",
        (start_epoch, end_epoch),
    )
    network_cases = query_rows(
        connection,
        """SELECT network_cidr, status, hostile_ips, incident_count, event_count,
                  active_days, first_seen, last_seen, suggested_block_days,
                  grouping_basis, asns, network_classes, operator_note
           FROM network_cases
           WHERE status IN ('review','escalation-review','long-block-review','blocked')
           ORDER BY CASE status WHEN 'blocked' THEN 0 WHEN 'long-block-review' THEN 1
                                WHEN 'escalation-review' THEN 2 ELSE 3 END,
                    hostile_ips DESC, last_seen DESC LIMIT ?""",
        (int(review.get("max_network_rows", 20)),),
    )

    body = [
        "Argent Sentinel daily operator review",
        f"Version: {APP_VERSION}",
        f"UTC interval: {dt.datetime.fromtimestamp(start_epoch, UTC).isoformat()} through {dt.datetime.fromtimestamp(end_epoch, UTC).isoformat()}",
        "",
        "HTTP 429 pressure:",
        f"  Total rejected requests: {len(rows_429)}",
        f"  Prefix/client-identity groups: {len(grouped)}",
        f"  Groups requiring review: {len(candidates)}",
    ]
    for item in candidates[: int(review.get("max_rows", 20))]:
        body.extend(
            [
                "",
                f"  Prefix: {item['prefix']}",
                f"  Client identity: {item['identity']}",
                f"  Review reason(s): {', '.join(item['review_reasons'])}",
                f"  Events: {item['events']}",
                f"  Distinct source IPs: {item['distinct_ips']}",
                f"  Duration seconds: {item['duration_seconds']}",
                f"  Distinct paths: {item['distinct_paths']}",
                f"  Hosts: {', '.join(sorted(item['hosts'])) or '-'}",
                "  Representative User-Agent(s):",
            ]
        )
        body.extend(f"    {agent}" for agent in sorted(item["user_agents"])[:3])
        body.append("  Sample targets:")
        body.extend(f"    {path}" for path in sorted(item["paths"])[:5])

    jail_counts: dict[str, int] = {}
    for row in fail2ban:
        try:
            metadata = json.loads(str(row["metadata_json"] or "{}"))
        except json.JSONDecodeError:
            metadata = {}
        jail = str(metadata.get("jail") or "unknown")
        jail_counts[jail] = jail_counts.get(jail, 0) + 1
    body.extend(["", "Fail2ban bans recorded:"])
    body.extend(
        (f"  {jail}: {count}" for jail, count in sorted(jail_counts.items(), key=lambda item: (-item[1], item[0])))
        if jail_counts else ["  none"]
    )
    body.extend(["", "Incidents observed:"])
    body.extend(
        (f"  {row['rule_id']} / {row['report_status']}: {row['count']}" for row in incidents)
        if incidents else ["  none"]
    )
    body.extend(["", "Report attempts needing review:"])
    body.extend((f"  {row['status']}: {row['count']}" for row in attempts) if attempts else ["  none"])
    body.extend(["", "CIDR/network cases requiring review:"])
    if network_cases:
        for row in network_cases:
            duration = int(row["suggested_block_days"] or 0)
            body.extend(
                [
                    "",
                    f"  Network: {row['network_cidr']}",
                    f"  Status: {row['status']}",
                    f"  Grouping basis: {row['grouping_basis']}",
                    f"  Hostile IPs: {row['hostile_ips']}",
                    f"  Incidents/events: {row['incident_count']} / {row['event_count']}",
                    f"  Active days: {row['active_days']}",
                    f"  Suggested block: {duration} days" if duration else "  Suggested block: none",
                    f"  ASN(s): {row['asns'] or '-'}",
                    f"  Network classes: {row['network_classes'] or '-'}",
                    f"  First/last seen: {row['first_seen'] or '-'} / {row['last_seen'] or '-'}",
                    f"  Operator note: {row['operator_note'] or '-'}",
                ]
            )
    else:
        body.append("  none")
    body.extend(
        [
            "",
            "HTTP 429 and CIDR long-block entries are review telemetry only.",
            "The digest does not create a firewall ban or provider report",
            "from a 429 response or recommendation alone.",
        ]
    )
    return "\n".join(body) + "\n"


def send_digest(config: Mapping[str, Any], body: str) -> str:
    review = config["daily_review"]
    recipient = resolve_recipient(config)
    if not recipient:
        raise DigestError("No daily_review recipient, test recipient_override, or admin_copy")
    reporting = config.get("abuse_reporting", {})
    sender = parse_address(reporting.get("from")) or f"root@{socket.getfqdn()}"
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = email.utils.format_datetime(dt.datetime.now().astimezone())
    message["Message-ID"] = email.utils.make_msgid(
        domain=str(reporting.get("message_id_domain") or socket.getfqdn())
    )
    message["Subject"] = (
        f"{review.get('subject_prefix', '[Argent Sentinel Review]')} "
        f"{dt.datetime.now().astimezone().date().isoformat()}"
    )
    message.set_content(body)
    sendmail = str(review.get("sendmail_path") or reporting.get("sendmail_path") or "/usr/sbin/sendmail")
    result = subprocess.run(
        [sendmail, "-t", "-oi"],
        input=message.as_bytes(),
        capture_output=True,
        timeout=int(review.get("send_timeout_seconds", 30)),
        check=False,
    )
    if result.returncode != 0:
        raise DigestError(
            result.stderr.decode("utf-8", "replace").strip()
            or f"sendmail exited {result.returncode}"
        )
    return recipient


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/argent-sentinel/collector.json")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise DigestError("Configuration root must be an object")
        review = config.get("daily_review", {})
        if not review.get("enabled"):
            print(json.dumps({"status": "disabled", "version": APP_VERSION}))
            return 0
        end_epoch = int(dt.datetime.now(UTC).timestamp())
        start_epoch = end_epoch - int(review.get("lookback_hours", 24)) * 3600
        with open_review_database(config) as connection:
            body = render_digest(config, connection, start_epoch, end_epoch)
        if args.stdout:
            print(body, end="")
            return 0
        recipient = send_digest(config, body)
    except (OSError, json.JSONDecodeError, sqlite3.Error, DigestError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps({"status": "sent", "recipient": recipient, "version": APP_VERSION}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
