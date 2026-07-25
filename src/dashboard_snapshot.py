#!/usr/bin/env python3
"""Build a sanitized read-only dashboard snapshot for Argent Sentinel."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import email.utils
import fcntl
import grp
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Iterator, Mapping, Sequence
import urllib.parse

import review_digest

APP_VERSION = "0.5.0.1"
UTC = dt.timezone.utc

DEFAULTS: dict[str, Any] = {
    "state_db": "/var/lib/argent-sentinel/collector/state.sqlite3",
    "lock_file": "/run/argent-sentinel/collector.lock",
    "snapshot_file": "/var/lib/argent-sentinel/dashboard/snapshot.json",
    "snapshot_group": "www-data",
    "lookback_hours": 24,
    "max_rows": 50,
    "traffic_sites_config": "/etc/argent-sentinel/traffic-sites.json",
    "awstats_root": "/var/lib/argent-sentinel/dashboard/awstats",
}


class SnapshotError(RuntimeError):
    pass


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in base.items():
        result[key] = deep_merge(value, {}) if isinstance(value, Mapping) else value
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotError(f"Configuration not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SnapshotError(f"Configuration root must be an object: {path}")
    return value


def load_config(path: Path) -> dict[str, Any]:
    return deep_merge(DEFAULTS, load_json(path))


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    value = value or utc_now()
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@contextmanager
def open_database(config: Mapping[str, Any]) -> Iterator[sqlite3.Connection]:
    lock_path = Path(str(config["lock_file"]))
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with lock_path.open("a+b") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_SH)
        database_path = Path(str(config["state_db"])).resolve()
        quoted = urllib.parse.quote(str(database_path), safe="/")
        connection = sqlite3.connect(
            f"file:{quoted}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA query_only=ON")
        try:
            yield connection
        finally:
            connection.close()
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def rows(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in connection.execute(sql, parameters)]
    except sqlite3.OperationalError:
        return []


def scalar(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
) -> int:
    try:
        row = connection.execute(sql, parameters).fetchone()
    except sqlite3.OperationalError:
        return 0
    if row is None:
        return 0
    try:
        return int(row[0] or 0)
    except (TypeError, ValueError):
        return 0


def load_sites(path: Path, awstats_root: Path) -> list[dict[str, Any]]:
    try:
        config = load_json(path)
    except SnapshotError:
        return []
    result: list[dict[str, Any]] = []
    sites = config.get("sites", [])
    if not isinstance(sites, list):
        return []
    for site in sites:
        if not isinstance(site, Mapping):
            continue
        site_id = str(site.get("id") or "").strip()
        domain = str(site.get("domain") or "").strip()
        if not site_id or not domain:
            continue
        report = awstats_root / site_id / f"awstats.{site_id}.html"
        result.append(
            {
                "id": site_id,
                "domain": domain,
                "aliases": [
                    str(value)
                    for value in site.get("aliases", [])
                    if str(value).strip()
                ],
                "report_available": report.is_file(),
                "report_mtime": (
                    utc_text(
                        dt.datetime.fromtimestamp(
                            report.stat().st_mtime,
                            UTC,
                        )
                    )
                    if report.is_file()
                    else None
                ),
                "url": f"/awstats/{urllib.parse.quote(site_id)}/awstats.{urllib.parse.quote(site_id)}.html",
            }
        )
    return sorted(result, key=lambda item: item["domain"])


def build_snapshot(config: Mapping[str, Any]) -> dict[str, Any]:
    end_epoch = int(utc_now().timestamp())
    start_epoch = end_epoch - int(config["lookback_hours"]) * 3600
    max_rows = max(1, min(500, int(config["max_rows"])))

    with open_database(config) as connection:
        overview = {
            "events": scalar(
                connection,
                "SELECT COUNT(*) FROM events WHERE occurred_epoch >= ?",
                (start_epoch,),
            ),
            "observations": scalar(
                connection,
                "SELECT COUNT(*) FROM network_observations "
                "WHERE occurred_epoch >= ?",
                (start_epoch,),
            ),
            "http_429": scalar(
                connection,
                "SELECT COUNT(*) FROM network_observations "
                "WHERE occurred_epoch >= ? AND http_status = 429",
                (start_epoch,),
            ),
            "incidents": scalar(
                connection,
                "SELECT COUNT(*) FROM incidents WHERE last_seen_epoch >= ?",
                (start_epoch,),
            ),
            "reports_sent": scalar(
                connection,
                "SELECT COUNT(*) FROM report_attempts "
                "WHERE attempted_epoch >= ? AND status = 'sent'",
                (start_epoch,),
            ),
            "reports_failed": scalar(
                connection,
                "SELECT COUNT(*) FROM report_attempts "
                "WHERE attempted_epoch >= ? "
                "AND status IN ('failed','deferred','no-contact')",
                (start_epoch,),
            ),
        }

        incident_rules = rows(
            connection,
            """
            SELECT rule_id, report_status, COUNT(*) AS count,
                   SUM(event_count) AS events,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen
            FROM incidents
            WHERE last_seen_epoch >= ?
            GROUP BY rule_id, report_status
            ORDER BY count DESC, rule_id
            LIMIT ?
            """,
            (start_epoch, max_rows),
        )
        recent_incidents = rows(
            connection,
            """
            SELECT incident_uuid, source_ip, rule_id, first_seen, last_seen,
                   event_count, distinct_accounts, site_count,
                   registered_cidr, network_cidr, asn, asn_holder,
                   network_class, decision_status, report_status,
                   report_detail
            FROM incidents
            WHERE last_seen_epoch >= ?
            ORDER BY last_seen_epoch DESC
            LIMIT ?
            """,
            (start_epoch, max_rows),
        )
        report_attempts = rows(
            connection,
            """
            SELECT attempted_at, recipient, status, detail, test_mode,
                   message_id, incident_uuid
            FROM report_attempts
            WHERE attempted_epoch >= ?
            ORDER BY attempted_epoch DESC
            LIMIT ?
            """,
            (start_epoch, max_rows),
        )
        fail2ban = rows(
            connection,
            """
            SELECT
                COALESCE(
                    json_extract(metadata_json, '$.jail'),
                    'unknown'
                ) AS jail,
                COUNT(*) AS count,
                COUNT(DISTINCT source_ip) AS source_ips,
                MIN(occurred_at) AS first_seen,
                MAX(occurred_at) AS last_seen
            FROM events
            WHERE service = 'fail2ban'
              AND event_type = 'fail2ban_ban'
              AND occurred_epoch >= ?
            GROUP BY jail
            ORDER BY count DESC, jail
            LIMIT ?
            """,
            (start_epoch, max_rows),
        )
        network_cases = rows(
            connection,
            """
            SELECT network_cidr, status, hostile_ips, incident_count,
                   event_count, active_days, first_seen, last_seen,
                   suggested_block_days, grouping_basis, asns,
                   network_classes, operator_note, updated_at
            FROM network_cases
            ORDER BY
                CASE status
                    WHEN 'blocked' THEN 0
                    WHEN 'long-block-review' THEN 1
                    WHEN 'escalation-review' THEN 2
                    WHEN 'review' THEN 3
                    ELSE 4
                END,
                hostile_ips DESC,
                last_seen DESC
            LIMIT ?
            """,
            (max_rows,),
        )
        repeated_sources = rows(
            connection,
            """
            WITH activity AS (
                SELECT source_ip, occurred_epoch, occurred_at,
                       service AS source_type,
                       site_id AS host
                FROM events
                WHERE source_ip IS NOT NULL
                  AND occurred_epoch >= ?
                UNION ALL
                SELECT source_ip, occurred_epoch, occurred_at,
                       'nginx-observation' AS source_type,
                       COALESCE(host, server_name, '-') AS host
                FROM network_observations
                WHERE source_ip IS NOT NULL
                  AND occurred_epoch >= ?
            )
            SELECT source_ip,
                   COUNT(*) AS hits,
                   COUNT(DISTINCT source_type) AS source_types,
                   COUNT(DISTINCT host) AS hosts,
                   GROUP_CONCAT(DISTINCT source_type) AS seen_in,
                   MIN(occurred_at) AS first_seen,
                   MAX(occurred_at) AS last_seen
            FROM activity
            GROUP BY source_ip
            ORDER BY hits DESC, last_seen DESC
            LIMIT ?
            """,
            (start_epoch, start_epoch, max_rows),
        )
        top_user_agents = rows(
            connection,
            """
            SELECT COALESCE(user_agent, '-') AS user_agent,
                   COUNT(*) AS requests,
                   COUNT(DISTINCT source_ip) AS source_ips,
                   COUNT(DISTINCT COALESCE(host, server_name, '-')) AS hosts,
                   SUM(CASE WHEN http_status = 429 THEN 1 ELSE 0 END) AS limited,
                   SUM(CASE WHEN http_status IN (403, 444) THEN 1 ELSE 0 END) AS denied,
                   MIN(occurred_at) AS first_seen,
                   MAX(occurred_at) AS last_seen
            FROM network_observations
            WHERE occurred_epoch >= ?
            GROUP BY COALESCE(user_agent, '-')
            ORDER BY requests DESC
            LIMIT ?
            """,
            (start_epoch, max_rows),
        )
        crawler_rows = rows(
            connection,
            """
            SELECT occurred_epoch, source_ip, host, request_uri, user_agent
            FROM network_observations
            WHERE occurred_epoch >= ?
              AND http_status = 429
            ORDER BY occurred_epoch
            """,
            (start_epoch,),
        )

    crawler_groups = review_digest.aggregate_429(crawler_rows)
    for item in crawler_groups:
        item["source_ips"] = sorted(item["source_ips"])[:10]
        item["hosts"] = sorted(item["hosts"])[:10]
        item["paths"] = sorted(item["paths"])[:10]
        item["user_agents"] = sorted(item["user_agents"])[:5]
        item["review_reasons"] = review_digest.review_reasons(
            item,
            {
                "min_429_events": 10,
                "min_429_distinct_ips": 3,
                "min_429_duration_seconds": 300,
                "min_429_single_ip_events": 50,
                "min_429_single_ip_paths": 25,
                "min_429_single_ip_duration_seconds": 600,
            },
        )

    awstats_root = Path(str(config["awstats_root"]))
    sites = load_sites(
        Path(str(config["traffic_sites_config"])),
        awstats_root,
    )
    database_path = Path(str(config["state_db"]))
    return {
        "version": APP_VERSION,
        "generated_at": utc_text(),
        "window": {
            "hours": int(config["lookback_hours"]),
            "start_epoch": start_epoch,
            "end_epoch": end_epoch,
            "start": utc_text(dt.datetime.fromtimestamp(start_epoch, UTC)),
            "end": utc_text(dt.datetime.fromtimestamp(end_epoch, UTC)),
        },
        "overview": overview,
        "incident_rules": incident_rules,
        "recent_incidents": recent_incidents,
        "report_attempts": report_attempts,
        "fail2ban": fail2ban,
        "network_cases": network_cases,
        "repeated_sources": repeated_sources,
        "top_user_agents": top_user_agents,
        "crawler_groups": crawler_groups[:max_rows],
        "awstats_sites": sites,
        "health": {
            "database": str(database_path),
            "database_exists": database_path.is_file(),
            "database_mtime": (
                utc_text(
                    dt.datetime.fromtimestamp(
                        database_path.stat().st_mtime,
                        UTC,
                    )
                )
                if database_path.is_file()
                else None
            ),
        },
    }


def atomic_write_json(
    path: Path,
    value: Mapping[str, Any],
    group_name: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    payload = (
        json.dumps(value, indent=2, sort_keys=True, default=str)
        + "\n"
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
    os.chmod(temporary, 0o640)
    try:
        group_id = grp.getgrnam(group_name).gr_gid
    except KeyError:
        group_id = -1
    if group_id >= 0:
        os.chown(temporary, 0, group_id)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="/etc/argent-sentinel/dashboard.json",
    )
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(Path(args.config))
        snapshot = build_snapshot(config)
        if args.stdout:
            print(json.dumps(snapshot, indent=2, sort_keys=True, default=str))
            return 0
        atomic_write_json(
            Path(str(config["snapshot_file"])),
            snapshot,
            str(config["snapshot_group"]),
        )
    except (
        OSError,
        sqlite3.Error,
        SnapshotError,
        ValueError,
    ) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "snapshot": str(config["snapshot_file"]),
                "version": APP_VERSION,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
