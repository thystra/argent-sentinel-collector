#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/wordpress_sites.py
# Installed: /usr/lib/argent-sentinel/wordpress_sites.py
"""Inventory WordPress sites visible to the Argent Sentinel collector."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Sequence


def parse_expected(values: Sequence[str]) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for value in values:
        if "=" not in value:
            raise ValueError(
                f"--expect must use DOMAIN=SITE_ID, received {value!r}"
            )
        domain, site_id = value.split("=", 1)
        domain = domain.strip()
        site_id = site_id.strip()
        if not domain or not site_id:
            raise ValueError(
                f"--expect must use DOMAIN=SITE_ID, received {value!r}"
            )
        parsed.append((domain, site_id))
    return parsed


def inventory(
    database: Path,
    drop_root: Path,
    expected: Sequence[tuple[str, str]],
) -> list[dict[str, Any]]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        batch_rows = {
            str(row["site_id"]): dict(row)
            for row in connection.execute(
                """SELECT site_id,
                          COUNT(*) AS batch_count,
                          MIN(imported_at) AS first_import,
                          MAX(imported_at) AS last_import,
                          GROUP_CONCAT(DISTINCT source_host) AS batch_hosts
                   FROM batches
                   GROUP BY site_id"""
            )
        }
        event_rows = {
            str(row["site_id"]): dict(row)
            for row in connection.execute(
                """SELECT site_id,
                          COUNT(*) AS event_count,
                          MIN(occurred_at) AS first_event,
                          MAX(occurred_at) AS last_event,
                          GROUP_CONCAT(DISTINCT source_host) AS event_hosts
                   FROM events
                   WHERE service = 'wordpress'
                   GROUP BY site_id"""
            )
        }
    finally:
        connection.close()

    if expected:
        sites = list(expected)
    else:
        site_ids = sorted(set(batch_rows) | set(event_rows))
        sites = [(site_id, site_id) for site_id in site_ids]

    output: list[dict[str, Any]] = []
    for domain, site_id in sites:
        batches = batch_rows.get(site_id, {})
        events = event_rows.get(site_id, {})
        incoming = drop_root / site_id / "incoming"
        batch_count = int(batches.get("batch_count") or 0)
        event_count = int(events.get("event_count") or 0)
        drop_exists = incoming.is_dir()
        if batch_count or event_count:
            status = "seen"
        elif drop_exists:
            status = "provisioned-no-import"
        else:
            status = "missing"
        output.append(
            {
                "domain": domain,
                "site_id": site_id,
                "status": status,
                "batch_count": batch_count,
                "event_count": event_count,
                "first_import": batches.get("first_import"),
                "last_import": batches.get("last_import"),
                "first_event": events.get("first_event"),
                "last_event": events.get("last_event"),
                "source_hosts": sorted(
                    {
                        value
                        for field in (
                            batches.get("batch_hosts"),
                            events.get("event_hosts"),
                        )
                        for value in str(field or "").split(",")
                        if value
                    }
                ),
                "incoming_directory": str(incoming),
                "incoming_exists": drop_exists,
            }
        )
    return output


def table(rows: Sequence[dict[str, Any]]) -> str:
    columns = (
        ("domain", 26),
        ("site_id", 31),
        ("status", 23),
        ("batch_count", 7),
        ("event_count", 7),
        ("last_import", 22),
        ("last_event", 22),
    )
    header = " ".join(name.upper().ljust(width) for name, width in columns)
    separator = " ".join("-" * width for _name, width in columns)
    lines = [header, separator]
    for row in rows:
        lines.append(
            " ".join(
                str(
                    row.get(name, "")
                    if row.get(name) is not None
                    else "-"
                )[:width].ljust(width)
                for name, width in columns
            )
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        default="/var/lib/argent-sentinel/collector/state.sqlite3",
    )
    parser.add_argument(
        "--drop-root",
        default="/var/lib/argent-sentinel/drop/wordpress",
    )
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="DOMAIN=SITE_ID",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
    )
    args = parser.parse_args(argv)
    try:
        expected = parse_expected(args.expect)
        rows = inventory(
            Path(args.database),
            Path(args.drop_root),
            expected,
        )
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        print(table(rows))
    return 1 if any(row["status"] == "missing" for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())

# EOF: /home/alan/src/argent-sentinel-collector/src/wordpress_sites.py
