#!/usr/bin/env python3
"""Export local Fail2ban ban notices as immutable Sentinel event batches."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid
from typing import Any, Mapping, Sequence

APP_VERSION = "0.4.10"
UTC = dt.timezone.utc
BAN_RE = re.compile(r"\[(?P<jail>[A-Za-z0-9_.:-]+)\]\s+Ban\s+(?P<ip>\S+)")


class ExportError(RuntimeError):
    pass


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    value = value or utc_now()
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def parse_time(row: Mapping[str, Any]) -> dt.datetime:
    try:
        return dt.datetime.fromtimestamp(
            int(str(row.get("__REALTIME_TIMESTAMP"))) / 1_000_000,
            UTC,
        )
    except (TypeError, ValueError, OverflowError):
        return utc_now()


def parse_ban_row(row: Mapping[str, Any], node_id: str) -> dict[str, Any] | None:
    message = str(row.get("MESSAGE", ""))
    match = BAN_RE.search(message)
    if not match:
        return None
    try:
        source_ip = str(ipaddress.ip_address(match.group("ip")))
    except ValueError:
        return None
    jail = match.group("jail")
    cursor = str(row.get("__CURSOR", ""))
    identity = cursor or f"{row.get('__REALTIME_TIMESTAMP', '')}\0{message}"
    return {
        "event_uuid": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"argent-sentinel:fail2ban:{node_id}:{identity}",
            )
        ),
        "occurred_at": utc_text(parse_time(row)),
        "recorded_at": utc_text(),
        "event_type": "fail2ban_ban",
        "outcome": "blocked",
        "source_ip": source_ip,
        "transport_protocol": "TCP",
        "application_protocol": "FAIL2BAN",
        "metadata": {
            "jail": jail,
            "action": "ban",
            "journal_unit": "fail2ban.service",
        },
    }


def journal_rows(settings: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    cursor_path = Path(str(settings["cursor_file"]))
    command = [
        "journalctl",
        "--no-pager",
        "--output=json",
        "--show-cursor",
        "-u",
        str(settings.get("unit", "fail2ban.service")),
    ]
    cursor = cursor_path.read_text(encoding="utf-8").strip() if cursor_path.exists() else ""
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since=-{int(settings.get('initial_lookback_minutes', 60))}min")
    result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    if result.returncode != 0:
        raise ExportError(result.stderr.strip() or f"journalctl exited {result.returncode}")
    rows: list[dict[str, Any]] = []
    final_cursor: str | None = None
    for line in result.stdout.splitlines():
        if line.startswith("-- cursor:"):
            final_cursor = line.split(":", 1)[1].strip() or None
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows, final_cursor


def build_batches(
    node_id: str,
    fqdn: str,
    events: Sequence[Mapping[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    batches: list[dict[str, Any]] = []
    for offset in range(0, len(events), limit):
        batches.append(
            {
                "schema_version": 1,
                "batch_uuid": str(uuid.uuid4()),
                "created_at": utc_text(),
                "source": {
                    "host": node_id,
                    "site_id": f"fail2ban-{node_id}",
                    "site_url": f"fail2ban://{fqdn or node_id}/",
                    "service": "fail2ban",
                    "plugin_version": APP_VERSION,
                },
                "events": list(events[offset : offset + limit]),
            }
        )
    return batches


def export(config: Mapping[str, Any]) -> dict[str, int]:
    settings = config.get("fail2ban_ingest", {})
    if not settings.get("enabled"):
        return {"journal_rows": 0, "ban_events": 0, "batches": 0}
    node = config.get("node", {})
    node_id = str(node.get("id", "")).strip()
    if not node_id:
        raise ExportError("node.id is required")
    rows, final_cursor = journal_rows(settings)
    events = [
        event
        for row in rows
        if (event := parse_ban_row(row, node_id)) is not None
    ]
    batches = build_batches(
        node_id,
        str(node.get("fqdn", "")).strip(),
        events,
        int(settings.get("max_events_per_batch", 500)),
    )
    drop_dir = Path(str(settings["drop_dir"]))
    for batch in batches:
        target = drop_dir / (
            f"fail2ban-{node_id}-{utc_now():%Y%m%dT%H%M%SZ}-"
            f"{batch['batch_uuid']}.json"
        )
        atomic_write(
            target,
            (json.dumps(batch, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            0o640,
        )
    if final_cursor:
        atomic_write(
            Path(str(settings["cursor_file"])),
            (final_cursor + "\n").encode(),
            0o600,
        )
    return {
        "journal_rows": len(rows),
        "ban_events": len(events),
        "batches": len(batches),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/argent-sentinel/collector.json")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ExportError("Configuration root must be an object")
        counts = export(config)
    except (OSError, json.JSONDecodeError, ExportError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps({"status": "ok", **counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
