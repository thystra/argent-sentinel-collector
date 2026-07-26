#!/usr/bin/env python3
"""Export HTTP 429 Nginx access-log entries as Sentinel observations."""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import uuid
from typing import Any, Mapping

APP_VERSION = "0.5.0.5"
UTC = dt.timezone.utc

ACCESS_RE = re.compile(
    r'^(?P<remote>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"(?P<extra>.*)$'
)
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"')


class ExportError(RuntimeError):
    pass


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_port(value: str | None) -> int | None:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def parse_ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def parse_access_line(
    line: str,
    *,
    source_host: str,
    log_path: str,
    device: int,
    inode: int,
    byte_offset: int,
) -> dict[str, Any] | None:
    match = ACCESS_RE.match(line.rstrip("\r\n"))
    if not match or int(match.group("status")) != 429:
        return None
    try:
        occurred = dt.datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    fields = dict(KV_RE.findall(match.group("extra")))
    source_ip = parse_ip(fields.get("src_ip")) or parse_ip(match.group("remote"))
    if source_ip is None:
        return None
    parts = match.group("request").split(" ", 2)
    method = parts[0] if parts else ""
    request_uri = parts[1] if len(parts) >= 2 else ""
    protocol = parts[2] if len(parts) >= 3 else ""
    scheme = fields.get("scheme", "")
    host = fields.get("host") or fields.get("server_name") or ""
    server_name = fields.get("server_name") or host

    return {
        "occurred_at": utc_text(occurred),
        "source_host": source_host,
        "source_ip": source_ip,
        "source_port": parse_port(fields.get("src_port")),
        "destination_ip": parse_ip(fields.get("dst_ip")),
        "destination_port": parse_port(fields.get("dst_port")),
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "tls_protocol": "TLS" if scheme.lower() == "https" else None,
        "host": host or None,
        "server_name": server_name or None,
        "request_method": method or None,
        "request_uri": request_uri or None,
        "http_status": 429,
        "user_agent": match.group("user_agent") or None,
        "rate_limit_review": True,
        "request_protocol": protocol,
        "scheme": scheme,
        "bytes_sent": match.group("bytes"),
        "referer": match.group("referer"),
        "log_path": log_path,
        "log_device": device,
        "log_inode": inode,
        "log_offset": byte_offset,
    }


def atomic_write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def cursor_path(cursor_dir: Path, log_path: Path) -> Path:
    key = hashlib.sha256(str(log_path).encode("utf-8")).hexdigest()
    return cursor_dir / f"{key}.json"


def load_cursor(path: Path) -> dict[str, int]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return {name: int(value[name]) for name in ("device", "inode", "offset")}
    except (FileNotFoundError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {}


def scan_log(
    path: Path,
    *,
    source_host: str,
    cursor_dir: Path,
    initial_tail_bytes: int,
    max_lines: int,
    max_read_bytes: int,
    max_line_bytes: int,
) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    stat_result = path.stat()
    prior = load_cursor(cursor_path(cursor_dir, path))
    same_file = (
        prior.get("device") == stat_result.st_dev
        and prior.get("inode") == stat_result.st_ino
        and 0 <= prior.get("offset", -1) <= stat_result.st_size
    )
    start = prior["offset"] if same_file else max(0, stat_result.st_size - initial_tail_bytes)
    observations: list[dict[str, Any]] = []
    lines_read = bytes_read = 0
    with path.open("rb") as handle:
        handle.seek(start)
        if start:
            handle.readline(max_line_bytes + 1)
        while lines_read < max_lines and bytes_read < max_read_bytes:
            offset = handle.tell()
            raw = handle.readline(max_line_bytes + 1)
            if not raw:
                break
            lines_read += 1
            bytes_read += len(raw)
            if len(raw) > max_line_bytes and not raw.endswith(b"\n"):
                while raw and not raw.endswith(b"\n"):
                    raw = handle.readline(max_line_bytes + 1)
                continue
            item = parse_access_line(
                raw.decode("utf-8", "replace"),
                source_host=source_host,
                log_path=str(path),
                device=stat_result.st_dev,
                inode=stat_result.st_ino,
                byte_offset=offset,
            )
            if item is not None:
                observations.append(item)
        end_offset = handle.tell()
    return observations, {
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
        "offset": end_offset,
    }, lines_read


def write_batches(drop_dir: Path, observations: list[dict[str, Any]], limit: int) -> int:
    count = 0
    for offset in range(0, len(observations), limit):
        payload = "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
            for item in observations[offset : offset + limit]
        )
        destination = drop_dir / (
            f"nginx-429-{utc_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4()}.jsonl"
        )
        atomic_write(destination, payload.encode("utf-8"), 0o640)
        count += 1
    return count


def discover_logs(patterns: list[str]) -> list[Path]:
    found: set[Path] = set()
    for pattern in patterns:
        for value in glob.glob(pattern):
            path = Path(value)
            try:
                if path.is_file() and not path.is_symlink():
                    found.add(path.resolve())
            except OSError:
                continue
    return sorted(found, key=str)


def export(config: Mapping[str, Any]) -> dict[str, Any]:
    settings = config.get("nginx_429_ingest", {})
    if not settings.get("enabled"):
        return {"status": "disabled", "reason": "nginx_429_ingest disabled"}
    if not config.get("abuse_context", {}).get("enabled"):
        return {"status": "disabled", "reason": "abuse_context must be enabled"}
    source_host = str(config.get("node", {}).get("id", "")).strip()
    if not source_host:
        raise ExportError("node.id is required")

    cursor_dir = Path(str(settings["cursor_dir"]))
    drop_dir = Path(str(settings["drop_dir"]))
    cursor_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    drop_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    logs = discover_logs([str(item) for item in settings.get("log_globs", [])])

    total_lines = total_observations = output_files = 0
    for log_path in logs:
        observations, state, lines = scan_log(
            log_path,
            source_host=source_host,
            cursor_dir=cursor_dir,
            initial_tail_bytes=int(settings.get("initial_tail_bytes", 64 * 1024 * 1024)),
            max_lines=int(settings.get("max_lines_per_file", 200000)),
            max_read_bytes=int(settings.get("max_read_bytes_per_file", 64 * 1024 * 1024)),
            max_line_bytes=int(settings.get("max_line_bytes", 65536)),
        )
        output_files += write_batches(
            drop_dir, observations, int(settings.get("max_observations_per_file", 2000))
        )
        atomic_write(
            cursor_path(cursor_dir, log_path),
            (json.dumps(state, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
        total_lines += lines
        total_observations += len(observations)

    return {
        "status": "ok",
        "logs": len(logs),
        "lines_read": total_lines,
        "observations": total_observations,
        "output_files": output_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/argent-sentinel/collector.json")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ExportError("Configuration root must be an object")
        result = export(config)
    except (OSError, json.JSONDecodeError, ExportError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps({"version": APP_VERSION, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
