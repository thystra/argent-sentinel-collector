#!/usr/bin/env python3
# /home/alan/src/argent-sentinel-collector/src/watchdogs/php_fpm.py
"""Observe-only PHP-FPM functional health watchdog."""

from __future__ import annotations

import os
from pathlib import Path
import re
import time
from typing import Any, Mapping
from urllib.parse import urlparse

from watchdog_runtime import command_ok, run_command

EXIT_RE = re.compile(r"exited with code 0 after ([0-9.]+) seconds from start")
EPOLL_TEXT = "epoll: unable to remove fd"


def validate(config: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(config.get("mode", "")) != "observe":
        errors.append("PHP-FPM watchdog must remain in observe mode in this release")
    if int(config.get("interval_seconds", 0)) < 60:
        errors.append("interval_seconds must be at least 60")
    if not isinstance(config.get("probes", []), list):
        errors.append("probes must be a list")
    if config.get("enabled"):
        command = Path(str(config.get("php_fpm_command", "/usr/sbin/php-fpm8.5")))
        if not command.is_file():
            errors.append(f"PHP-FPM command does not exist: {command}")
        for required in ("/usr/bin/curl", "/usr/bin/ps", "/usr/bin/ss"):
            if not Path(required).is_file():
                errors.append(f"required command does not exist: {required}")
    return errors


def _systemd_properties(service: str) -> dict[str, Any]:
    result = run_command(
        [
            "/usr/bin/systemctl",
            "show",
            service,
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=MemoryCurrent",
            "--property=TasksCurrent",
        ],
        timeout=15,
    )
    values: dict[str, Any] = {"command": result}
    for line in str(result.get("stdout", "")).splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    for key in ("MainPID", "MemoryCurrent", "TasksCurrent"):
        try:
            values[key] = int(values.get(key, 0))
        except (TypeError, ValueError):
            values[key] = 0
    return values


def _zombies() -> int:
    result = run_command(["/usr/bin/ps", "-eo", "stat=,comm="], timeout=15)
    if not command_ok(result):
        return -1
    return sum(
        1
        for line in str(result.get("stdout", "")).splitlines()
        if line.strip().startswith("Z") and "php-fpm" in line
    )


def _maximum_socket_queue(prefix: str) -> int:
    result = run_command(["/usr/bin/ss", "-lxn"], timeout=15)
    if not command_ok(result):
        return -1
    maximum = 0
    for line in str(result.get("stdout", "")).splitlines():
        if prefix not in line or ".sock" not in line:
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            maximum = max(maximum, int(fields[2]))
        except ValueError:
            continue
    return maximum


def _event_mechanism(command: str) -> tuple[str, dict[str, Any]]:
    result = run_command([command, "-tt"], timeout=20)
    text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    match = re.search(r"events\.mechanism\s*=\s*([A-Za-z0-9_-]+)", text)
    return (match.group(1).lower() if match else "unknown"), result


def _read_log_delta(path: Path, previous: Mapping[str, Any]) -> tuple[dict[str, int], dict[str, int]]:
    try:
        stat = path.stat()
    except OSError:
        return {"code0": 0, "short": 0, "epoll": 0}, {"inode": 0, "offset": 0}
    cursor = previous.get("runtime", {}).get("log_cursor", {})
    try:
        old_inode = int(cursor.get("inode", 0))
        old_offset = int(cursor.get("offset", 0))
    except (TypeError, ValueError):
        old_inode, old_offset = 0, 0
    if old_inode == 0:
        return {"code0": 0, "short": 0, "epoll": 0}, {"inode": stat.st_ino, "offset": stat.st_size}
    start = old_offset if old_inode == stat.st_ino and stat.st_size >= old_offset else 0
    counts = {"code0": 0, "short": 0, "epoll": 0}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(start)
        for line in handle:
            match = EXIT_RE.search(line)
            if match:
                counts["code0"] += 1
                if float(match.group(1)) < 2:
                    counts["short"] += 1
            if EPOLL_TEXT in line:
                counts["epoll"] += 1
        offset = handle.tell()
    return counts, {"inode": stat.st_ino, "offset": offset}


def _probe(probe: Mapping[str, Any]) -> dict[str, Any]:
    url = str(probe.get("url", ""))
    host = str(probe.get("host", ""))
    address = str(probe.get("address", "127.0.0.1"))
    command = [
        "/usr/bin/curl",
        "--http1.1",
        "--max-time",
        str(int(probe.get("timeout_seconds", 20))),
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code} %{time_total}",
    ]
    if host:
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme == "https" else 80
        port = int(probe.get("port", parsed.port or default_port))
        command.extend(["--resolve", f"{host}:{port}:{address}"])
    command.append(url)
    result = run_command(command, timeout=int(probe.get("timeout_seconds", 20)) + 5)
    output = str(result.get("stdout", "")).strip().split()
    code = output[0] if output else "000"
    try:
        total = float(output[1]) if len(output) > 1 else None
    except ValueError:
        total = None
    allowed = {str(item) for item in probe.get("allowed_codes", ["200"])}
    return {
        "name": str(probe.get("name", host or url)),
        "code": code,
        "allowed": code in allowed and command_ok(result),
        "time_seconds": total,
        "stderr": str(result.get("stderr", ""))[-1000:],
    }


def check(
    context: Mapping[str, Any],
    config: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> dict[str, Any]:
    del context
    started = time.monotonic()
    properties = _systemd_properties(str(config.get("service", "php8.5-fpm.service")))
    zombies = _zombies()
    maximum_queue = _maximum_socket_queue(str(config.get("socket_prefix", "/run/php/")))
    mechanism, mechanism_result = _event_mechanism(str(config.get("php_fpm_command", "/usr/sbin/php-fpm8.5")))
    counts, cursor = _read_log_delta(Path(str(config.get("log_file", "/var/log/php8.5-fpm.log"))), previous)
    probes = [_probe(item) for item in config.get("probes", []) if isinstance(item, Mapping)]
    failed_probes = [item for item in probes if not item["allowed"]]

    warnings: list[str] = []
    critical: list[str] = []
    if properties.get("ActiveState") != "active" or properties.get("SubState") != "running" or properties.get("MainPID", 0) < 1:
        critical.append("PHP-FPM service or master process is not active")
    if zombies < 0:
        warnings.append("Unable to count PHP-FPM zombies")
    elif zombies > 0:
        critical.append(f"PHP-FPM has {zombies} zombie process(es)")
    warning_queue = int(config.get("warning_socket_queue", 100))
    critical_queue = int(config.get("critical_socket_queue", 1000))
    if maximum_queue < 0:
        warnings.append("Unable to inspect FastCGI socket queues")
    elif maximum_queue >= critical_queue:
        critical.append(f"FastCGI socket queue reached {maximum_queue}")
    elif maximum_queue >= warning_queue:
        warnings.append(f"FastCGI socket queue reached {maximum_queue}")
    expected = str(config.get("expected_event_mechanism", "poll")).lower()
    if mechanism != expected:
        warnings.append(f"PHP-FPM event mechanism is {mechanism}, expected {expected}")
    if counts["epoll"] > 0:
        critical.append(f"Observed {counts['epoll']} new epoll remove failure(s)")
    warning_short = int(config.get("warning_rapid_exits", 20))
    critical_short = int(config.get("critical_rapid_exits", 100))
    if counts["short"] >= critical_short:
        critical.append(f"Observed {counts['short']} rapid PHP-FPM worker exits")
    elif counts["short"] >= warning_short:
        warnings.append(f"Observed {counts['short']} rapid PHP-FPM worker exits")
    if len(failed_probes) >= int(config.get("critical_failed_probes", 2)):
        critical.append(f"{len(failed_probes)} application probes failed")
    elif failed_probes:
        warnings.append(f"Application probe failed: {failed_probes[0]['name']}")

    if critical:
        status, severity, summary = "critical", "critical", "; ".join(critical)
    elif warnings:
        status, severity, summary = "warning", "warning", "; ".join(warnings)
    else:
        status, severity, summary = "healthy", "info", "PHP-FPM functional health checks succeeded"

    return {
        "status": status,
        "severity": severity,
        "summary": summary,
        "metrics": {
            "main_pid": properties.get("MainPID", 0),
            "memory_bytes": properties.get("MemoryCurrent", 0),
            "tasks": properties.get("TasksCurrent", 0),
            "zombies": zombies,
            "maximum_socket_queue": maximum_queue,
            "code0_exits": counts["code0"],
            "rapid_exits": counts["short"],
            "epoll_remove_failures": counts["epoll"],
            "failed_probes": len(failed_probes),
        },
        "details": {
            "active_state": properties.get("ActiveState", "unknown"),
            "sub_state": properties.get("SubState", "unknown"),
            "event_mechanism": mechanism,
            "mechanism_command_ok": command_ok(mechanism_result),
            "probes": probes,
            "warnings": warnings,
            "critical_reasons": critical,
        },
        "public_details": {
            "active_state": properties.get("ActiveState", "unknown"),
            "sub_state": properties.get("SubState", "unknown"),
            "event_mechanism": mechanism,
            "probes": [
                {
                    "name": item.get("name"),
                    "code": item.get("code"),
                    "allowed": item.get("allowed"),
                    "time_seconds": item.get("time_seconds"),
                }
                for item in probes
            ],
            "warnings": warnings,
            "critical_reasons": critical,
        },
        "runtime": {"log_cursor": cursor},
        "notify_admin": status in {"warning", "critical"},
        "notify_emergency": status == "critical",
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


# EOF: /home/alan/src/argent-sentinel-collector/src/watchdogs/php_fpm.py
