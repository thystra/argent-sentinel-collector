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
SERVICE_RE = re.compile(r"^php(?P<major>[0-9]+)[.](?P<minor>[0-9]+)-fpm[.]service$")
AUTO_VALUES = {"", "auto"}
ANY_MECHANISM_VALUES = {"", "auto", "any"}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _service_version(service: str) -> tuple[int, int] | None:
    match = SERVICE_RE.fullmatch(service)
    if not match:
        return None
    return int(match.group("major")), int(match.group("minor"))


def _service_sort_key(service: str) -> tuple[int, int, str]:
    version = _service_version(service)
    if version is None:
        return (-1, -1, service)
    return (*version, service)


def _service_names(text: str) -> list[str]:
    values: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        service = fields[0]
        if SERVICE_RE.fullmatch(service):
            values.add(service)
    return sorted(values, key=_service_sort_key, reverse=True)


def _enabled_service_names(text: str) -> list[str]:
    values: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        service, state = fields[0], fields[1]
        if SERVICE_RE.fullmatch(service) and state in {
            "enabled",
            "enabled-runtime",
            "static",
        }:
            values.add(service)
    return sorted(values, key=_service_sort_key, reverse=True)


def _discover_service() -> dict[str, Any]:
    active_result = run_command(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
            "php*-fpm.service",
        ],
        timeout=15,
    )
    installed_result = run_command(
        [
            "/usr/bin/systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "php*-fpm.service",
        ],
        timeout=15,
    )

    active = _service_names(str(active_result.get("stdout", "")))
    installed = _service_names(str(installed_result.get("stdout", "")))
    enabled = _enabled_service_names(str(installed_result.get("stdout", "")))

    if active:
        service, source = active[0], "auto-active"
    elif enabled:
        service, source = enabled[0], "auto-enabled"
    elif installed:
        service, source = installed[0], "auto-installed"
    else:
        service, source = "", "auto-unresolved"

    return {
        "service": service,
        "source": source,
        "active_services": active,
        "enabled_services": enabled,
        "installed_services": installed,
        "active_command_ok": command_ok(active_result),
        "installed_command_ok": command_ok(installed_result),
    }


def _resolve_target(config: Mapping[str, Any]) -> dict[str, Any]:
    configured_service = _text(config.get("service"))
    if configured_service.lower() not in AUTO_VALUES:
        discovery: dict[str, Any] = {
            "service": configured_service,
            "source": "explicit",
            "active_services": [],
            "enabled_services": [],
            "installed_services": [],
            "active_command_ok": True,
            "installed_command_ok": True,
        }
    else:
        discovery = _discover_service()

    service = _text(discovery.get("service"))
    version = _service_version(service)
    version_text = f"{version[0]}.{version[1]}" if version else ""

    configured_command = _text(config.get("php_fpm_command"))
    configured_log = _text(config.get("log_file"))
    configured_process = _text(config.get("process_name"))

    command = (
        configured_command
        if configured_command.lower() not in AUTO_VALUES
        else (f"/usr/sbin/php-fpm{version_text}" if version_text else "")
    )
    log_file = (
        configured_log
        if configured_log.lower() not in AUTO_VALUES
        else (f"/var/log/php{version_text}-fpm.log" if version_text else "")
    )
    process_name = (
        configured_process
        if configured_process.lower() not in AUTO_VALUES
        else (f"php-fpm{version_text}" if version_text else "")
    )

    target_id = "|".join((service, command, log_file, process_name))
    errors: list[str] = []
    if not service:
        errors.append("No PHP-FPM systemd service could be resolved")
    if not command:
        errors.append("No PHP-FPM command could be resolved")
    if not log_file:
        errors.append("No PHP-FPM log file could be resolved")
    if not process_name:
        errors.append("No PHP-FPM process name could be resolved")

    return {
        **discovery,
        "service": service,
        "version": version_text,
        "command": command,
        "log_file": log_file,
        "process_name": process_name,
        "id": target_id,
        "errors": errors,
        "overrides": {
            "service": configured_service.lower() not in AUTO_VALUES,
            "command": configured_command.lower() not in AUTO_VALUES,
            "log_file": configured_log.lower() not in AUTO_VALUES,
            "process_name": configured_process.lower() not in AUTO_VALUES,
        },
    }


def validate(config: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(config.get("mode", "")) != "observe":
        errors.append("PHP-FPM watchdog must remain in observe mode in this release")
    if int(config.get("interval_seconds", 0)) < 60:
        errors.append("interval_seconds must be at least 60")
    if not isinstance(config.get("probes", []), list):
        errors.append("probes must be a list")
    if config.get("enabled"):
        target = _resolve_target(config)
        errors.extend(str(item) for item in target.get("errors", []))
        command = Path(str(target.get("command", "")))
        if str(command) and not command.is_file():
            errors.append(f"PHP-FPM command does not exist: {command}")
        for required in (
            "/usr/bin/curl",
            "/usr/bin/ps",
            "/usr/bin/ss",
            "/usr/bin/systemctl",
        ):
            if not Path(required).is_file():
                errors.append(f"required command does not exist: {required}")
    return errors


def _systemd_properties(service: str) -> dict[str, Any]:
    result = run_command(
        [
            "/usr/bin/systemctl",
            "show",
            service,
            "--property=LoadState",
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


def _zombies(main_pid: int, process_name: str) -> int:
    if main_pid < 1 or not process_name:
        return 0
    result = run_command(
        ["/usr/bin/ps", "-eo", "ppid=,stat=,comm="],
        timeout=15,
    )
    if not command_ok(result):
        return -1
    count = 0
    for line in str(result.get("stdout", "")).splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3:
            continue
        try:
            parent = int(fields[0])
        except ValueError:
            continue
        state, command = fields[1], fields[2]
        if parent == main_pid and state.startswith("Z") and command == process_name:
            count += 1
    return count


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
    if not command:
        return "unknown", {
            "returncode": 1,
            "timed_out": False,
            "stdout": "",
            "stderr": "PHP-FPM command was not resolved",
        }
    result = run_command([command, "-tt"], timeout=20)
    text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    match = re.search(r"events[.]mechanism\s*=\s*([A-Za-z0-9_-]+)", text)
    return (match.group(1).lower() if match else "unknown"), result


def _event_mechanism_diagnostics(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Return bounded private diagnostics for an enforced mechanism check."""
    return {
        "mechanism_command_ok": command_ok(result),
        "mechanism_command_returncode": result.get("returncode"),
        "mechanism_command_timed_out": bool(result.get("timed_out", False)),
        "mechanism_command_stderr_tail": str(result.get("stderr", ""))[-1000:],
    }


def _previous_main_pid(previous: Mapping[str, Any]) -> int:
    metrics = previous.get("metrics", {})
    if not isinstance(metrics, Mapping):
        return 0
    try:
        value = int(metrics.get("main_pid", 0))
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


def _previous_target_id(previous: Mapping[str, Any]) -> str:
    runtime = previous.get("runtime", {})
    if isinstance(runtime, Mapping):
        target = runtime.get("target", {})
        if isinstance(target, Mapping):
            value = _text(target.get("id"))
            if value:
                return value
    details = previous.get("details", {})
    if isinstance(details, Mapping):
        service = _text(details.get("selected_service"))
        command = _text(details.get("selected_command"))
        log_file = _text(details.get("selected_log_file"))
        process_name = _text(details.get("selected_process_name"))
        if any((service, command, log_file, process_name)):
            return "|".join((service, command, log_file, process_name))
    return ""


def _read_log_delta(
    path: Path,
    previous: Mapping[str, Any],
    *,
    rebase: bool = False,
) -> tuple[dict[str, int], dict[str, int]]:
    try:
        stat = path.stat()
    except OSError:
        return {"code0": 0, "short": 0, "epoll": 0}, {"inode": 0, "offset": 0}
    cursor = previous.get("runtime", {}).get("log_cursor", {})
    try:
        old_inode = int(cursor.get("inode", 0))
        old_offset = int(cursor.get("offset", 0))
    except (AttributeError, TypeError, ValueError):
        old_inode, old_offset = 0, 0
    if rebase or old_inode == 0:
        return {"code0": 0, "short": 0, "epoll": 0}, {
            "inode": stat.st_ino,
            "offset": stat.st_size,
        }
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
    target = _resolve_target(config)
    properties = _systemd_properties(str(target.get("service", "")))
    current_main_pid = int(properties.get("MainPID", 0) or 0)
    previous_main_pid = _previous_main_pid(previous)
    previous_target_id = _previous_target_id(previous)
    current_target_id = _text(target.get("id"))
    target_changed = bool(
        previous_target_id
        and current_target_id
        and previous_target_id != current_target_id
    )
    master_changed = (
        previous_main_pid > 0
        and current_main_pid > 0
        and previous_main_pid != current_main_pid
    )
    epoch_changed = master_changed or target_changed

    zombies = _zombies(current_main_pid, str(target.get("process_name", "")))
    maximum_queue = _maximum_socket_queue(str(config.get("socket_prefix", "/run/php/")))
    expected = _text(config.get("expected_event_mechanism")).lower()
    mechanism_check_enforced = expected not in ANY_MECHANISM_VALUES
    if mechanism_check_enforced:
        mechanism, mechanism_result = _event_mechanism(
            str(target.get("command", ""))
        )
    else:
        mechanism = "not_checked"
        mechanism_result = {
            "args": [],
            "duration_ms": 0,
            "returncode": 0,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "skipped": True,
        }
    mechanism_diagnostics = _event_mechanism_diagnostics(mechanism_result)
    counts, cursor = _read_log_delta(
        Path(str(target.get("log_file", ""))),
        previous,
        rebase=epoch_changed,
    )
    log_cursor_rebased = epoch_changed and cursor.get("inode", 0) > 0
    probes = [
        _probe(item)
        for item in config.get("probes", [])
        if isinstance(item, Mapping)
    ]
    failed_probes = [item for item in probes if not item["allowed"]]

    warnings: list[str] = []
    critical: list[str] = []
    target_errors = [str(item) for item in target.get("errors", [])]
    if target_errors:
        critical.extend(target_errors)
    if len(target.get("active_services", [])) > 1:
        warnings.append(
            "Multiple active PHP-FPM services were discovered: "
            + ", ".join(str(item) for item in target.get("active_services", []))
        )
    if (
        properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or current_main_pid < 1
    ):
        critical.append("PHP-FPM service or master process is not active")
    if zombies < 0:
        warnings.append("Unable to count selected PHP-FPM zombies")
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

    if mechanism_check_enforced:
        if not mechanism_diagnostics["mechanism_command_ok"] or mechanism == "unknown":
            warnings.append("Unable to determine PHP-FPM event mechanism")
        elif mechanism != expected:
            warnings.append(
                f"PHP-FPM event mechanism is {mechanism}, expected {expected}"
            )

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

    version_label = str(target.get("version", "")).strip()
    if critical:
        status, severity, summary = "critical", "critical", "; ".join(critical)
    elif warnings:
        status, severity, summary = "warning", "warning", "; ".join(warnings)
    else:
        status, severity = "healthy", "info"
        summary = (
            f"PHP-FPM {version_label} functional health checks succeeded"
            if version_label
            else "PHP-FPM functional health checks succeeded"
        )

    target_details = {
        "selected_service": target.get("service", ""),
        "selected_version": target.get("version", ""),
        "selected_command": target.get("command", ""),
        "selected_log_file": target.get("log_file", ""),
        "selected_process_name": target.get("process_name", ""),
        "target_source": target.get("source", "unknown"),
        "active_php_fpm_services": target.get("active_services", []),
        "target_changed": target_changed,
    }

    return {
        "status": status,
        "severity": severity,
        "summary": summary,
        "metrics": {
            "main_pid": current_main_pid,
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
            **target_details,
            "active_state": properties.get("ActiveState", "unknown"),
            "sub_state": properties.get("SubState", "unknown"),
            "event_mechanism": mechanism,
            "expected_event_mechanism": expected or "any",
            "mechanism_check_enforced": mechanism_check_enforced,
            "mechanism_check_skipped": not mechanism_check_enforced,
            **mechanism_diagnostics,
            "previous_main_pid": previous_main_pid,
            "current_main_pid": current_main_pid,
            "master_changed": master_changed,
            "log_cursor_rebased": log_cursor_rebased,
            "probes": probes,
            "warnings": warnings,
            "critical_reasons": critical,
        },
        "public_details": {
            **target_details,
            "active_state": properties.get("ActiveState", "unknown"),
            "sub_state": properties.get("SubState", "unknown"),
            "event_mechanism": mechanism,
            "expected_event_mechanism": expected or "any",
            "mechanism_check_enforced": mechanism_check_enforced,
            "mechanism_check_skipped": not mechanism_check_enforced,
            "previous_main_pid": previous_main_pid,
            "current_main_pid": current_main_pid,
            "master_changed": master_changed,
            "log_cursor_rebased": log_cursor_rebased,
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
        "runtime": {
            "log_cursor": cursor,
            "target": {
                "id": current_target_id,
                "service": target.get("service", ""),
                "version": target.get("version", ""),
            },
        },
        "notify_admin": status in {"warning", "critical"},
        "notify_emergency": status == "critical",
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


# EOF: /home/alan/src/argent-sentinel-collector/src/watchdogs/php_fpm.py
