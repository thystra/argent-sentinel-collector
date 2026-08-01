#!/usr/bin/env python3
# /home/alan/src/argent-sentinel-collector/src/watchdog.py
"""Modular Argent Sentinel watchdog runner and notification coordinator."""

from __future__ import annotations

import argparse
import fcntl
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time
from typing import Any, Mapping

from watchdog_runtime import (
    atomic_write_json,
    command_ok,
    deduplicate,
    load_optional_json,
    run_command,
    utc_text,
)

APP_VERSION = "0.5.5.0"
MODULE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
STATUS_RANK = {"disabled": 0, "healthy": 1, "warning": 2, "critical": 3, "error": 4}

DEFAULTS: dict[str, Any] = {
    "schema_version": 1,
    "package_config_dir": "/usr/lib/argent-sentinel/watchdog.d",
    "config_dir": "/etc/argent-sentinel/watchdog.d",
    "state_dir": "/var/lib/argent-sentinel/watchdogs",
    "incident_dir": "/var/lib/argent-sentinel/watchdogs/incidents",
    "lock_file": "/run/argent-sentinel/watchdog.lock",
    "retention_days": 30,
    "routine_summary_hours": 24,
    "notifications": {
        "enabled": True,
        "mail_command": "/usr/bin/mail",
        "admin_recipients": [],
        "emergency_recipients": [],
        "hostname": "",
    },
}


class WatchdogError(RuntimeError):
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
        raise WatchdogError(f"Configuration not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise WatchdogError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WatchdogError(f"Configuration root must be an object: {path}")
    return value


def load_config(path: Path) -> dict[str, Any]:
    config = deep_merge(DEFAULTS, load_json(path))
    if config.get("schema_version") != 1:
        raise WatchdogError("watchdog configuration schema_version must be 1")
    notifications = config.get("notifications")
    if not isinstance(notifications, Mapping):
        raise WatchdogError("notifications must be an object")
    for key in ("admin_recipients", "emergency_recipients"):
        recipients = notifications.get(key)
        if not isinstance(recipients, list):
            raise WatchdogError(f"notifications.{key} must be a list")
        invalid = [str(item) for item in recipients if not EMAIL_RE.fullmatch(str(item).strip())]
        if invalid:
            raise WatchdogError(
                f"notifications.{key} contains invalid address(es): {', '.join(invalid)}"
            )
    configured_recipients = (
        notifications.get("admin_recipients", [])
        + notifications.get("emergency_recipients", [])
    )
    mail_command = Path(str(notifications.get("mail_command", "/usr/bin/mail")))
    if notifications.get("enabled", True) and configured_recipients and not mail_command.is_file():
        raise WatchdogError(f"notification mail command does not exist: {mail_command}")
    return config


def _load_directory(path: Path, result: dict[str, dict[str, Any]]) -> None:
    if not path.is_dir():
        return
    for item in sorted(path.glob("*.json")):
        supplied = load_json(item)
        watchdog_id = str(supplied.get("id", "")).strip()
        if not MODULE_RE.fullmatch(watchdog_id):
            raise WatchdogError(f"Invalid or missing watchdog id in {item}")
        supplied["_source"] = str(item)
        result[watchdog_id] = deep_merge(result.get(watchdog_id, {}), supplied)


def load_watchdogs(config: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    _load_directory(Path(str(config["package_config_dir"])), result)
    _load_directory(Path(str(config["config_dir"])), result)
    if not result:
        raise WatchdogError("No watchdog definitions were found")
    return result


def load_module(definition: Mapping[str, Any]):
    module_name = str(definition.get("module", "")).strip()
    if not MODULE_RE.fullmatch(module_name):
        raise WatchdogError(
            f"Watchdog {definition.get('id')} has an invalid module name"
        )
    try:
        return importlib.import_module(f"watchdogs.{module_name}")
    except ImportError as exc:
        raise WatchdogError(
            f"Unable to import watchdog module {module_name}: {exc}"
        ) from exc


def validate_watchdogs(definitions: Mapping[str, Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    for watchdog_id, definition in definitions.items():
        try:
            if int(definition.get("interval_seconds", 0)) < 60:
                errors.append(f"{watchdog_id}: interval_seconds must be at least 60")
            timeout_seconds = int(definition.get("timeout_seconds", 120))
            if timeout_seconds < 10 or timeout_seconds > 900:
                errors.append(f"{watchdog_id}: timeout_seconds must be between 10 and 900")
            module = load_module(definition)
            for error in module.validate(definition):
                errors.append(f"{watchdog_id}: {error}")
        except (TypeError, ValueError, WatchdogError) as exc:
            errors.append(f"{watchdog_id}: {exc}")
    return errors


def state_path(config: Mapping[str, Any], watchdog_id: str) -> Path:
    return Path(str(config["state_dir"])) / "status" / f"{watchdog_id}.json"


def load_state(config: Mapping[str, Any], watchdog_id: str) -> dict[str, Any]:
    return load_optional_json(state_path(config, watchdog_id))


def write_state(config: Mapping[str, Any], watchdog_id: str, value: Mapping[str, Any]) -> None:
    atomic_write_json(state_path(config, watchdog_id), value)


def _hostname(config: Mapping[str, Any]) -> str:
    supplied = str(config.get("notifications", {}).get("hostname", "")).strip()
    return supplied or socket.getfqdn()


def _mail(
    config: Mapping[str, Any],
    recipients: list[str],
    subject: str,
    body: str,
    *,
    individual: bool,
) -> list[dict[str, Any]]:
    notifications = config.get("notifications", {})
    if not notifications.get("enabled", True) or not recipients:
        return []
    command = str(notifications.get("mail_command", "/usr/bin/mail"))
    groups = [[item] for item in recipients] if individual else [recipients]
    results: list[dict[str, Any]] = []
    for group in groups:
        result = run_command(
            [command, "-s", subject, *group],
            timeout=30,
            input_text=body,
        )
        results.append(
            {
                "recipients": group,
                "success": command_ok(result),
                "returncode": result.get("returncode"),
                "timed_out": bool(result.get("timed_out")),
                "stderr": str(result.get("stderr", ""))[-1000:],
            }
        )
    return results


def _admin_body(hostname: str, state: Mapping[str, Any]) -> str:
    details = state.get("details", {})
    metrics = state.get("metrics", {})
    lines = [
        f"Argent Sentinel watchdog event on {hostname}",
        "",
        f"Watchdog: {state.get('display_name', state.get('id'))}",
        f"State: {state.get('status')}",
        f"Severity: {state.get('severity')}",
        f"Checked: {state.get('checked_at')}",
        f"Summary: {state.get('summary')}",
        f"Mode: {state.get('mode')}",
        f"Consecutive failures: {state.get('consecutive_failures', 0)}",
        "",
        "Metrics:",
        json.dumps(metrics, indent=2, sort_keys=True, default=str),
        "",
        "Details:",
        json.dumps(details, indent=2, sort_keys=True, default=str),
        "",
    ]
    return "\n".join(lines)


def _emergency_body(hostname: str, state: Mapping[str, Any]) -> str:
    incident = str(state.get("details", {}).get("incident_archive", "")).strip()
    lines = [
        f"{hostname} WATCHDOG {str(state.get('status', '')).upper()}",
        str(state.get("display_name", state.get("id"))),
        str(state.get("summary", "")),
        f"Time: {state.get('checked_at')}",
    ]
    if incident:
        lines.append(f"Incident: {incident}")
    return "\n".join(lines) + "\n"


def send_state_notifications(
    config: Mapping[str, Any],
    previous: Mapping[str, Any],
    state: dict[str, Any],
) -> None:
    notifications = config.get("notifications", {})
    admin = deduplicate(notifications.get("admin_recipients", []))
    admin_keys = {item.casefold() for item in admin}
    emergency = [
        item
        for item in deduplicate(notifications.get("emergency_recipients", []))
        if item.casefold() not in admin_keys
    ]
    previous_status = str(previous.get("status", ""))
    current_status = str(state.get("status", ""))
    transition = previous_status != current_status
    escalation = STATUS_RANK.get(current_status, 0) > STATUS_RANK.get(previous_status, 0)
    recovered = previous_status in {"warning", "critical", "error"} and current_status == "healthy"
    event = str(state.get("event", ""))
    threshold = max(1, int(state.get("notification_failure_threshold", 1) or 1))
    previous_failures = int(previous.get("consecutive_failures", 0) or 0)
    current_failures = int(state.get("consecutive_failures", 0) or 0)
    threshold_crossed = previous_failures < threshold <= current_failures

    should_admin = bool(state.get("notify_admin")) and (
        recovered or event == "automatic-recovery" or threshold_crossed or
        ((transition or escalation) and current_failures >= threshold)
    )
    should_emergency = bool(state.get("notify_emergency")) and (
        event == "automatic-recovery" or threshold_crossed or
        ((transition or escalation) and current_failures >= threshold)
    )
    hostname = _hostname(config)
    deliveries: dict[str, Any] = {}
    if should_admin:
        deliveries["admin"] = _mail(
            config,
            admin,
            f"[{hostname}] {state.get('display_name')} watchdog {current_status}",
            _admin_body(hostname, state),
            individual=False,
        )
    if should_emergency:
        deliveries["emergency"] = _mail(
            config,
            emergency,
            f"[{hostname}] WATCHDOG {current_status.upper()}",
            _emergency_body(hostname, state),
            individual=True,
        )
    if deliveries:
        state["notification_deliveries"] = deliveries


def _routine_summary(config: Mapping[str, Any], states: list[Mapping[str, Any]]) -> None:
    hours = int(config.get("routine_summary_hours", 0))
    if hours <= 0:
        return
    state_file = Path(str(config["state_dir"])) / "notification-state.json"
    notification_state = load_optional_json(state_file)
    now = int(time.time())
    last = int(notification_state.get("last_routine_summary_epoch", 0) or 0)
    if last == 0:
        atomic_write_json(state_file, {"last_routine_summary_epoch": now})
        return
    if now - last < hours * 3600:
        return
    admin = deduplicate(config.get("notifications", {}).get("admin_recipients", []))
    hostname = _hostname(config)
    lines = [
        f"Argent Sentinel watchdog routine report for {hostname}",
        f"Generated: {utc_text()}",
        "",
    ]
    for state in sorted(states, key=lambda item: str(item.get("id", ""))):
        lines.append(
            f"{state.get('display_name', state.get('id'))}: "
            f"{state.get('status')} — {state.get('summary')}"
        )
    results = _mail(
        config,
        admin,
        f"[{hostname}] Watchdog routine report",
        "\n".join(lines) + "\n",
        individual=False,
    )
    if not results or all(item.get("success") for item in results):
        atomic_write_json(state_file, {"last_routine_summary_epoch": now})


def _retention(config: Mapping[str, Any]) -> None:
    cutoff = time.time() - max(1, int(config.get("retention_days", 30))) * 86400
    root = Path(str(config["incident_dir"]))
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            continue


def _disabled_state(definition: Mapping[str, Any], previous: Mapping[str, Any]) -> dict[str, Any]:
    now = int(time.time())
    return {
        "schema_version": 1,
        "version": APP_VERSION,
        "id": definition["id"],
        "display_name": definition.get("display_name", definition["id"]),
        "module": definition.get("module"),
        "enabled": False,
        "mode": definition.get("mode", "observe"),
        "interval_seconds": int(definition.get("interval_seconds", 60)),
        "status": "disabled",
        "severity": "info",
        "summary": "Watchdog is disabled",
        "checked_at": utc_text(),
        "checked_epoch": now,
        "last_started_epoch": previous.get("last_started_epoch", 0),
        "consecutive_failures": 0,
        "metrics": {},
        "details": {},
        "public_details": {},
        "history": previous.get("history", []),
        "runtime": previous.get("runtime", {}),
    }


def _module_worker(
    queue: multiprocessing.Queue,
    module_name: str,
    context: Mapping[str, Any],
    definition: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> None:
    """Execute one module in its own process group."""

    try:
        os.setsid()
    except OSError:
        pass
    try:
        module = importlib.import_module(f"watchdogs.{module_name}")
        result = module.check(context, definition, previous)
        if not isinstance(result, dict):
            raise WatchdogError("watchdog module returned a non-object result")
        queue.put({"ok": True, "result": result})
    except BaseException as exc:  # noqa: BLE001 - child must report all failures
        queue.put(
            {
                "ok": False,
                "exception_type": type(exc).__name__,
                "error": str(exc),
            }
        )


def _run_module_bounded(
    definition: Mapping[str, Any],
    context: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> dict[str, Any]:
    module_name = str(definition.get("module", ""))
    timeout_seconds = int(definition.get("timeout_seconds", 120))
    process_context = multiprocessing.get_context("fork")
    queue = process_context.Queue(maxsize=1)
    process = process_context.Process(
        target=_module_worker,
        args=(queue, module_name, context, definition, previous),
        daemon=False,
    )
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
        process.join(3)
        if process.is_alive():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            process.join(3)
        queue.close()
        return {
            "status": "error",
            "severity": "critical",
            "summary": f"Watchdog module exceeded its {timeout_seconds}-second timeout",
            "metrics": {},
            "details": {"timeout_seconds": timeout_seconds},
            "public_details": {"timeout_seconds": timeout_seconds},
            "notify_admin": True,
            "notify_emergency": True,
            "duration_ms": timeout_seconds * 1000,
        }
    try:
        payload = queue.get(timeout=2)
    except Exception as exc:  # noqa: BLE001 - missing child result is a runner error
        payload = {
            "ok": False,
            "exception_type": type(exc).__name__,
            "error": "module process exited without a result",
        }
    finally:
        queue.close()
        queue.join_thread()
    if payload.get("ok"):
        return dict(payload["result"])
    return {
        "status": "error",
        "severity": "critical",
        "summary": f"Watchdog module failed: {payload.get('error', 'unknown failure')}",
        "metrics": {},
        "details": {"exception_type": payload.get("exception_type", "Unknown")},
        "public_details": {"exception_type": payload.get("exception_type", "Unknown")},
        "notify_admin": True,
        "notify_emergency": True,
        "duration_ms": 0,
    }


def _history(
    previous: Mapping[str, Any],
    state: Mapping[str, Any],
    *,
    maximum: int = 50,
) -> list[dict[str, Any]]:
    existing = previous.get("history", [])
    history = [dict(item) for item in existing if isinstance(item, Mapping)][-maximum:]
    changed = previous.get("status") != state.get("status")
    event = bool(state.get("event"))
    if not previous or changed or event:
        history.append(
            {
                "checked_at": state.get("checked_at"),
                "status": state.get("status"),
                "severity": state.get("severity"),
                "summary": state.get("summary"),
                "event": state.get("event", ""),
            }
        )
    return history[-maximum:]


def run_watchdog(
    config: Mapping[str, Any],
    definition: Mapping[str, Any],
    *,
    force: bool,
    notify: bool,
) -> dict[str, Any]:
    watchdog_id = str(definition["id"])
    previous = load_state(config, watchdog_id)
    if not bool(definition.get("enabled", False)):
        state = _disabled_state(definition, previous)
        write_state(config, watchdog_id, state)
        return state

    now_epoch = int(time.time())
    interval = int(definition.get("interval_seconds", 60))
    last_started = int(previous.get("last_started_epoch", 0) or 0)
    if not force and last_started and now_epoch - last_started < interval:
        return previous

    context = {
        "hostname": _hostname(config),
        "state_dir": str(config["state_dir"]),
        "incident_dir": str(config["incident_dir"]),
        "version": APP_VERSION,
    }
    result = _run_module_bounded(definition, context, previous)

    status = str(result.get("status", "error"))
    if status not in {"healthy", "warning", "critical", "error"}:
        status = "error"
        result["summary"] = "Watchdog module returned an invalid status"
    previous_failures = int(previous.get("consecutive_failures", 0) or 0)
    failures = 0 if status == "healthy" else previous_failures + 1
    checked_at = utc_text()
    state: dict[str, Any] = {
        "schema_version": 1,
        "version": APP_VERSION,
        "id": watchdog_id,
        "display_name": definition.get("display_name", watchdog_id),
        "module": definition.get("module"),
        "enabled": True,
        "mode": definition.get("mode", "observe"),
        "interval_seconds": interval,
        "status": status,
        "severity": result.get("severity", status),
        "summary": result.get("summary", "No summary supplied"),
        "checked_at": checked_at,
        "checked_epoch": now_epoch,
        "last_started_epoch": now_epoch,
        "duration_ms": int(result.get("duration_ms", 0) or 0),
        "consecutive_failures": failures,
        "last_healthy_at": checked_at if status == "healthy" else previous.get("last_healthy_at"),
        "last_failure_at": checked_at if status != "healthy" else previous.get("last_failure_at"),
        "last_transition_at": (
            checked_at if previous.get("status") != status else previous.get("last_transition_at", checked_at)
        ),
        "metrics": result.get("metrics", {}),
        "details": result.get("details", {}),
        "public_details": result.get("public_details", {}),
        "runtime": result.get("runtime", previous.get("runtime", {})),
        "event": result.get("event", ""),
        "notify_admin": bool(result.get("notify_admin", False)),
        "notify_emergency": bool(result.get("notify_emergency", False)),
        "notification_failure_threshold": max(
            1, int(definition.get("notification_failure_threshold", 1) or 1)
        ),
        "definition_source": definition.get("_source"),
    }
    state["history"] = _history(previous, state)
    if notify:
        send_state_notifications(config, previous, state)
        deliveries = state.get("notification_deliveries", {})
        state["notification_delivery_failed"] = any(
            not item.get("success", False)
            for group in deliveries.values()
            for item in group
            if isinstance(item, Mapping)
        )
    write_state(config, watchdog_id, state)
    return state


def run_all(
    config: Mapping[str, Any],
    definitions: Mapping[str, Mapping[str, Any]],
    *,
    force: bool,
    selected: str | None,
    notify: bool,
) -> list[dict[str, Any]]:
    lock_path = Path(str(config["lock_file"]))
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with lock_path.open("a+b") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return []
        states: list[dict[str, Any]] = []
        for watchdog_id, definition in sorted(definitions.items()):
            if selected and watchdog_id != selected:
                continue
            states.append(
                run_watchdog(
                    config,
                    definition,
                    force=force,
                    notify=notify,
                )
            )
        _retention(config)
        if not selected and notify:
            _routine_summary(config, states)
        return states


def status_document(config: Mapping[str, Any], definitions: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    states = []
    for watchdog_id, definition in sorted(definitions.items()):
        state = load_state(config, watchdog_id)
        if not state:
            state = _disabled_state(definition, {}) if not definition.get("enabled", False) else {
                "id": watchdog_id,
                "display_name": definition.get("display_name", watchdog_id),
                "status": "unknown",
                "summary": "Watchdog has not run yet",
            }
        states.append(state)
    return {"version": APP_VERSION, "generated_at": utc_text(), "watchdogs": states}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/argent-sentinel/watchdog.json")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-config")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--force", action="store_true")
    run_parser.add_argument("--watchdog")
    run_parser.add_argument("--no-notify", action="store_true")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        config = load_config(Path(args.config))
        definitions = load_watchdogs(config)
        errors = validate_watchdogs(definitions)
        if errors:
            raise WatchdogError("; ".join(errors))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok", "version": APP_VERSION, "watchdogs": sorted(definitions)}, indent=2))
            return 0
        if args.command == "run":
            if args.watchdog and args.watchdog not in definitions:
                raise WatchdogError(f"Unknown watchdog: {args.watchdog}")
            result = run_all(
                config,
                definitions,
                force=args.force,
                selected=args.watchdog,
                notify=not args.no_notify,
            )
            print(json.dumps({"status": "ok", "version": APP_VERSION, "watchdogs": result}, indent=2, sort_keys=True, default=str))
            return 0
        document = status_document(config, definitions)
        if args.json:
            print(json.dumps(document, indent=2, sort_keys=True, default=str))
        else:
            for item in document["watchdogs"]:
                print(f"{item.get('id')}: {item.get('status')} — {item.get('summary')}")
        return 0
    except (WatchdogError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc), "version": APP_VERSION}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# EOF: /home/alan/src/argent-sentinel-collector/src/watchdog.py
