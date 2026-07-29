#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/review_processor.py
# Installed: /usr/lib/argent-sentinel/review_processor.py
"""Root-owned processor for audited dashboard review requests."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
from typing import Any, Iterator, Mapping
import uuid

from review_queue import (
    REVIEW_ACTIONS,
    install_review_schema,
    utc_text,
)

APP_VERSION = "0.5.2.0"
UTC = dt.timezone.utc
DEFAULTS: dict[str, Any] = {
    "state_db": "/var/lib/argent-sentinel/collector/state.sqlite3",
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
    incident_uuid = valid_uuid(raw.get("incident_uuid"), "incident_uuid")
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
    return {
        "request_uuid": request_uuid,
        "incident_uuid": incident_uuid,
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
    if action == "note":
        return previous_report_status, "open", "note-added"
    raise ReviewError(f"Unsupported action: {action}")


def apply_request(
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
        SELECT incident_uuid, report_status, report_detail, updated_at,
               review_status, review_disposition, review_note
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

    applied = (now or dt.datetime.now(UTC)).astimezone(UTC)
    applied_epoch = int(applied.timestamp())
    applied_at = utc_text(applied)
    previous_report_status = str(incident["report_status"])
    previous_review_status = str(incident["review_status"] or "open")
    new_report_status, new_review_status, disposition = action_result(
        request["action"],
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
    if request["action"] in {
        "retry",
        "suppress",
        "permanent-no-contact",
    }:
        report_detail = (
            f"{report_detail}; {action_detail}" if report_detail else action_detail
        )

    with connection:
        connection.execute(
            """
            UPDATE incidents
            SET report_status = ?,
                report_detail = ?,
                next_report_after_epoch = CASE
                    WHEN ? = 'retry' THEN 0
                    ELSE next_report_after_epoch
                END,
                report_recipient = CASE
                    WHEN ? = 'retry' THEN NULL
                    ELSE report_recipient
                END,
                report_message_id = CASE
                    WHEN ? = 'retry' THEN NULL
                    ELSE report_message_id
                END,
                report_sent_epoch = CASE
                    WHEN ? = 'retry' THEN NULL
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
                request["action"],
                request["action"],
                request["action"],
                request["action"],
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
                request["action"],
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
        "action": request["action"],
        "disposition": disposition,
        "report_status": new_report_status,
        "review_status": new_review_status,
        "applied_at": applied_at,
    }


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
                    result = apply_request(connection, request)
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
