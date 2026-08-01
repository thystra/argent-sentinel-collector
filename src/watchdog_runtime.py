#!/usr/bin/env python3
# /home/alan/src/argent-sentinel-collector/src/watchdog_runtime.py
"""Shared runtime helpers for Argent Sentinel watchdog modules."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from typing import Any, Iterable, Mapping, Sequence

UTC = dt.timezone.utc


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    value = value or utc_now()
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_text(value: dt.datetime | None = None) -> str:
    value = value or dt.datetime.now().astimezone()
    return value.replace(microsecond=0).isoformat()


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 20,
    input_text: str | None = None,
) -> dict[str, Any]:
    """Run one bounded command and terminate its process group on timeout."""

    started = time.monotonic()
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            list(args),
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        return {
            "args": list(args),
            "returncode": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": False,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                process.terminate()
            try:
                trailing_stdout, trailing_stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    process.kill()
                trailing_stdout, trailing_stderr = process.communicate()
            stdout += trailing_stdout or ""
            stderr += trailing_stderr or ""
        return {
            "args": list(args),
            "returncode": process.returncode if process is not None else None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
    except OSError as exc:
        return {
            "args": list(args),
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }


def command_ok(result: Mapping[str, Any]) -> bool:
    return result.get("returncode") == 0 and not result.get("timed_out")


def atomic_write_json(path: Path, value: Mapping[str, Any], mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_optional_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def write_command_capture(path: Path, title: str, result: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lines = [
        f"===== {title} =====",
        f"Command: {' '.join(str(item) for item in result.get('args', []))}",
        f"Return code: {result.get('returncode')}",
        f"Timed out: {bool(result.get('timed_out'))}",
        f"Duration ms: {result.get('duration_ms')}",
        "",
        "===== STDOUT =====",
        str(result.get("stdout", "")),
        "",
        "===== STDERR =====",
        str(result.get("stderr", "")),
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o600)


def deduplicate(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value).strip()
        key = normalized.casefold()
        if not normalized or key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


# EOF: /home/alan/src/argent-sentinel-collector/src/watchdog_runtime.py
