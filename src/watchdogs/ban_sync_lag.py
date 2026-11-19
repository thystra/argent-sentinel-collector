#!/usr/bin/env python3
# /home/alan/src/argent-sentinel/argent-sentinel/src/watchdogs/ban_sync_lag.py
"""Cross-node ban-sync lag watchdog (0.5.8.0).

Runs on the central host.  Reads the collector-published ban-sync status
file (``ban_sync.status_file``; the watchdog sandbox cannot open the store's
WAL files) and alerts when
an enrolled node has not pulled the effective ban set within
``max_pull_age_seconds`` (default 30 minutes), or never pulled at all.  It
never changes CrowdSec or ban-sync state.
"""

from __future__ import annotations

from pathlib import Path
import re
import time
from typing import Any, Mapping

import ban_sync

NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def validate(config: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(config.get("mode", "observe")) != "observe":
        errors.append("mode must be observe")
    if int(config.get("interval_seconds", 0)) < 60:
        errors.append("interval_seconds must be at least 60")
    if int(config.get("max_pull_age_seconds", 0)) < 300:
        errors.append("max_pull_age_seconds must be at least 300")
    if int(config.get("max_status_age_seconds", 0)) < 120:
        errors.append("max_status_age_seconds must be at least 120")
    if not str(config.get("status_file", "")).startswith("/"):
        errors.append("status_file must be an absolute path")
    nodes = config.get("expected_nodes", [])
    if not isinstance(nodes, list) or not all(NODE_RE.fullmatch(str(item)) for item in nodes):
        errors.append("expected_nodes must be a list of node ids")
    return errors


def evaluate(
    pulls: list[Mapping[str, Any]],
    expected_nodes: list[str],
    *,
    now_epoch: int,
    max_pull_age_seconds: int,
) -> dict[str, Any]:
    """Pure evaluation used by check() and the unit tests."""
    last = {
        str(item["node_id"]): int(item.get("last_pull_epoch", 0) or 0)
        for item in pulls
        if isinstance(item, Mapping) and item.get("node_id")
    }
    nodes = sorted(set(last) | {str(item) for item in expected_nodes})
    lag: dict[str, int | None] = {}
    stale: list[str] = []
    never: list[str] = []
    for node in nodes:
        if node not in last or last[node] <= 0:
            lag[node] = None
            never.append(node)
            continue
        lag[node] = max(0, now_epoch - last[node])
        if lag[node] > max_pull_age_seconds:
            stale.append(node)
    return {"nodes": nodes, "lag_seconds": lag, "stale": stale, "never": never}


def check(context: Mapping[str, Any], config: Mapping[str, Any], previous: Mapping[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    threshold = int(config.get("max_pull_age_seconds", 1800))
    status_age_limit = int(config.get("max_status_age_seconds", 600))
    path = Path(str(config.get("status_file", ban_sync.CENTRAL_DEFAULTS["status_file"])))
    now_epoch = int(time.time())
    status = ban_sync.load_json_file(path)
    generated = int(status.get("generated_epoch", 0) or 0) if status else 0
    if status.get("schema_version") != 1 or generated <= 0 or now_epoch - generated > status_age_limit:
        detail = "missing or invalid" if generated <= 0 else f"{now_epoch - generated} s old"
        return {
            "status": "warning",
            "severity": "warning",
            "summary": f"Ban-sync status file {detail}; is the collector running with ban_sync enabled?",
            "metrics": {},
            "details": {"status_file": str(path)},
            "public_details": {},
            "notify_admin": True,
            "notify_emergency": False,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
    result = evaluate(
        list(status.get("nodes", [])) if isinstance(status.get("nodes"), list) else [],
        [str(item) for item in config.get("expected_nodes", [])],
        now_epoch=now_epoch,
        max_pull_age_seconds=threshold,
    )
    problems = result["stale"] + result["never"]
    if problems:
        parts = []
        if result["stale"]:
            parts.append("not pulled within %d s: %s" % (threshold, ", ".join(result["stale"])))
        if result["never"]:
            parts.append("never pulled: %s" % ", ".join(result["never"]))
        summary = "Ban-sync lag: " + "; ".join(parts)
    else:
        summary = f"All {len(result['nodes'])} ban-sync nodes pulled within {threshold} s"
    return {
        "status": "critical" if problems else "healthy",
        "severity": "critical" if problems else "info",
        "summary": summary,
        "metrics": {"nodes": len(result["nodes"]), "lagging": len(problems)},
        "details": result,
        "public_details": {"lag_seconds": result["lag_seconds"], "lagging": problems},
        "notify_admin": bool(problems) or previous.get("status") not in (None, "healthy"),
        "notify_emergency": False,
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


# EOF: /home/alan/src/argent-sentinel/argent-sentinel/src/watchdogs/ban_sync_lag.py
