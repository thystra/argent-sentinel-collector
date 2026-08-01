#!/usr/bin/env python3
"""Read-only Argent Sentinel operator dashboard."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import secrets
import tempfile
import uuid
import grp
from html import escape
import json
import logging
import os
from pathlib import Path
import re
import socket
import socketserver
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Any, Mapping
from review_queue import NETWORK_REVIEW_ACTIONS, REVIEW_ACTIONS

APP_VERSION = "0.5.5.0"
LOG = logging.getLogger("argent-sentinel-dashboard")

DEFAULTS: dict[str, Any] = {
    "socket_path": "/run/argent-sentinel-dashboard/dashboard.sock",
    "socket_group": "www-data",
    "socket_mode": "0660",
    "snapshot_file": "/var/lib/argent-sentinel/dashboard/snapshot.json",
    "title": "Argent Sentinel",
    "awstats_url_prefix": "/awstats/",
    "max_json_bytes": 20 * 1024 * 1024,
    "max_post_bytes": 32768,
    "review_note_max_chars": 2000,
    "review_request_dir": "/var/spool/argent-sentinel/review/incoming",
}


class DashboardError(RuntimeError):
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


def load_config(path: Path) -> dict[str, Any]:
    try:
        supplied = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DashboardError(f"Dashboard configuration missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise DashboardError(f"Invalid dashboard JSON: {exc}") from exc
    if not isinstance(supplied, dict):
        raise DashboardError("Dashboard configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    mode = str(config["socket_mode"])
    if not re.fullmatch(r"0?[0-7]{3,4}", mode):
        raise DashboardError("socket_mode must be an octal permission string")
    return config


def load_snapshot(config: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(str(config["snapshot_file"]))
    try:
        if path.stat().st_size > int(config["max_json_bytes"]):
            raise DashboardError("Dashboard snapshot exceeds configured size limit")
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except PermissionError as exc:
        raise DashboardError(
            f"Dashboard snapshot is not readable: {path}"
        ) from exc
    except FileNotFoundError as exc:
        raise DashboardError("Dashboard snapshot has not been generated") from exc
    except json.JSONDecodeError as exc:
        raise DashboardError(f"Dashboard snapshot is invalid: {exc}") from exc
    if not isinstance(snapshot, dict):
        raise DashboardError("Dashboard snapshot root must be an object")
    return snapshot


def h(value: Any) -> str:
    return escape(str(value if value is not None else "-"), quote=True)

LOCAL_TIME_FORMAT = "%Y-%m-%d %H:%M:%S %Z"
_CSRF_SECRET = secrets.token_bytes(32)


def when(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "-"
    try:
        normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        local = parsed.astimezone()
    except ValueError:
        return h(raw)
    display = local.strftime(LOCAL_TIME_FORMAT)
    return (
        f'<time datetime="{h(raw)}" title="UTC: {h(raw)}">'
        f'{h(display)}</time>'
    )


def csrf_token(
    request_uuid: str,
    target_id: str,
    updated_at: str,
    revision: str = "",
) -> str:
    payload = (
        f"{request_uuid}\n{target_id}\n{updated_at}\n{revision}"
    ).encode("utf-8")
    return hmac.new(_CSRF_SECRET, payload, hashlib.sha256).hexdigest()


def csrf_valid(
    supplied: str,
    request_uuid: str,
    target_id: str,
    updated_at: str,
    revision: str = "",
) -> bool:
    expected = csrf_token(request_uuid, target_id, updated_at, revision)
    return hmac.compare_digest(str(supplied or ""), expected)


def operator_from_headers(headers: Mapping[str, Any]) -> str:
    # The existing Nginx Basic Auth credentials are the canonical operator
    # identity. Do not trust arbitrary client-supplied identity headers.
    authorization = str(headers.get("Authorization", ""))
    if authorization.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(
                authorization.split(None, 1)[1],
                validate=True,
            ).decode("utf-8")
            username = decoded.split(":", 1)[0].strip()
            if username:
                return username[:128]
        except (ValueError, UnicodeDecodeError):
            pass
    return ""


def queue_review_request(
    directory: Path,
    request: Mapping[str, Any],
) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o730)
    payload = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    with tempfile.NamedTemporaryFile(
        prefix=".review-",
        suffix=".json",
        dir=directory,
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    destination = directory / f"{request['request_uuid']}.json"
    try:
        os.chmod(temporary, 0o640)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def number(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def status_class(value: Any) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return f"status status-{normalized or 'unknown'}"


def page(
    title: str,
    body: str,
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
) -> bytes:
    generated = when(snapshot.get("generated_at", "unavailable"))
    app_title = h(config.get("title", "Argent Sentinel"))
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{h(title)} · {app_title}</title>
<style>
:root {{
  color-scheme: dark;
  --bg:#0b1020;--panel:#141b2d;--panel2:#1a2338;--text:#e8edf7;
  --muted:#98a6bd;--line:#2d3954;--accent:#8cc8ff;--good:#6ee7a8;
  --warn:#ffd166;--bad:#ff7b86;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}}
header{{padding:20px 28px;border-bottom:1px solid var(--line);background:#0e1527;position:sticky;top:0;z-index:2}}
header h1{{margin:0;font-size:22px}}
header small{{color:var(--muted)}}
nav{{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px}}
nav a{{color:var(--accent);text-decoration:none;font-weight:650}}
main{{padding:24px 28px;max-width:1600px;margin:auto}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:16px 0 28px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}}
.card-link{{display:block;color:inherit;text-decoration:none}}
.card-link:hover{{border-color:var(--accent)}}
.card .value{{font-size:30px;font-weight:750;margin-top:7px}}
.card .label{{color:var(--muted)}}
section{{margin:28px 0}}
h2{{font-size:19px;margin:0 0 12px}}
.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%;min-width:760px;background:var(--panel)}}
th,td{{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{background:var(--panel2);color:#cbd7ea;position:sticky;top:0}}
tr:last-child td{{border-bottom:0}}
.muted{{color:var(--muted)}}
.status{{display:inline-block;padding:2px 8px;border-radius:999px;background:#26324b}}
.status-sent,.status-blocked,.status-healthy,.status-recovered{{color:var(--good)}}
.status-failed,.status-deferred,.status-long-block-review,.status-critical,.status-error{{color:var(--bad)}}
.status-review,.status-escalation-review,.status-suppressed,.status-warning{{color:var(--warn)}}
code{{white-space:pre-wrap;overflow-wrap:anywhere;color:#cde7ff}}
a{{color:var(--accent)}}
.review-form{{display:grid;gap:7px;min-width:240px}}
details{{min-width:340px}} details summary{{cursor:pointer;color:var(--accent)}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:4px 10px}} dt{{color:var(--muted)}} dd{{margin:0}}
select,input,button{{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:7px}}
button{{cursor:pointer;background:#203a5e}}
button:hover{{border-color:var(--accent)}}
footer{{padding:20px 28px;color:var(--muted);border-top:1px solid var(--line)}}
</style>
</head>
<body>
<header>
<h1>{app_title}</h1>
<small>Operator dashboard · snapshot {generated}</small>
<nav>
<a href="/">Overview</a>
<a href="/traffic">Traffic</a>
<a href="/incidents">Incidents</a>
<a href="/networks">Networks</a>
<a href="/reports">Reports</a>
<a href="/reviews">Reviews</a>
<a href="/watchdogs">Watchdogs</a>
<a href="/api/snapshot">JSON</a>
</nav>
</header>
<main>{body}</main>
<footer>Argent Sentinel {h(APP_VERSION)} · review actions are audited; direct enforcement changes are not available from this interface.</footer>
</body>
</html>"""
    return html.encode("utf-8")


def table(headers: list[str], rows_data: list[list[Any]]) -> str:
    if not rows_data:
        return '<div class="card muted">No records in this snapshot.</div>'
    head = "".join(f"<th>{h(value)}</th>" for value in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{value}</td>" for value in row) + "</tr>"
        for row in rows_data
    )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + body
        + "</tbody></table></div>"
    )


def render_overview(snapshot: Mapping[str, Any]) -> str:
    overview = snapshot.get("overview", {})
    cards = [
        ("Events", overview.get("events"), None),
        ("Observations", overview.get("observations"), None),
        ("HTTP 429", overview.get("http_429"), None),
        ("Incidents", overview.get("incidents"), "/incidents"),
        ("Reports sent", overview.get("reports_sent"), "/reports"),
        ("Open review items", overview.get("open_reviews"), "/reviews"),
        (
            "Credential-spray reviews",
            overview.get("credential_spray_reviews"),
            "/reviews",
        ),
        (
            "No-contact enforcement",
            overview.get("no_contact_reviews"),
            "/reviews",
        ),
        (
            "CIDR reviews",
            overview.get("network_reviews"),
            "/networks",
        ),
        (
            "Unhealthy watchdogs",
            overview.get("watchdogs_unhealthy"),
            "/watchdogs",
        ),
    ]
    card_html = "".join(
        (
            f'<a class="card card-link" href="{h(url)}">'
            f'<div class="label">{h(label)}</div>'
            f'<div class="value">{number(value)}</div></a>'
            if url
            else f'<div class="card"><div class="label">{h(label)}</div>'
            f'<div class="value">{number(value)}</div></div>'
        )
        for label, value, url in cards
    )
    fail_rows = [
        [
            h(row.get("jail")),
            number(row.get("count")),
            number(row.get("source_ips")),
            when(row.get("first_seen")),
            when(row.get("last_seen")),
        ]
        for row in snapshot.get("fail2ban", [])
    ]
    rule_rows = [
        [
            h(row.get("rule_id")),
            f'<span class="{status_class(row.get("report_status"))}">'
            f'{h(row.get("report_status"))}</span>',
            number(row.get("count")),
            number(row.get("events")),
            when(row.get("first_seen")),
            when(row.get("last_seen")),
        ]
        for row in snapshot.get("incident_rules", [])
    ]
    awstats_rows = [
        [
            h(row.get("domain")),
            h(", ".join(row.get("aliases", [])) or "-"),
            (
                f'<a href="{h(row.get("url"))}">Open static report</a>'
                if row.get("report_available")
                else '<span class="muted">Not generated</span>'
            ),
            when(row.get("report_mtime")),
        ]
        for row in snapshot.get("awstats_sites", [])
    ]
    return (
        f'<div class="grid">{card_html}</div>'
        "<section><h2>Incident summary</h2>"
        + table(
            ["Rule", "Report status", "Incidents", "Events", "First", "Last"],
            rule_rows,
        )
        + "</section><section><h2>Fail2ban activity</h2>"
        + table(["Jail", "Bans", "IPs", "First", "Last"], fail_rows)
        + "</section><section><h2>Per-site AWStats</h2>"
        + table(["Site", "Aliases", "Report", "Updated"], awstats_rows)
        + "</section>"
    )

def render_watchdogs(snapshot: Mapping[str, Any]) -> str:
    watchdogs = snapshot.get("watchdogs", [])
    rows_data: list[list[Any]] = []
    details_html: list[str] = []
    for item in watchdogs:
        status = item.get("status", "unknown")
        metrics = item.get("metrics", {})
        details = item.get("details", {})
        rows_data.append(
            [
                h(item.get("display_name", item.get("id"))),
                f'<span class="{status_class(status)}">{h(status)}</span>',
                h(item.get("mode")),
                when(item.get("checked_at")),
                number(item.get("consecutive_failures")),
                h(item.get("summary")),
            ]
        )
        history_rows = [
            [
                when(event.get("checked_at")),
                f'<span class="{status_class(event.get("status"))}">{h(event.get("status"))}</span>',
                h(event.get("event")),
                h(event.get("summary")),
            ]
            for event in reversed(item.get("history", [])[-10:])
        ]
        details_html.append(
            '<div class="card">'
            f'<h2>{h(item.get("display_name", item.get("id")))}</h2>'
            '<dl>'
            f'<dt>ID</dt><dd><code>{h(item.get("id"))}</code></dd>'
            f'<dt>Module</dt><dd>{h(item.get("module"))}</dd>'
            f'<dt>Enabled</dt><dd>{h(item.get("enabled"))}</dd>'
            f'<dt>Mode</dt><dd>{h(item.get("mode"))}</dd>'
            f'<dt>Interval</dt><dd>{number(item.get("interval_seconds"))} seconds</dd>'
            f'<dt>Stale</dt><dd>{h(item.get("stale", False))}</dd>'
            f'<dt>Reported state</dt><dd>{h(item.get("reported_status", status))}</dd>'
            f'<dt>Last healthy</dt><dd>{when(item.get("last_healthy_at"))}</dd>'
            f'<dt>Last failure</dt><dd>{when(item.get("last_failure_at"))}</dd>'
            f'<dt>Last transition</dt><dd>{when(item.get("last_transition_at"))}</dd>'
            f'<dt>Duration</dt><dd>{number(item.get("duration_ms"))} ms</dd>'
            f'<dt>Notification failure</dt><dd>{h(item.get("notification_delivery_failed", False))}</dd>'
            '</dl>'
            '<h3>Metrics</h3>'
            f'<code>{h(json.dumps(metrics, indent=2, sort_keys=True, default=str))}</code>'
            '<h3>Details</h3>'
            f'<code>{h(json.dumps(details, indent=2, sort_keys=True, default=str))}</code>'
            '<h3>Recent events</h3>'
            + table(["Time", "State", "Event", "Summary"], history_rows)
            + '</div>'
        )
    return (
        '<section><h2>Watchdog status</h2>'
        + table(["Watchdog", "State", "Mode", "Last check", "Failures", "Summary"], rows_data)
        + '</section><section><h2>Module details</h2><div class="grid">'
        + ''.join(details_html)
        + '</div></section>'
    )


def render_traffic(snapshot: Mapping[str, Any]) -> str:
    source_rows = [
        [
            f"<code>{h(row.get('source_ip'))}</code>",
            number(row.get("hits")),
            number(row.get("source_types")),
            number(row.get("hosts")),
            h(row.get("seen_in")),
            when(row.get("first_seen")),
            when(row.get("last_seen")),
        ]
        for row in snapshot.get("repeated_sources", [])
    ]
    agent_rows = [
        [
            f"<code>{h(row.get('user_agent'))}</code>",
            number(row.get("requests")),
            number(row.get("source_ips")),
            number(row.get("hosts")),
            number(row.get("limited")),
            number(row.get("denied")),
            when(row.get("last_seen")),
        ]
        for row in snapshot.get("top_user_agents", [])
    ]
    crawler_rows = []
    for row in snapshot.get("crawler_groups", []):
        reasons = ", ".join(row.get("review_reasons", [])) or "observing"
        crawler_rows.append(
            [
                f"<code>{h(row.get('prefix'))}</code>",
                h(row.get("identity")),
                f'<span class="{status_class(reasons)}">{h(reasons)}</span>',
                number(row.get("events")),
                number(row.get("distinct_ips")),
                number(row.get("distinct_paths")),
                number(row.get("duration_seconds")),
                h(", ".join(row.get("hosts", [])) or "-"),
            ]
        )
    return (
        "<section><h2>Repeated sources across all ingested logs</h2>"
        + table(
            ["Source", "Hits", "Data types", "Hosts", "Seen in", "First", "Last"],
            source_rows,
        )
        + "</section><section><h2>User agents</h2>"
        + table(
            ["User-Agent", "Requests", "IPs", "Hosts", "429", "444", "Last"],
            agent_rows,
        )
        + "</section><section><h2>Crawler and scraper pressure</h2>"
        + table(
            ["Prefix", "Identity", "Review", "Events", "IPs", "Paths", "Seconds", "Hosts"],
            crawler_rows,
        )
        + "</section>"
    )


def render_incidents(snapshot: Mapping[str, Any]) -> str:
    incident_rows = [
        [
            f"<code>{h(row.get('source_ip'))}</code>",
            h(row.get("rule_id")),
            f'<span class="{status_class(row.get("report_status"))}">{h(row.get("report_status"))}</span>',
            number(row.get("event_count")),
            number(row.get("site_count")),
            f"<code>{h(row.get('registered_cidr') or row.get('network_cidr'))}</code>",
            h(row.get("asn_holder")),
            when(row.get("last_seen")),
            h(row.get("report_detail")),
        ]
        for row in snapshot.get("recent_incidents", [])
    ]
    return "<section><h2>Recent incidents</h2>" + table(
        ["Source", "Rule", "Report", "Events", "Sites", "Network", "Holder", "Last", "Detail"],
        incident_rows,
    ) + "</section>"


def render_networks(
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
) -> str:
    cases = snapshot.get("network_cases", [])
    note_max = int(config.get("review_note_max_chars", 2000))
    open_count = sum(
        str(row.get("review_status") or "open") != "closed"
        for row in cases
    )
    blocked_count = sum(str(row.get("status") or "") == "blocked" for row in cases)
    protected_count = sum(
        row.get("protection_status") == "protected-overlap"
        for row in cases
    )
    cards = (
        '<div class="grid">'
        f'<div class="card"><div class="label">Open CIDR reviews</div>'
        f'<div class="value">{number(open_count)}</div></div>'
        f'<div class="card"><div class="label">Blocked prefixes</div>'
        f'<div class="value">{number(blocked_count)}</div></div>'
        f'<div class="card"><div class="label">Protected overlaps</div>'
        f'<div class="value">{number(protected_count)}</div></div>'
        f'<div class="card"><div class="label">Displayed cases</div>'
        f'<div class="value">{number(len(cases))}</div></div>'
        '</div>'
    )
    labels = {
        "network-block-180": "Block proposed CIDR for 180 days",
        "network-block-365": "Block proposed CIDR for 365 days",
        "network-observe": "Keep observing",
        "network-reject": "Reject recommendation",
        "network-remove-block": "Remove existing CIDR block",
        "network-note": "Add note",
        "network-ack-protected": "Acknowledge protected network",
    }
    network_rows: list[list[Any]] = []
    for row in cases:
        request_uuid = str(uuid.uuid4())
        network_cidr = str(row.get("network_cidr") or "")
        proposal_cidr = str(row.get("proposal_cidr") or "")
        proposal_revision = str(row.get("proposal_revision") or "")
        updated_at = str(row.get("updated_at") or "")
        token = csrf_token(
            request_uuid,
            network_cidr,
            updated_at,
            proposal_revision,
        )
        try:
            coverage = f"{float(row.get('proposal_coverage_percent') or 0):.6f}%"
        except (TypeError, ValueError):
            coverage = "0%"
        evidence = (
            '<details><summary>Proposal and enforcement history</summary><dl>'
            f'<dt>Registered case</dt><dd><code>{h(network_cidr)}</code></dd>'
            f'<dt>Proposed CIDR</dt><dd><code>{h(proposal_cidr)}</code></dd>'
            f'<dt>Proposal revision</dt><dd><code>{h(proposal_revision)}</code></dd>'
            f'<dt>Proposal basis</dt><dd>{h(row.get("proposal_basis"))}</dd>'
            f'<dt>Protection status</dt><dd>{h(row.get("protection_status"))}</dd>'
            f'<dt>Protected by</dt><dd><code>{h(row.get("protected_by_cidr"))}</code> '
            f'({h(row.get("protection_source"))}) '
            f'{h(row.get("protected_by_nodes"))}</dd>'
            f'<dt>Proposal hostile IPs</dt><dd>{number(row.get("proposal_hostile_ips"))}</dd>'
            f'<dt>Proposal incidents/events</dt><dd>'
            f'{number(row.get("proposal_incident_count"))} / '
            f'{number(row.get("proposal_event_count"))}</dd>'
            f'<dt>Proposal active days</dt><dd>{number(row.get("proposal_active_days"))}</dd>'
            f'<dt>Address-space coverage</dt><dd>{h(coverage)}</dd>'
            f'<dt>Review disposition</dt><dd>{h(row.get("review_disposition"))}</dd>'
            f'<dt>Operator notes</dt><dd>{h(row.get("review_note") or row.get("operator_note"))}</dd>'
            f'<dt>Decision CIDR</dt><dd><code>{h(row.get("decision_cidr"))}</code></dd>'
            f'<dt>Decision</dt><dd>{h(row.get("decision_status"))}: '
            f'{h(row.get("decision_detail"))}</dd>'
            f'<dt>Decision duration</dt><dd>{number(row.get("decision_duration_days"))} days</dd>'
            f'<dt>Decision applied</dt><dd>{when(row.get("decision_applied_at"))}</dd>'
            '</dl></details>'
        )
        actions = [str(value) for value in row.get("available_actions", [])]
        if actions:
            options = "".join(
                f'<option value="{h(action)}">{h(labels.get(action, action))}</option>'
                for action in actions
            )
            controls = f"""
<form class="review-form" method="post" action="/networks/action">
<input type="hidden" name="request_uuid" value="{h(request_uuid)}">
<input type="hidden" name="network_cidr" value="{h(network_cidr)}">
<input type="hidden" name="proposal_cidr" value="{h(proposal_cidr)}">
<input type="hidden" name="proposal_revision" value="{h(proposal_revision)}">
<input type="hidden" name="expected_updated_at" value="{h(updated_at)}">
<input type="hidden" name="csrf_token" value="{h(token)}">
<select name="action" required>{options}</select>
<input type="text" name="note" maxlength="{note_max}" placeholder="Justification or operator note">
<button type="submit">Queue action</button>
</form>"""
        else:
            controls = '<span class="muted">No action until evidence changes</span>'
        display_status = str(row.get("status") or "")
        if row.get("protection_status") == "protected-overlap":
            display_status = f"{display_status} / protected"
        network_rows.append(
            [
                f'<code>{h(network_cidr)}</code>',
                f'<span class="{status_class(row.get("status"))}">{h(display_status)}</span>',
                f'<span class="{status_class(row.get("review_status"))}">{h(row.get("review_status"))}</span>',
                f'<code>{h(proposal_cidr)}</code>',
                number(row.get("proposal_hostile_ips")),
                coverage,
                number(row.get("active_days")),
                h(row.get("asns")),
                h(row.get("network_classes")),
                when(row.get("last_seen")),
                evidence,
                controls,
            ]
        )
    action_rows = [
        [
            when(row.get("applied_at")),
            h(row.get("operator")),
            h(row.get("action")),
            h(row.get("disposition")),
            f'<code>{h(row.get("network_cidr"))}</code>',
            f'<code>{h(row.get("proposal_cidr"))}</code>',
            h(row.get("previous_status")),
            h(row.get("new_status")),
            h(row.get("decision_status")),
            h(row.get("decision_detail")),
            h(row.get("note")),
        ]
        for row in snapshot.get("network_review_actions", [])
    ]
    protection = snapshot.get("local_address_protection", {})
    node_rows: list[list[Any]] = []
    for node in protection.get("nodes", []) if isinstance(protection, Mapping) else []:
        cidrs = node.get("effective_cidrs", [])
        addresses = node.get("addresses", [])
        address_text = ", ".join(
            f"{item.get('interface')}={item.get('address')}/{item.get('prefix_length')}"
            for item in addresses
            if isinstance(item, Mapping)
        )
        node_rows.append(
            [
                h(node.get("node_id")),
                h(node.get("configured_mode")),
                h(node.get("effective_mode")),
                h(node.get("freshness")),
                "yes" if node.get("operator_confirmed") else "no",
                h(node.get("selection_source")),
                h(address_text),
                "<br>".join(f"<code>{h(value)}</code>" for value in cidrs),
                when(node.get("generated_at")),
            ]
        )
    state_status = protection.get("state_status", "unknown") if isinstance(
        protection, Mapping
    ) else "unknown"
    state_age = protection.get("state_age_seconds") if isinstance(
        protection, Mapping
    ) else None
    protection_section = (
        '<section><h2>Dynamic local-address protection</h2>'
        '<p class="muted">Authenticated node inventories add a dynamic '
        'never-block boundary. Host mode protects current /128 addresses; '
        'confirmed LAN-prefix mode follows current connected prefixes.</p>'
        f'<p>Effective-state publication: <strong>{h(state_status)}</strong>; '
        f'age: {h(state_age if state_age is not None else "unknown")} seconds.</p>'
        + table(
            [
                "Node", "Configured", "Effective", "Freshness", "Confirmed",
                "Source", "Discovered addresses", "Protected CIDRs", "Generated",
            ],
            node_rows,
        )
        + '</section>'
    )
    return (
        cards
        + protection_section
        + '<section><h2>Audited CIDR review and enforcement</h2>'
        + '<p class="muted">Registered allocations remain ownership scopes. '
        'Only the displayed most-specific bounded proposal is eligible for a '
        'manual CrowdSec range decision. Block actions require an operator '
        'justification and never bypass allowlists.</p>'
        + table(
            [
                "Registered case", "Recommendation", "Review", "Proposal",
                "Proposal IPs", "Coverage", "Days", "ASNs", "Class", "Last",
                "Evidence", "Action",
            ],
            network_rows,
        )
        + '</section><section><h2>Recent CIDR review actions</h2>'
        + table(
            [
                "Applied", "Operator", "Action", "Disposition", "Case",
                "Proposal", "Previous", "New", "Decision", "Detail", "Note",
            ],
            action_rows,
        )
        + '</section>'
    )


def render_reports(snapshot: Mapping[str, Any]) -> str:
    reporting = snapshot.get("reporting", {})
    counts = reporting.get("status_counts", {})
    last_run = reporting.get("last_run", {})
    preparation = last_run.get("preparation", {})
    cards = [
        ("Mode", reporting.get("mode", "unknown")),
        ("Queued groups", len(reporting.get("queued_groups", []))),
        ("Sent incidents", counts.get("sent", 0)),
        ("Deferred", counts.get("deferred", 0)),
        ("Failed", counts.get("failed", 0)),
        ("No contact", counts.get("no-contact", 0)),
        ("Suppressed", counts.get("suppressed", 0)),
    ]
    card_html = "".join(
        f'<div class="card"><div class="label">{h(label)}</div>'
        f'<div class="value">{h(value)}</div></div>'
        for label, value in cards
    )
    run_rows = [
        [
            when(last_run.get("generated_at")),
            when(reporting.get("next_scheduled_at")),
            h(last_run.get("status")),
            number(last_run.get("groups")),
            number(last_run.get("messages_sent")),
            number(last_run.get("messages_failed")),
            number(preparation.get("eligible")),
            number(preparation.get("suppressed")),
            when(reporting.get("production_cutoff")),
        ]
    ]
    queue_rows = [
        [
            (
                f'<span class="bad"><code>{h(row.get("batch_cidr"))}</code></span>'
                if row.get("broad_registered_allocation")
                else f'<code>{h(row.get("batch_cidr"))}</code>'
            ),
            h(", ".join(row.get("registered_allocations", [])) or "-"),
            h(row.get("grouping_basis")),
            h(row.get("family")),
            h(row.get("recipients")),
            number(row.get("incident_count")),
            number(row.get("event_count")),
            h(", ".join(row.get("source_ips", [])) or "-"),
            when(row.get("last_seen")),
        ]
        for row in reporting.get("queued_groups", [])
    ]
    suppression_rows = [
        [
            f"<code>{h(row.get('source_ip'))}</code>",
            h(row.get("rule_id")),
            f"<code>{h(row.get('registered_cidr') or row.get('network_cidr'))}</code>",
            h(row.get("asn")),
            h(row.get("asn_holder")),
            when(row.get("last_seen")),
            h(row.get("report_detail")),
        ]
        for row in reporting.get("ban_only_suppressions", [])
    ]
    message_rows = [
        [
            when(row.get("attempted_at")),
            h(row.get("recipients")),
            number(row.get("incident_count")),
            h(row.get("statuses")),
            f"<code>{h(row.get('message_id'))}</code>",
            h(row.get("detail")),
        ]
        for row in reporting.get("recent_messages", [])
    ]
    report_rows = [
        [
            when(row.get("attempted_at")),
            h(row.get("recipient")),
            f'<span class="{status_class(row.get("status"))}">{h(row.get("status"))}</span>',
            h(row.get("test_mode")),
            h(row.get("detail")),
            f"<code>{h(row.get('message_id'))}</code>",
        ]
        for row in snapshot.get("report_attempts", [])
    ]
    return (
        f'<div class="grid">{card_html}</div>'
        "<section><h2>Hourly batch runtime</h2>"
        + table(
            [
                "Last run",
                "Next run",
                "Status",
                "Groups",
                "Sent",
                "Failed",
                "Eligible",
                "Suppressed",
                "Production cutoff",
            ],
            run_rows,
        )
        + "</section><section><h2>Queued hourly groups</h2>"
        + '<p class="muted">Red batch prefixes indicate a registered allocation '
        "broader than the configured evidence-grouping boundary.</p>"
        + table(
            [
                "Batch CIDR",
                "Registered allocation(s)",
                "Basis",
                "Family",
                "Recipients",
                "Incidents",
                "Events",
                "Sources",
                "Latest",
            ],
            queue_rows,
        )
        + "</section><section><h2>Ban-only suppressions</h2>"
        + table(
            [
                "Source",
                "Rule",
                "Network",
                "ASN",
                "Holder",
                "Last",
                "Reason",
            ],
            suppression_rows,
        )
        + "</section><section><h2>Recent outbound messages</h2>"
        + table(
            [
                "Attempted",
                "Recipients",
                "Incidents",
                "Status",
                "Message ID",
                "Detail",
            ],
            message_rows,
        )
        + "</section><section><h2>Recent report attempts</h2>"
        + table(
            ["Attempted", "Recipient", "Status", "Test", "Detail", "Message ID"],
            report_rows,
        )
        + "</section>"
    )

def render_reviews(
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
) -> str:
    reviews = snapshot.get("reviews", {})
    items = reviews.get("items", [])
    counts = reviews.get("category_counts", {})
    note_max = int(config.get("review_note_max_chars", 2000))
    cards = (
        '<div class="grid">'
        f'<div class="card"><div class="label">Open items</div>'
        f'<div class="value">{number(reviews.get("open_count"))}</div></div>'
        f'<div class="card"><div class="label">Credential spray</div>'
        f'<div class="value">{number(counts.get("credential_spray"))}</div></div>'
        f'<div class="card"><div class="label">No-contact enforcement</div>'
        f'<div class="value">{number(counts.get("no_contact"))}</div></div>'
        f'<div class="card"><div class="label">Delivery failures</div>'
        f'<div class="value">{number(counts.get("delivery_failed"))}</div></div>'
        f'<div class="card"><div class="label">Displayed</div>'
        f'<div class="value">{number(len(items))}</div></div>'
        '</div>'
    )
    action_labels = {
        "acknowledge": "Acknowledge",
        "retry": "Retry next batch",
        "suppress": "Suppress report",
        "permanent-no-contact": "Permanent no contact",
        "approve-report": "Approve provider report",
        "keep-suppressed": "Keep suppressed and close",
        "duplicate-subsumed": "Close as duplicate/subsumed",
        "refresh-contact": "Refresh abuse contact",
        "note": "Add note",
    }
    item_rows: list[list[Any]] = []
    for row in items:
        request_uuid = str(uuid.uuid4())
        incident_uuid = str(row.get("incident_uuid") or "")
        updated_at = str(row.get("updated_at") or "")
        token = csrf_token(request_uuid, incident_uuid, updated_at)
        attempt_rows = [
            [
                when(attempt.get("attempted_at")),
                h(attempt.get("recipient")),
                f'<span class="{status_class(attempt.get("status"))}">'
                f'{h(attempt.get("status"))}</span>',
                h(attempt.get("detail")),
                f'<code>{h(attempt.get("message_id"))}</code>',
            ]
            for attempt in row.get("recent_attempts", [])
        ]
        evidence = (
            '<details><summary>Incident and attempt history</summary>'
            '<dl>'
            f'<dt>Incident UUID</dt><dd><code>{h(incident_uuid)}</code></dd>'
            f'<dt>Network</dt><dd>{h(row.get("network_cidr"))}</dd>'
            f'<dt>Registered allocation</dt><dd>{h(row.get("registered_cidr"))}</dd>'
            f'<dt>ASN</dt><dd>{h(row.get("asn"))} {h(row.get("asn_holder"))}</dd>'
            f'<dt>Targeted accounts</dt><dd>{number(row.get("distinct_accounts"))}</dd>'
            f'<dt>Sites</dt><dd>{number(row.get("site_count"))}</dd>'
            f'<dt>Decision</dt><dd>{h(row.get("decision_status"))}: '
            f'{h(row.get("decision_detail"))}</dd>'
            f'<dt>Review disposition</dt><dd>{h(row.get("review_disposition"))}</dd>'
            f'<dt>Operator notes</dt><dd>{h(row.get("review_note"))}</dd>'
            '</dl>'
            + table(
                ["Attempted", "Recipient", "Status", "Detail", "Message ID"],
                attempt_rows,
            )
            + '</details>'
        )
        actions = row.get("available_actions") or [
            "acknowledge",
            "retry",
            "suppress",
            "permanent-no-contact",
            "note",
        ]
        options = "".join(
            f'<option value="{h(action)}">'
            f'{h(action_labels.get(str(action), str(action)))}</option>'
            for action in actions
        )
        controls = f"""
<form class="review-form" method="post" action="/reviews/action">
<input type="hidden" name="request_uuid" value="{h(request_uuid)}">
<input type="hidden" name="incident_uuid" value="{h(incident_uuid)}">
<input type="hidden" name="expected_updated_at" value="{h(updated_at)}">
<input type="hidden" name="csrf_token" value="{h(token)}">
<select name="action" required>{options}</select>
<input type="text" name="note" maxlength="{note_max}" placeholder="Operator note">
<button type="submit">Queue action</button>
</form>"""
        item_rows.append(
            [
                f'<code>{h(row.get("source_ip"))}</code>',
                h(row.get("rule_id")),
                f'<span class="{status_class(row.get("review_reason"))}">'
                f'{h(row.get("review_reason"))}</span>',
                f'<span class="{status_class(row.get("report_status"))}">'
                f'{h(row.get("report_status"))}</span>',
                number(row.get("attempt_count")),
                h(row.get("latest_recipient") or row.get("report_recipient")),
                when(row.get("first_seen")),
                when(row.get("last_seen")),
                h(row.get("report_detail") or row.get("latest_attempt_detail")),
                evidence,
                controls,
            ]
        )
    action_rows = [
        [
            when(row.get("applied_at")),
            h(row.get("operator")),
            h(row.get("action")),
            h(row.get("disposition")),
            f'<code>{h(row.get("incident_uuid"))}</code>',
            h(row.get("previous_report_status")),
            h(row.get("new_report_status")),
            h(row.get("note")),
        ]
        for row in reviews.get("recent_actions", [])
    ]
    return (
        cards
        + '<section><h2>Open review items</h2>'
        + '<p class="muted">Credential-spray suppressions have explicit '
        'approval and closure actions. No-contact items close automatically '
        'only after local CrowdSec enforcement is verified.</p>'
        + table(
            [
                "Source", "Rule", "Reason", "Report", "Attempts",
                "Recipient", "First", "Last", "Detail", "Evidence",
                "Action",
            ],
            item_rows,
        )
        + '</section><section><h2>Recent review actions</h2>'
        + table(
            [
                "Applied", "Operator", "Action", "Disposition",
                "Incident", "Previous", "New", "Note",
            ],
            action_rows,
        )
        + '</section>'
    )

class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = f"ArgentSentinelDashboard/{APP_VERSION}"

    @property
    def app_config(self) -> Mapping[str, Any]:
        return getattr(self.server, "app_config")

    def log_message(self, format_string: str, *args: Any) -> None:
        LOG.info("%s - %s", self.client_address, format_string % args)

    def send_payload(
        self,
        status: int,
        payload: bytes,
        content_type: str,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    def send_redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path not in {"/reviews/action", "/networks/action"}:
            self.send_payload(404, b"Not found\n", "text/plain")
            return
        try:
            content_type = str(self.headers.get("Content-Type", ""))
            if not content_type.startswith("application/x-www-form-urlencoded"):
                raise DashboardError("Unsupported form content type")
            length = int(self.headers.get("Content-Length", "0"))
            maximum = int(self.app_config["max_post_bytes"])
            if length < 1 or length > maximum:
                raise DashboardError("Review form size is invalid")
            raw = self.rfile.read(length).decode("utf-8")
            form = urllib.parse.parse_qs(
                raw,
                keep_blank_values=True,
                strict_parsing=True,
            )
            value = lambda name: str(form.get(name, [""])[0]).strip()
            request_uuid = str(uuid.UUID(value("request_uuid")))
            expected_updated_at = value("expected_updated_at")
            action = value("action")
            note = value("note")
            if len(note) > int(self.app_config["review_note_max_chars"]):
                raise DashboardError("Review note exceeds configured limit")
            operator = operator_from_headers(self.headers)
            if not operator:
                raise DashboardError(
                    "Authenticated operator identity was not forwarded"
                )
            snapshot = load_snapshot(self.app_config)
            requested_at = (
                dt.datetime.now(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )

            if parsed.path == "/reviews/action":
                incident_uuid = str(uuid.UUID(value("incident_uuid")))
                if action not in REVIEW_ACTIONS or action in NETWORK_REVIEW_ACTIONS:
                    raise DashboardError("Unsupported incident review action")
                if not csrf_valid(
                    value("csrf_token"),
                    request_uuid,
                    incident_uuid,
                    expected_updated_at,
                ):
                    raise DashboardError("Invalid or expired review form token")
                matching = [
                    row
                    for row in snapshot.get("reviews", {}).get("items", [])
                    if str(row.get("incident_uuid")) == incident_uuid
                ]
                if len(matching) != 1:
                    raise DashboardError("Incident is no longer in the review queue")
                item = matching[0]
                if str(item.get("updated_at")) != expected_updated_at:
                    raise DashboardError("Incident changed; reload the review page")
                if action not in item.get("available_actions", []):
                    raise DashboardError("Action is no longer available")
                request = {
                    "request_uuid": request_uuid,
                    "target_type": "incident",
                    "incident_uuid": incident_uuid,
                    "expected_updated_at": expected_updated_at,
                    "action": action,
                    "operator": operator,
                    "note": note,
                    "requested_at": requested_at,
                }
                redirect = "/reviews?queued=" + urllib.parse.quote(request_uuid)
            else:
                try:
                    network_cidr = str(
                        ipaddress.ip_network(value("network_cidr"), strict=False)
                    )
                except ValueError as exc:
                    raise DashboardError("Invalid network review CIDR") from exc
                proposal_cidr = value("proposal_cidr")
                if proposal_cidr:
                    try:
                        proposal_cidr = str(
                            ipaddress.ip_network(proposal_cidr, strict=False)
                        )
                    except ValueError as exc:
                        raise DashboardError("Invalid proposed CIDR") from exc
                proposal_revision = value("proposal_revision")
                if action not in NETWORK_REVIEW_ACTIONS:
                    raise DashboardError("Unsupported network review action")
                if not csrf_valid(
                    value("csrf_token"),
                    request_uuid,
                    network_cidr,
                    expected_updated_at,
                    proposal_revision,
                ):
                    raise DashboardError("Invalid or expired network review token")
                matching = [
                    row
                    for row in snapshot.get("network_cases", [])
                    if str(row.get("network_cidr")) == network_cidr
                ]
                if len(matching) != 1:
                    raise DashboardError("Network case is no longer available")
                item = matching[0]
                if str(item.get("updated_at")) != expected_updated_at:
                    raise DashboardError("Network case changed; reload the page")
                if str(item.get("proposal_revision") or "") != proposal_revision:
                    raise DashboardError("Network proposal changed; reload the page")
                if str(item.get("proposal_cidr") or "") != proposal_cidr:
                    raise DashboardError("Proposed CIDR changed; reload the page")
                if action not in item.get("available_actions", []):
                    raise DashboardError("Network action is no longer available")
                if action in {"network-block-180", "network-block-365"} and not note:
                    raise DashboardError(
                        "CIDR block actions require an operator justification"
                    )
                request = {
                    "request_uuid": request_uuid,
                    "target_type": "network",
                    "network_cidr": network_cidr,
                    "proposal_cidr": proposal_cidr,
                    "proposal_revision": proposal_revision,
                    "expected_updated_at": expected_updated_at,
                    "action": action,
                    "operator": operator,
                    "note": note,
                    "requested_at": requested_at,
                }
                redirect = "/networks?queued=" + urllib.parse.quote(request_uuid)

            queue_review_request(
                Path(str(self.app_config["review_request_dir"])),
                request,
            )
            self.send_redirect(redirect)
        except (
            DashboardError,
            UnicodeDecodeError,
            ValueError,
            OSError,
        ) as exc:
            payload = page(
                "Review action rejected",
                '<div class="card"><h2>Review action rejected</h2>'
                f'<code>{h(exc)}</code></div>',
                {"generated_at": "unavailable"},
                self.app_config,
            )
            self.send_payload(400, payload, "text/html; charset=utf-8")

    def do_HEAD(self) -> None:
        self.do_GET(send_body=False)

    def do_GET(self, send_body: bool = True) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        try:
            snapshot = load_snapshot(self.app_config)
            if path == "/healthz":
                payload = json.dumps(
                    {
                        "status": "ok",
                        "version": APP_VERSION,
                        "snapshot_generated_at": snapshot.get("generated_at"),
                    },
                    sort_keys=True,
                ).encode("utf-8")
                if send_body:
                    self.send_payload(200, payload, "application/json")
                else:
                    self.send_payload(200, b"", "application/json")
                return
            if path == "/api/snapshot":
                payload = json.dumps(
                    snapshot,
                    indent=2,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
                self.send_payload(
                    200,
                    payload if send_body else b"",
                    "application/json",
                )
                return
            if path == "/":
                title, body = "Overview", render_overview(snapshot)
            elif path == "/traffic":
                title, body = "Traffic", render_traffic(snapshot)
            elif path == "/incidents":
                title, body = "Incidents", render_incidents(snapshot)
            elif path == "/networks":
                title, body = "Networks", render_networks(
                    snapshot,
                    self.app_config,
                )
            elif path == "/reports":
                title, body = "Reports", render_reports(snapshot)
            elif path == "/reviews":
                title, body = "Reviews", render_reviews(
                    snapshot,
                    self.app_config,
                )
            elif path == "/watchdogs":
                title, body = "Watchdogs", render_watchdogs(snapshot)
            else:
                self.send_payload(404, b"Not found\n", "text/plain")
                return
            payload = page(title, body, snapshot, self.app_config)
            self.send_payload(
                200,
                payload if send_body else b"",
                "text/html; charset=utf-8",
            )
        except DashboardError as exc:
            payload = page(
                "Unavailable",
                f'<div class="card"><h2>Dashboard unavailable</h2><code>{h(exc)}</code></div>',
                {"generated_at": "unavailable"},
                self.app_config,
            )
            self.send_payload(
                503,
                payload if send_body else b"",
                "text/html; charset=utf-8",
            )


def serve(config: Mapping[str, Any]) -> None:
    socket_path = Path(str(config["socket_path"]))
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    server = UnixHTTPServer(str(socket_path), Handler)
    setattr(server, "app_config", config)
    try:
        mode = int(str(config["socket_mode"]), 8)
        os.chmod(socket_path, mode)
        try:
            group_id = grp.getgrnam(str(config["socket_group"])).gr_gid
        except KeyError as exc:
            raise DashboardError(
                f"Unknown socket group: {config['socket_group']}"
            ) from exc
        os.chown(socket_path, -1, group_id)
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="/etc/argent-sentinel/dashboard.json",
    )
    parser.add_argument(
        "command",
        choices=("serve", "validate-config"),
        nargs="?",
        default="serve",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(
                json.dumps(
                    {"status": "ok", "version": APP_VERSION},
                    sort_keys=True,
                )
            )
            return 0
        serve(config)
    except (OSError, DashboardError) as exc:
        LOG.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
