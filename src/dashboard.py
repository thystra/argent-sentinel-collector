#!/usr/bin/env python3
"""Read-only Argent Sentinel operator dashboard."""

from __future__ import annotations

import argparse
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

APP_VERSION = "0.5.0.4"
LOG = logging.getLogger("argent-sentinel-dashboard")

DEFAULTS: dict[str, Any] = {
    "socket_path": "/run/argent-sentinel-dashboard/dashboard.sock",
    "socket_group": "www-data",
    "socket_mode": "0660",
    "snapshot_file": "/var/lib/argent-sentinel/dashboard/snapshot.json",
    "title": "Argent Sentinel",
    "awstats_url_prefix": "/awstats/",
    "max_json_bytes": 20 * 1024 * 1024,
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
    generated = h(snapshot.get("generated_at", "unavailable"))
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
.status-sent,.status-blocked{{color:var(--good)}}
.status-failed,.status-deferred,.status-long-block-review{{color:var(--bad)}}
.status-review,.status-escalation-review,.status-suppressed{{color:var(--warn)}}
code{{white-space:pre-wrap;overflow-wrap:anywhere;color:#cde7ff}}
a{{color:var(--accent)}}
footer{{padding:20px 28px;color:var(--muted);border-top:1px solid var(--line)}}
</style>
</head>
<body>
<header>
<h1>{app_title}</h1>
<small>Read-only operator dashboard · snapshot {generated}</small>
<nav>
<a href="/">Overview</a>
<a href="/traffic">Traffic</a>
<a href="/incidents">Incidents</a>
<a href="/networks">Networks</a>
<a href="/reports">Reports</a>
<a href="/api/snapshot">JSON</a>
</nav>
</header>
<main>{body}</main>
<footer>Argent Sentinel {h(APP_VERSION)} · enforcement changes are not available from this interface.</footer>
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
        ("Events", overview.get("events")),
        ("Observations", overview.get("observations")),
        ("HTTP 429", overview.get("http_429")),
        ("Incidents", overview.get("incidents")),
        ("Reports sent", overview.get("reports_sent")),
        ("Reports needing review", overview.get("reports_failed")),
    ]
    card_html = "".join(
        f'<div class="card"><div class="label">{h(label)}</div>'
        f'<div class="value">{number(value)}</div></div>'
        for label, value in cards
    )
    fail_rows = [
        [
            h(row.get("jail")),
            number(row.get("count")),
            number(row.get("source_ips")),
            h(row.get("first_seen")),
            h(row.get("last_seen")),
        ]
        for row in snapshot.get("fail2ban", [])
    ]
    rule_rows = [
        [
            h(row.get("rule_id")),
            f'<span class="{status_class(row.get("report_status"))}">{h(row.get("report_status"))}</span>',
            number(row.get("count")),
            number(row.get("events")),
            h(row.get("first_seen")),
            h(row.get("last_seen")),
        ]
        for row in snapshot.get("incident_rules", [])
    ]
    awstats = snapshot.get("awstats_sites", [])
    awstats_rows = [
        [
            h(row.get("domain")),
            h(", ".join(row.get("aliases", [])) or "-"),
            (
                f'<a href="{h(row.get("url"))}">Open static report</a>'
                if row.get("report_available")
                else '<span class="muted">Not generated</span>'
            ),
            h(row.get("report_mtime")),
        ]
        for row in awstats
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


def render_traffic(snapshot: Mapping[str, Any]) -> str:
    source_rows = [
        [
            f"<code>{h(row.get('source_ip'))}</code>",
            number(row.get("hits")),
            number(row.get("source_types")),
            number(row.get("hosts")),
            h(row.get("seen_in")),
            h(row.get("first_seen")),
            h(row.get("last_seen")),
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
            h(row.get("last_seen")),
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
            h(row.get("last_seen")),
            h(row.get("report_detail")),
        ]
        for row in snapshot.get("recent_incidents", [])
    ]
    return "<section><h2>Recent incidents</h2>" + table(
        ["Source", "Rule", "Report", "Events", "Sites", "Network", "Holder", "Last", "Detail"],
        incident_rows,
    ) + "</section>"


def render_networks(snapshot: Mapping[str, Any]) -> str:
    network_rows = [
        [
            f"<code>{h(row.get('network_cidr'))}</code>",
            f'<span class="{status_class(row.get("status"))}">{h(row.get("status"))}</span>',
            h(row.get("grouping_basis")),
            number(row.get("hostile_ips")),
            number(row.get("incident_count")),
            number(row.get("active_days")),
            (
                f"{number(row.get('suggested_block_days'))} days"
                if row.get("suggested_block_days")
                else "-"
            ),
            h(row.get("asns")),
            h(row.get("network_classes")),
            h(row.get("last_seen")),
            h(row.get("operator_note")),
        ]
        for row in snapshot.get("network_cases", [])
    ]
    return "<section><h2>CIDR and registered-network cases</h2>" + table(
        ["Network", "Status", "Basis", "IPs", "Incidents", "Days", "Suggested block", "ASNs", "Class", "Last", "Note"],
        network_rows,
    ) + "</section>"


def render_reports(snapshot: Mapping[str, Any]) -> str:
    report_rows = [
        [
            h(row.get("attempted_at")),
            h(row.get("recipient")),
            f'<span class="{status_class(row.get("status"))}">{h(row.get("status"))}</span>',
            h(row.get("test_mode")),
            h(row.get("detail")),
            f"<code>{h(row.get('message_id'))}</code>",
        ]
        for row in snapshot.get("report_attempts", [])
    ]
    return "<section><h2>Recent report attempts</h2>" + table(
        ["Attempted", "Recipient", "Status", "Test", "Detail", "Message ID"],
        report_rows,
    ) + "</section>"


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
            "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

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
                title, body = "Networks", render_networks(snapshot)
            elif path == "/reports":
                title, body = "Reports", render_reports(snapshot)
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
