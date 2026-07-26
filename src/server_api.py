#!/usr/bin/env python3
"""Argent Sentinel central ingestion API.

The service listens on a Unix socket.  Nginx terminates TLS, requires a valid
client certificate, removes client-supplied identity headers, and forwards the
certificate subject as X-Argent-Client-DN plus X-Argent-Client-Verify=SUCCESS.
"""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import socketserver
import sqlite3
import tempfile
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Mapping, Sequence

APP_VERSION = "0.5.1.0"
LOG = logging.getLogger("argent-sentinel-api")

DEFAULTS: dict[str, Any] = {
    "socket_path": "/run/argent-sentinel-api/api.sock",
    "socket_group": "www-data",
    "socket_mode": "0660",
    "max_request_bytes": 30 * 1024 * 1024,
    "nodes_dir": "/etc/argent-sentinel/nodes.d",
    "receipt_db": "/var/lib/argent-sentinel/server/ingress.sqlite3",
    "event_drop_root": "/var/lib/argent-sentinel/drop/remote",
    "require_proxy_verified_client": True,
}


class APIError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


CLIENT_CN_RE = re.compile(
    r"(?:^|[,/])\s*CN=([A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?)(?=\s*(?:[,/]|$))"
)


def client_node_from_subject(subject: str) -> str:
    """Extract one conservative node ID from Nginx's standard client subject DN."""
    matches = CLIENT_CN_RE.findall(str(subject or "").strip())
    if len(matches) != 1:
        raise APIError(403, "Client certificate must contain exactly one simple CN")
    return normalize_node_id(matches[0])


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
        raise APIError(500, f"Server API configuration missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise APIError(500, f"Invalid Server API JSON: {exc}") from exc
    if not isinstance(supplied, dict):
        raise APIError(500, "Server API configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    validate_config(config)
    return config


def validate_config(config: Mapping[str, Any]) -> None:
    if int(config.get("max_request_bytes", 0)) < 1024:
        raise APIError(500, "max_request_bytes must be at least 1024")
    mode = str(config.get("socket_mode", ""))
    if not re.fullmatch(r"0?[0-7]{3,4}", mode):
        raise APIError(500, "socket_mode must be an octal permission string")


def atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def normalize_node_id(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise APIError(403, "Invalid node identity")
    return value


def load_node(nodes_dir: Path, node_id: str) -> dict[str, Any]:
    path = nodes_dir / f"{node_id}.json"
    try:
        item = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise APIError(403, "Node is not enrolled") from exc
    except json.JSONDecodeError as exc:
        raise APIError(500, f"Invalid node enrollment file: {path}") from exc
    if not isinstance(item, dict) or str(item.get("node_id", "")) != node_id:
        raise APIError(500, f"Node enrollment mismatch: {path}")
    if item.get("enabled", True) is not True:
        raise APIError(403, "Node enrollment is disabled")
    return item


def decode_envelope(raw: bytes, expected_node: str, max_payload: int) -> tuple[dict[str, Any], bytes]:
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise APIError(400, f"Invalid JSON envelope: {exc}") from exc
    if not isinstance(envelope, dict) or envelope.get("schema_version") != 1:
        raise APIError(400, "Unsupported transport envelope schema")
    try:
        transport_uuid = str(uuid.UUID(str(envelope.get("transport_uuid", ""))))
    except ValueError as exc:
        raise APIError(400, "Invalid transport_uuid") from exc
    node_id = normalize_node_id(str(envelope.get("node_id", "")))
    if node_id != expected_node:
        raise APIError(403, "Envelope node_id does not match client certificate")
    kind = str(envelope.get("kind", ""))
    if kind not in {"event_batch", "abuse_context"}:
        raise APIError(400, "Unsupported transport kind")
    try:
        payload = base64.b64decode(str(envelope.get("payload_b64", "")), validate=True)
    except Exception as exc:
        raise APIError(400, "payload_b64 is invalid") from exc
    if not payload or len(payload) > max_payload:
        raise APIError(413, "Decoded payload size is outside limits")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != str(envelope.get("payload_sha256", "")).lower():
        raise APIError(400, "Payload digest mismatch")
    normalized = dict(envelope)
    normalized["transport_uuid"] = transport_uuid
    normalized["node_id"] = node_id
    normalized["kind"] = kind
    normalized["payload_sha256"] = digest
    return normalized, payload


def validate_event_batch(payload: bytes, node: Mapping[str, Any]) -> tuple[str, str]:
    try:
        batch = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise APIError(400, f"Event batch is invalid JSON: {exc}") from exc
    if not isinstance(batch, dict) or batch.get("schema_version") != 1:
        raise APIError(400, "Unsupported event batch schema")
    source = batch.get("source")
    if not isinstance(source, dict):
        raise APIError(400, "Event batch source is missing")
    source_host = str(source.get("host", ""))
    service = str(source.get("service", ""))
    site_id = str(source.get("site_id", ""))
    if source_host != str(node["node_id"]):
        raise APIError(403, "Event source.host is not authorized for this node")
    allowed_services = {str(value) for value in node.get("services", [])}
    if allowed_services and service not in allowed_services:
        raise APIError(403, f"Service {service!r} is not authorized for this node")
    allowed_sites = {str(value) for value in node.get("site_ids", [])}
    if service == "wordpress" and allowed_sites and site_id not in allowed_sites:
        raise APIError(403, f"WordPress site {site_id!r} is not authorized for this node")
    if service not in {"wordpress", "sshd"}:
        raise APIError(400, f"Unsupported event service: {service}")
    try:
        uuid.UUID(str(batch.get("batch_uuid", "")))
    except ValueError as exc:
        raise APIError(400, "Invalid event batch UUID") from exc
    if not isinstance(batch.get("events"), list) or not batch["events"]:
        raise APIError(400, "Event batch must contain events")
    return service, site_id


def validate_abuse_context(payload: bytes, node: Mapping[str, Any]) -> None:
    # Perform a bounded structural check.  Full normalization remains in the
    # collector so one parser governs both local and remote observations.
    count = 0
    stripped = payload.lstrip()
    if stripped.startswith(b"["):
        try:
            rows = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise APIError(400, f"Abuse-context JSON is invalid: {exc}") from exc
        if not isinstance(rows, list):
            raise APIError(400, "Abuse-context JSON root must be an array")
        count = len(rows)
    else:
        for line in payload.splitlines():
            if not line.strip():
                continue
            if len(line) > 65536:
                raise APIError(400, "Abuse-context line exceeds 64 KiB")
            try:
                row = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise APIError(400, f"Abuse-context JSONL is invalid: {exc}") from exc
            if not isinstance(row, dict):
                raise APIError(400, "Abuse-context rows must be objects")
            source_host = row.get("source_host")
            if source_host not in (None, "", node["node_id"]):
                raise APIError(403, "Abuse-context source_host is not authorized")
            count += 1
    if count < 1 or count > 200000:
        raise APIError(400, "Abuse-context observation count is outside limits")


class ReceiptDB:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS receipts (
                transport_uuid TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                stored_path TEXT NOT NULL
            )"""
        )
        self.conn.commit()
        self.lock = threading.Lock()

    def existing(self, transport_uuid: str) -> sqlite3.Row | tuple[Any, ...] | None:
        with self.lock:
            return self.conn.execute(
                "SELECT node_id, kind, payload_sha256, stored_path FROM receipts WHERE transport_uuid=?",
                (transport_uuid,),
            ).fetchone()

    def insert(self, envelope: Mapping[str, Any], stored_path: Path) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO receipts VALUES (?, ?, ?, ?, datetime('now'), ?)",
                (
                    envelope["transport_uuid"], envelope["node_id"], envelope["kind"],
                    envelope["payload_sha256"], str(stored_path),
                ),
            )


class Ingress:
    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = config
        self.receipts = ReceiptDB(Path(str(config["receipt_db"])))
        self.accept_lock = threading.Lock()

    def accept(self, raw: bytes, node_id: str) -> tuple[int, dict[str, Any]]:
        with self.accept_lock:
            return self._accept_locked(raw, node_id)

    def _accept_locked(self, raw: bytes, node_id: str) -> tuple[int, dict[str, Any]]:
        node_id = normalize_node_id(node_id)
        node = load_node(Path(str(self.config["nodes_dir"])), node_id)
        envelope, payload = decode_envelope(raw, node_id, int(self.config["max_request_bytes"]))
        existing = self.receipts.existing(envelope["transport_uuid"])
        if existing is not None:
            if existing[0] != node_id or existing[1] != envelope["kind"] or existing[2] != envelope["payload_sha256"]:
                raise APIError(409, "transport_uuid was previously used with different content")
            return 200, {
                "status": "duplicate",
                "transport_uuid": envelope["transport_uuid"],
            }
        root = Path(str(self.config["event_drop_root"])) / node_id
        if envelope["kind"] == "event_batch":
            service, _ = validate_event_batch(payload, node)
            destination = root / "events" / "incoming" / f"{envelope['transport_uuid']}-{service}.json"
        else:
            allowed_services = {str(value) for value in node.get("services", [])}
            if allowed_services and "nginx" not in allowed_services:
                raise APIError(403, "Nginx abuse-context is not authorized for this node")
            validate_abuse_context(payload, node)
            destination = root / "abuse-context" / "incoming" / f"{envelope['transport_uuid']}.jsonl"
        atomic_write(destination, payload, 0o640)
        self.receipts.insert(envelope, destination)
        return 201, {
            "status": "accepted",
            "transport_uuid": envelope["transport_uuid"],
        }


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = f"ArgentSentinel/{APP_VERSION}"

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("%s", fmt % args)

    def respond(self, status: int, payload: Mapping[str, Any]) -> None:
        data = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.respond(200, {"status": "ok", "version": APP_VERSION})
        else:
            self.respond(404, {"status": "error", "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            if self.path != "/v1/ingest":
                raise APIError(404, "not found")
            config = self.server.config  # type: ignore[attr-defined]
            if config.get("require_proxy_verified_client") and self.headers.get("X-Argent-Client-Verify") != "SUCCESS":
                raise APIError(403, "Verified client certificate required")
            node_id = client_node_from_subject(
                self.headers.get("X-Argent-Client-DN", "")
            )
            length_text = self.headers.get("Content-Length", "")
            if not length_text.isdigit():
                raise APIError(411, "Content-Length required")
            length = int(length_text)
            if length <= 0 or length > int(config["max_request_bytes"]):
                raise APIError(413, "Request body size is outside limits")
            raw = self.rfile.read(length)
            status, payload = self.server.ingress.accept(raw, node_id)  # type: ignore[attr-defined]
            self.respond(status, payload)
        except APIError as exc:
            self.respond(exc.status, {"status": "error", "error": str(exc)})
        except Exception:
            LOG.exception("Unhandled ingestion request failure")
            self.respond(500, {"status": "error", "error": "internal server error"})


def serve(config: Mapping[str, Any]) -> None:
    socket_path = Path(str(config["socket_path"]))
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    server = UnixHTTPServer(str(socket_path), Handler)
    server.config = config  # type: ignore[attr-defined]
    server.ingress = Ingress(config)  # type: ignore[attr-defined]
    mode = int(str(config["socket_mode"]), 8)
    os.chmod(socket_path, mode)
    group_name = str(config.get("socket_group", "")).strip()
    if group_name:
        os.chown(socket_path, 0, grp.getgrnam(group_name).gr_gid)
    LOG.info("Argent Sentinel API listening on %s", socket_path)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argent Sentinel central ingestion API")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    parser.add_argument("--config", default="/etc/argent-sentinel/server-api.json")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    sub.add_parser("validate-config")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok", "version": APP_VERSION}, indent=2))
            return 0
        serve(config)
        return 0
    except (APIError, KeyError, OSError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
