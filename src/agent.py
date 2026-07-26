#!/usr/bin/env python3
"""Argent Sentinel node agent.

Stages local producer files, captures bounded OpenSSH authentication failures from
systemd-journald, and delivers immutable transport envelopes to the central
Sentinel HTTPS endpoint.  The agent never sends abuse mail or changes firewall
state.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import errno
import fcntl
import glob
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

APP_VERSION = "0.5.0.3"
UTC = dt.timezone.utc
LOG = logging.getLogger("argent-sentinel-agent")

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "node": {
        "id": "",
        "fqdn": "",
    },
    "central_url": "https://sentinel.argentwolf.org/",
    "endpoint_path": "/v1/ingest",
    "ca_file": "/etc/ssl/certs/ca-certificates.crt",
    "cert_file": "/etc/argent-sentinel/pki/node.crt",
    "key_file": "/etc/argent-sentinel/pki/node.key",
    "timeout_seconds": 30,
    "max_files_per_run": 25,
    "max_payload_bytes": 20 * 1024 * 1024,
    "lock_file": "/run/argent-sentinel/agent.lock",
    "pending_dir": "/var/lib/argent-sentinel/agent/pending",
    "acknowledged_dir": "/var/lib/argent-sentinel/agent/acknowledged",
    "rejected_dir": "/var/lib/argent-sentinel/agent/rejected",
    "wordpress_globs": [
        "/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json"
    ],
    "abuse_context_globs": [
        "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.jsonl",
        "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.json",
    ],
    "sshd": {
        "enabled": False,
        "unit": "ssh.service",
        "cursor_file": "/var/lib/argent-sentinel/agent/sshd.cursor",
        "privacy_key_file": "/etc/argent-sentinel/agent-privacy.key",
        "initial_lookback_minutes": 5,
        "destination_ip": "",
        "destination_port": 22,
        "max_events_per_batch": 500,
    },
}


class AgentError(RuntimeError):
    pass


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    value = value or utc_now()
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
        raise AgentError(f"Agent configuration not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AgentError(f"Invalid agent configuration JSON: {exc}") from exc
    if not isinstance(supplied, dict):
        raise AgentError("Agent configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    validate_config(config)
    return config


def validate_config(config: Mapping[str, Any]) -> None:
    node_id = str(config.get("node", {}).get("id", "")).strip()
    if not node_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
        raise AgentError("node.id must be a stable hostname-like identifier")
    parsed = urllib.parse.urlparse(str(config.get("central_url", "")))
    if parsed.scheme != "https" or not parsed.netloc:
        raise AgentError("central_url must be an absolute https URL")
    if not str(config.get("endpoint_path", "")).startswith("/"):
        raise AgentError("endpoint_path must begin with /")
    for name in ("timeout_seconds", "max_files_per_run", "max_payload_bytes"):
        if int(config.get(name, 0)) < 1:
            raise AgentError(f"{name} must be positive")
    sshd = config.get("sshd", {})
    if int(sshd.get("initial_lookback_minutes", 0)) < 1:
        raise AgentError("sshd.initial_lookback_minutes must be positive")
    if not 1 <= int(sshd.get("destination_port", 0)) <= 65535:
        raise AgentError("sshd.destination_port must be a valid port")
    destination_ip = str(sshd.get("destination_ip", "")).strip()
    if destination_ip:
        ipaddress.ip_address(destination_ip)
    if config.get("enabled"):
        for name in ("ca_file", "cert_file", "key_file"):
            path = Path(str(config.get(name, "")))
            if not path.is_file() or path.stat().st_size == 0:
                raise AgentError(f"{name} is missing or empty: {path}")


@contextlib.contextmanager
def process_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AgentError("Another agent run is active") from exc
        yield


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def safe_claim(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise AgentError(f"Input is not a regular non-symlink file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(source, destination)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        temporary = destination.parent / f".{destination.name}.{uuid.uuid4()}.tmp"
        shutil.copyfile(source, temporary)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        source.unlink()


def make_envelope(node_id: str, kind: str, payload: bytes, *, transport_uuid: str | None = None) -> dict[str, Any]:
    if kind not in {"event_batch", "abuse_context"}:
        raise AgentError(f"Unsupported transport kind: {kind}")
    return {
        "schema_version": 1,
        "transport_uuid": transport_uuid or str(uuid.uuid4()),
        "created_at": utc_text(),
        "node_id": node_id,
        "kind": kind,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }


def save_envelope(config: Mapping[str, Any], envelope: Mapping[str, Any]) -> Path:
    pending = Path(str(config["pending_dir"]))
    pending.mkdir(parents=True, exist_ok=True)
    target = pending / f"{envelope['transport_uuid']}.json"
    atomic_write(target, (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return target


def discover_files(patterns: Sequence[str], suffixes: set[str]) -> list[Path]:
    paths: set[Path] = set()
    for pattern in patterns:
        for value in glob.glob(str(pattern)):
            path = Path(value)
            if path.name.startswith(".") or path.suffix.lower() not in suffixes:
                continue
            paths.add(path)
    return sorted(paths, key=str)


def stage_file(config: Mapping[str, Any], path: Path, kind: str) -> Path:
    max_bytes = int(config["max_payload_bytes"])
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise AgentError(f"Input file size outside limits: {path}")
    temporary = Path(str(config["pending_dir"])) / f".claim-{uuid.uuid4()}-{path.name}"
    safe_claim(path, temporary)
    try:
        payload = temporary.read_bytes()
        envelope = make_envelope(str(config["node"]["id"]), kind, payload)
        saved = save_envelope(config, envelope)
    except Exception:
        # Do not lose a producer batch if envelope creation or local spooling
        # fails.  Restore the original path when possible; otherwise retain the
        # hidden claim file for operator recovery.
        if not path.exists():
            try:
                os.replace(temporary, path)
            except OSError:
                pass
        raise
    else:
        temporary.unlink()
        return saved


FAILED_PASSWORD_RE = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?:(?P<invalid>invalid user) )?(?P<user>.+?) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)


INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>.+?) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)



def privacy_token(secret: bytes, node_id: str, username: str) -> str:
    material = f"sshd\0{node_id}\0{username.casefold()}".encode("utf-8", "replace")
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def parse_journal_time(row: Mapping[str, Any]) -> dt.datetime:
    micros = row.get("__REALTIME_TIMESTAMP")
    try:
        return dt.datetime.fromtimestamp(int(str(micros)) / 1_000_000, UTC)
    except (TypeError, ValueError, OverflowError):
        return utc_now()


def parse_sshd_row(
    row: Mapping[str, Any],
    *,
    node_id: str,
    secret: bytes,
    destination_ip: str,
    destination_port: int,
) -> dict[str, Any] | None:
    message = str(row.get("MESSAGE", ""))
    match = FAILED_PASSWORD_RE.search(message)

    if match:
        # OpenSSH emits a separate "Invalid user" record before some invalid
        # accounts reach an authentication method. Count that record instead,
        # so one connection does not become two events.
        if match.group("invalid"):
            return None
        username = match.group("user")
        source_ip = match.group("ip")
        source_port = int(match.group("port"))
        account_class = "known-or-unresolved"
        auth_method = match.group("method").lower()
    else:
        match = INVALID_USER_RE.search(message)
        if not match:
            return None
        username = match.group("user")
        source_ip = match.group("ip")
        source_port = int(match.group("port"))
        account_class = "invalid"
        auth_method = "invalid-user-preauth"
    try:
        normalized_ip = str(ipaddress.ip_address(source_ip))
    except ValueError:
        return None
    cursor = str(row.get("__CURSOR", ""))
    identity = cursor or f"{row.get('__REALTIME_TIMESTAMP','')}\0{message}"
    event_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"argent-sentinel:sshd:{node_id}:{identity}"))
    occurred = parse_journal_time(row)
    return {
        "event_uuid": event_uuid,
        "occurred_at": utc_text(occurred),
        "recorded_at": utc_text(),
        "event_type": "ssh_auth_failed",
        "outcome": "denied",
        "source_ip": normalized_ip,
        "source_port": source_port,
        "destination_ip": destination_ip or None,
        "destination_port": destination_port,
        "transport_protocol": "TCP",
        "application_protocol": "SSH",
        "account_key": privacy_token(secret, node_id, username),
        "metadata": {
            "account_class": account_class,
            "auth_method": auth_method,
        },
    }


def journal_rows(config: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    sshd = config["sshd"]
    cursor_path = Path(str(sshd["cursor_file"]))
    command = ["journalctl", "--no-pager", "--output=json", "--show-cursor", "-u", str(sshd["unit"])]
    cursor = cursor_path.read_text(encoding="utf-8").strip() if cursor_path.exists() else ""
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since=-{int(sshd['initial_lookback_minutes'])}min")
    result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    if result.returncode != 0:
        raise AgentError(result.stderr.strip() or f"journalctl exited {result.returncode}")
    rows: list[dict[str, Any]] = []
    final_cursor: str | None = None
    for line in result.stdout.splitlines():
        if line.startswith("-- cursor:"):
            final_cursor = line.split(":", 1)[1].strip() or None
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows, final_cursor


def build_sshd_batches(config: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    sshd = config["sshd"]
    key_path = Path(str(sshd["privacy_key_file"]))
    try:
        secret = key_path.read_bytes()
    except FileNotFoundError as exc:
        raise AgentError(f"SSHD privacy key missing: {key_path}") from exc
    if len(secret) < 32:
        raise AgentError("SSHD privacy key must contain at least 32 bytes")
    node_id = str(config["node"]["id"])
    destination_ip = str(sshd.get("destination_ip", "")).strip()
    events: list[dict[str, Any]] = []
    for row in rows:
        event = parse_sshd_row(
            row,
            node_id=node_id,
            secret=secret,
            destination_ip=destination_ip,
            destination_port=int(sshd["destination_port"]),
        )
        if event is not None:
            events.append(event)
    if not events:
        return []
    limit = int(sshd["max_events_per_batch"])
    batches: list[dict[str, Any]] = []
    for offset in range(0, len(events), limit):
        chunk = events[offset:offset + limit]
        batches.append({
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": utc_text(),
            "source": {
                "host": node_id,
                "site_id": f"sshd-{node_id}",
                "site_url": f"ssh://{config['node'].get('fqdn') or node_id}:{int(sshd['destination_port'])}/",
                "service": "sshd",
                "plugin_version": APP_VERSION,
            },
            "events": chunk,
        })
    return batches


def build_sshd_batch(config: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Compatibility helper returning the first bounded SSH batch."""
    batches = build_sshd_batches(config, rows)
    return batches[0] if batches else None


def collect_sshd(config: Mapping[str, Any]) -> int:
    if not config["sshd"].get("enabled"):
        return 0
    rows, final_cursor = journal_rows(config)
    batches = build_sshd_batches(config, rows)
    total = 0
    for batch in batches:
        payload = (json.dumps(batch, sort_keys=True, separators=(",", ":")) + "\n").encode()
        save_envelope(config, make_envelope(str(config["node"]["id"]), "event_batch", payload))
        total += len(batch["events"])
    # Advance the cursor only after every resulting batch is durably staged.
    if final_cursor:
        atomic_write(Path(str(config["sshd"]["cursor_file"])), (final_cursor + "\n").encode(), 0o600)
    return total


def ssl_context(config: Mapping[str, Any]) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(config["ca_file"]))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(config["cert_file"]), str(config["key_file"]))
    return context


def deliver_envelope(config: Mapping[str, Any], path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    if len(data) > int(config["max_payload_bytes"]) * 2:
        return "rejected", "Transport envelope exceeds configured limit"
    envelope = json.loads(data.decode("utf-8"))
    base = str(config["central_url"]).rstrip("/")
    url = base + str(config["endpoint_path"])
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"Argent-Sentinel-Agent/{APP_VERSION}",
            "X-Argent-Node": str(config["node"]["id"]),
            "X-Argent-Transport-UUID": str(envelope.get("transport_uuid", "")),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=int(config["timeout_seconds"]), context=ssl_context(config)) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if response.status not in {200, 201}:
                return "retry", f"Server returned HTTP {response.status}"
            return "acknowledged", str(payload.get("status", "accepted"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:1000]
        if 400 <= exc.code < 500 and exc.code not in {408, 429}:
            return "rejected", f"HTTP {exc.code}: {body}"
        return "retry", f"HTTP {exc.code}: {body}"
    except (OSError, urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError) as exc:
        return "retry", str(exc)


def archive_envelope(config: Mapping[str, Any], path: Path, category: str, detail: str) -> None:
    root = Path(str(config[f"{category}_dir"]))
    destination = root / f"{utc_now():%Y}" / f"{utc_now():%m}" / f"{utc_now():%d}"
    destination.mkdir(parents=True, exist_ok=True)
    final = destination / path.name
    os.replace(path, final)
    if detail:
        atomic_write(final.with_suffix(final.suffix + ".result.txt"), (detail + "\n").encode(), 0o600)


def run_agent(config: Mapping[str, Any]) -> dict[str, int]:
    if not config.get("enabled"):
        return {"staged": 0, "sshd_events": 0, "acknowledged": 0, "rejected": 0, "retried": 0}
    staged = 0
    for path in discover_files(config.get("wordpress_globs", []), {".json"}):
        stage_file(config, path, "event_batch")
        staged += 1
    for path in discover_files(config.get("abuse_context_globs", []), {".json", ".jsonl", ".ndjson"}):
        stage_file(config, path, "abuse_context")
        staged += 1
    sshd_events = collect_sshd(config)
    counts = {"staged": staged, "sshd_events": sshd_events, "acknowledged": 0, "rejected": 0, "retried": 0}
    pending = sorted(Path(str(config["pending_dir"])).glob("*.json"), key=str)
    for path in pending[: int(config["max_files_per_run"])]:
        status, detail = deliver_envelope(config, path)
        if status == "acknowledged":
            archive_envelope(config, path, "acknowledged", detail)
            counts["acknowledged"] += 1
        elif status == "rejected":
            archive_envelope(config, path, "rejected", detail)
            counts["rejected"] += 1
        else:
            counts["retried"] += 1
            LOG.warning("Delivery deferred for %s: %s", path, detail)
    return counts


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argent Sentinel remote node agent")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    parser.add_argument("--config", default="/etc/argent-sentinel/agent.json")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    sub.add_parser("validate-config")
    sub.add_parser("status")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok", "version": APP_VERSION}, indent=2))
            return 0
        if args.command == "status":
            print(json.dumps({
                "enabled": bool(config["enabled"]),
                "node": config["node"],
                "central_url": config["central_url"],
                "sshd_enabled": bool(config["sshd"]["enabled"]),
                "pending": len(list(Path(config["pending_dir"]).glob("*.json"))),
            }, indent=2, sort_keys=True))
            return 0
        with process_lock(Path(config["lock_file"])):
            counts = run_agent(config)
        LOG.info(
            "Agent run complete: staged=%d sshd_events=%d acknowledged=%d rejected=%d retried=%d",
            counts["staged"], counts["sshd_events"], counts["acknowledged"], counts["rejected"], counts["retried"],
        )
        print(json.dumps(counts, sort_keys=True))
        return 0
    except (AgentError, json.JSONDecodeError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
