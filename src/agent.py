#!/usr/bin/env python3
"""Argent Sentinel node agent.

Stages local producer files, captures bounded OpenSSH and mail (Dovecot,
Postfix SASL) authentication failures from systemd-journald and the Postfix
mail log file, and delivers
immutable transport envelopes to the central Sentinel HTTPS endpoint.  The
agent never sends abuse mail or changes firewall state.
"""

from __future__ import annotations

import argparse
import importlib.util
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
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import sys
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

try:
    import local_protection
except ModuleNotFoundError:
    _LOCAL_PROTECTION_PATH = Path(__file__).with_name("local_protection.py")
    _LOCAL_PROTECTION_SPEC = importlib.util.spec_from_file_location(
        "local_protection",
        _LOCAL_PROTECTION_PATH,
    )
    if _LOCAL_PROTECTION_SPEC is None or _LOCAL_PROTECTION_SPEC.loader is None:
        raise
    local_protection = importlib.util.module_from_spec(_LOCAL_PROTECTION_SPEC)
    sys.modules.setdefault("local_protection", local_protection)
    _LOCAL_PROTECTION_SPEC.loader.exec_module(local_protection)

APP_VERSION = "0.5.7.0"
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
    "local_address_protection": {
        "enabled": True,
        "mode": "host",
        "interfaces": [],
        "manual_cidrs": [],
        "include_unique_local": False,
        "selection_source": "safe-default",
        "operator_confirmed": False,
        "inventory_state_file": "/var/lib/argent-sentinel/agent/protection-inventory-state.json",
        "inventory_heartbeat_seconds": 3600,
    },
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
    # Observe-only mail authentication ingest.  One ``mail`` service covers
    # Dovecot (IMAP/POP3/ManageSieve/Submission login processes) and Postfix
    # SMTP AUTH (SASL) so one mailbox keeps one privacy token across protocols.
    "mail": {
        "enabled": False,
        "units": ["dovecot.service", "postfix@-.service"],
        "cursor_file": "/var/lib/argent-sentinel/agent/mail.cursor",
        "privacy_key_file": "/etc/argent-sentinel/agent-privacy.key",
        "initial_lookback_minutes": 5,
        "destination_ip": "",
        "postfix_service_ports": {"smtp": 25, "submission": 587, "smtps": 465},
        "max_events_per_batch": 500,
        # Postfix with ``maillog_file`` (and rsyslog mail.log) never reaches
        # journald, so Postfix SASL failures are tailed from the file. A
        # component covered by an existing file is ignored in the journal
        # stream, so a host may keep ``postfix@-.service`` in ``units`` for
        # journald-only Postfix without double counting.
        "log_files": [{"path": "/var/log/mail.log", "components": ["postfix"]}],
        "log_cursor_file": "/var/lib/argent-sentinel/agent/mail-log.cursor",
        "max_log_bytes_per_run": 16777216,
        # Node-local account-existence classification at ingest. Never changes
        # what Dovecot/Postfix answer the client; results stay on the node
        # except as event metadata for the local collector/dashboard.
        "account_lookup": {
            "enabled": True,
            "backend": "doveadm",
            "doveadm_path": "/usr/bin/doveadm",
            "auth_userdb_socket": "/run/dovecot/auth-userdb",
            "auth_userdb_service": "argent-sentinel",
            "timeout_seconds": 2,
            "positive_ttl_seconds": 600,
            "negative_ttl_seconds": 300,
            "error_ttl_seconds": 60,
            "max_lookups_per_run": 200,
            "max_cache_entries": 5000,
            "cache_file": "/var/lib/argent-sentinel/agent/mail-account-cache.json",
            "auth_verbose_fallback": True,
        },
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
    validate_mail_config(config.get("mail", {}))
    protection = config.get("local_address_protection", {})
    if not isinstance(protection, Mapping):
        raise AgentError("local_address_protection must be an object")
    try:
        local_protection.validate_local_config(protection)
    except local_protection.ProtectionError as exc:
        raise AgentError(str(exc)) from exc
    if config.get("enabled"):
        for name in ("ca_file", "cert_file", "key_file"):
            path = Path(str(config.get(name, "")))
            if not path.is_file() or path.stat().st_size == 0:
                raise AgentError(f"{name} is missing or empty: {path}")


def validate_mail_config(mail: Any) -> None:
    if not isinstance(mail, Mapping):
        raise AgentError("mail must be an object")
    if int(mail.get("initial_lookback_minutes", 0)) < 1:
        raise AgentError("mail.initial_lookback_minutes must be positive")
    if int(mail.get("max_events_per_batch", 0)) < 1:
        raise AgentError("mail.max_events_per_batch must be positive")
    units = mail.get("units")
    if (
        not isinstance(units, list)
        or not units
        or not all(isinstance(unit, str) and UNIT_NAME_RE.fullmatch(unit) for unit in units)
    ):
        raise AgentError("mail.units must be a non-empty list of systemd unit names")
    destination_ip = str(mail.get("destination_ip", "")).strip()
    if destination_ip:
        try:
            ipaddress.ip_address(destination_ip)
        except ValueError as exc:
            raise AgentError("mail.destination_ip must be an IP address") from exc
    ports = mail.get("postfix_service_ports", {})
    if not isinstance(ports, Mapping):
        raise AgentError("mail.postfix_service_ports must be an object")
    for name, port in ports.items():
        if not isinstance(name, str) or not 1 <= int(port) <= 65535:
            raise AgentError("mail.postfix_service_ports values must be valid ports")
    log_files = mail.get("log_files", [])
    if not isinstance(log_files, list):
        raise AgentError("mail.log_files must be a list")
    for index, entry in enumerate(log_files):
        where = f"mail.log_files[{index}]"
        if not isinstance(entry, Mapping):
            raise AgentError(f"{where} must be an object with path and components")
        path = entry.get("path")
        if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
            raise AgentError(f"{where}.path must be an absolute path")
        components = entry.get("components", ["postfix"])
        if (
            not isinstance(components, list)
            or not components
            or not all(item in MAIL_LOG_COMPONENTS for item in components)
        ):
            raise AgentError(f"{where}.components must be a non-empty subset of {list(MAIL_LOG_COMPONENTS)}")
    if log_files and not str(mail.get("log_cursor_file", "")).startswith("/"):
        raise AgentError("mail.log_cursor_file must be an absolute path")
    if int(mail.get("max_log_bytes_per_run", 0)) < 4096:
        raise AgentError("mail.max_log_bytes_per_run must be at least 4096")
    lookup = mail.get("account_lookup", {})
    if not isinstance(lookup, Mapping):
        raise AgentError("mail.account_lookup must be an object")
    for name in ("enabled", "auth_verbose_fallback"):
        if not isinstance(lookup.get(name, False), bool):
            raise AgentError(f"mail.account_lookup.{name} must be boolean")
    if lookup.get("backend", "none") not in MAIL_ACCOUNT_LOOKUP_BACKENDS:
        raise AgentError(f"mail.account_lookup.backend must be one of {list(MAIL_ACCOUNT_LOOKUP_BACKENDS)}")
    for name in ("positive_ttl_seconds", "negative_ttl_seconds", "error_ttl_seconds"):
        value = int(lookup.get(name, 0))
        if not 0 <= value <= 86400:
            raise AgentError(f"mail.account_lookup.{name} must be between 0 and 86400")
    for name in ("max_lookups_per_run", "max_cache_entries"):
        if int(lookup.get(name, 1)) < 1:
            raise AgentError(f"mail.account_lookup.{name} must be positive")
    timeout = float(lookup.get("timeout_seconds", 2))
    if not 0 < timeout <= 30:
        raise AgentError("mail.account_lookup.timeout_seconds must be in (0, 30]")
    for name in ("doveadm_path", "auth_userdb_socket", "cache_file"):
        value = lookup.get(name, "")
        if not isinstance(value, str) or (value and not value.startswith("/")):
            raise AgentError(f"mail.account_lookup.{name} must be an absolute path")


UNIT_NAME_RE = re.compile(r"[A-Za-z0-9@:._\\-]{1,255}")


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
    if kind not in {"event_batch", "abuse_context", "protection_inventory"}:
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



def privacy_token(secret: bytes, node_id: str, username: str, domain: str = "sshd") -> str:
    """HMAC-pseudonymise an account name; ``domain`` separates services."""
    material = f"{domain}\0{node_id}\0{username.casefold()}".encode("utf-8", "replace")
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
    return read_journal(
        [str(sshd["unit"])],
        Path(str(sshd["cursor_file"])),
        int(sshd["initial_lookback_minutes"]),
    )


def read_journal(
    units: Sequence[str],
    cursor_path: Path,
    initial_lookback_minutes: int,
) -> tuple[list[dict[str, Any]], str | None]:
    """Read JSON journal rows for one or more units after a durable cursor.

    Repeated ``-u`` options are OR-ed by journalctl, so several units share one
    interleaved stream and one cursor.
    """
    command = ["journalctl", "--no-pager", "--output=json", "--show-cursor"]
    for unit in units:
        command.extend(["-u", str(unit)])
    cursor = cursor_path.read_text(encoding="utf-8").strip() if cursor_path.exists() else ""
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since=-{int(initial_lookback_minutes)}min")
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


# ---------------------------------------------------------------------------
# Observe-only mail authentication ingest (Dovecot + Postfix SASL)
# ---------------------------------------------------------------------------

MAIL_PRIVACY_DOMAIN = "mail"
# Separate HMAC domain for the node-local account-existence cache so cache
# keys never equal the exported account token.
MAIL_LOOKUP_PRIVACY_DOMAIN = "mail-lookup"
MAIL_ACCOUNT_LOOKUP_BACKENDS = ("doveadm", "auth-userdb", "none")
MAIL_LOG_COMPONENTS = ("postfix", "dovecot")
MAIL_FAILURE_REASONS = ("unknown_user", "bad_password", "unknown")
# doveadm exit status for "user doesn't exist" (sysexits EX_NOUSER).
DOVEADM_EX_NOUSER = 67

DOVECOT_LOGIN_RE = re.compile(
    r"^(?P<proto>imap|pop3|managesieve|submission)-login:\s+"
    r"(?:(?:Info|Warning|Error):\s+)?",
    re.IGNORECASE,
)
DOVECOT_AUTH_FAILED_RE = re.compile(
    r"\(auth failed, (?P<attempts>\d+) attempts?\b",
    re.IGNORECASE,
)
DOVECOT_USER_RE = re.compile(r"\buser=<(?P<user>[^>]{0,512})>")
DOVECOT_METHOD_RE = re.compile(r"\bmethod=(?P<method>[A-Za-z0-9_-]{1,32})")
DOVECOT_RIP_RE = re.compile(r"\brip=(?P<ip>[0-9A-Fa-f:.]+)")
DOVECOT_LIP_RE = re.compile(r"\blip=(?P<ip>[0-9A-Fa-f:.]+)")
DOVECOT_RPORT_RE = re.compile(r"\brport=(?P<port>\d{1,5})\b")
DOVECOT_LPORT_RE = re.compile(r"\blport=(?P<port>\d{1,5})\b")
DOVECOT_TLS_RE = re.compile(r",\s*(?:TLS|TLS handshaking)(?=[,:\s]|$)")
DOVECOT_SESSION_RE = re.compile(r"\bsession=<(?P<session>[^>]{1,128})>")
# auth_verbose=yes companion lines, e.g.
#   auth: passwd-file(alice@example.org,198.51.100.7,<sess>): unknown user
#   auth-worker(123): pam(alice,198.51.100.7,<sess>): pam_authenticate() failed: ... (password mismatch?)
#   auth: sql(bob,198.51.100.8,<sess>): Password mismatch
# Only used in memory to correlate a login summary line; never exported.
DOVECOT_AUTH_DETAIL_RE = re.compile(
    r"^auth(?:-worker\(\d+\))?:\s+(?:(?:Info|Warning|Error|Debug):\s+)?"
    r"(?:conn [^:]{0,128}:\s+)?(?:request [^:]{0,64}:\s+)?"
    r"(?P<driver>[A-Za-z0-9_-]{1,32})\((?P<user>[^,()]{0,512}),(?P<ip>[0-9A-Fa-f:.]{2,64})"
    r"(?:,<(?P<session>[^>]{1,128})>)?\):\s+(?P<detail>.*)$",
)
DOVECOT_UNKNOWN_USER_RE = re.compile(r"\bunknown user\b", re.IGNORECASE)
DOVECOT_PASSWORD_MISMATCH_RE = re.compile(r"\bpassword mismatch\b", re.IGNORECASE)

POSTFIX_SASL_FAILED_RE = re.compile(
    r"(?:^|\s)(?:warning:\s+)?(?P<client>[^\s\[\]]{1,255})\[(?P<ip>[^\]\s]{1,64})\]:\s+"
    r"SASL (?P<mech>[A-Za-z0-9_-]{1,32}) authentication failed:"
    r"(?P<reason>[^,]*)"
    r"(?:,\s*sasl_username=(?P<user>\S{1,512}))?",
)
# Base64 SASL LOGIN challenges that Postfix echoes as the failure "reason".
POSTFIX_SASL_STAGES = {
    "UGFzc3dvcmQ6": "password",   # "Password:"
    "VXNlcm5hbWU6": "username",   # "Username:"
}

# Traditional (Postfix maillog_file / BSD syslog) and RFC 3339 (rsyslog on
# Ubuntu 24.04) line prefixes:
#   Oct 26 17:10:00 host postfix/submission/smtpd[123]: warning: ...
#   2026-10-26T17:10:00.123456-04:00 host postfix/smtpd[123]: warning: ...
SYSLOG_LINE_RE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S{1,255})\s+(?P<ident>[^\s\[\]:]{1,128})(?:\[(?P<pid>\d{1,10})\])?:\s"
    r"(?P<message>.*)$"
)
MAIL_LOG_MAX_LINE_BYTES = 16384


def journal_message(row: Mapping[str, Any]) -> str:
    """Return MESSAGE as text; journald emits non-UTF-8 values as byte arrays."""
    value = row.get("MESSAGE", "")
    if isinstance(value, list):
        try:
            return bytes(int(item) & 0xFF for item in value).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return ""
    return str(value or "")


def normalize_mail_ip(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if text.lower().startswith("ipv6:"):
        text = text[5:]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _mail_port(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def postfix_service_name(identifier: str) -> str | None:
    """Map ``postfix/submission/smtpd`` style identifiers to a master.cf name."""
    parts = [part for part in identifier.strip().split("/") if part]
    if len(parts) < 2 or not parts[0].lower().startswith("postfix") or parts[-1].lower() != "smtpd":
        return None
    return parts[1].lower() if len(parts) >= 3 else "smtp"


def mail_row_component(row: Mapping[str, Any]) -> str | None:
    """Classify a journal/log row as ``postfix`` or ``dovecot`` (or None)."""
    identifier = str(row.get("SYSLOG_IDENTIFIER", "") or "").strip().lower()
    if identifier.startswith("postfix"):
        return "postfix"
    if identifier.startswith("dovecot"):
        return "dovecot"
    message = journal_message(row)
    if DOVECOT_LOGIN_RE.match(message) or message.startswith(("auth:", "auth-worker(")):
        return "dovecot"
    return None


# -- account existence ------------------------------------------------------

def mail_lookup_name_is_safe(username: str) -> bool:
    """Reject names that a userdb lookup must not see verbatim.

    ``doveadm user`` treats ``*``/``?`` as a listing mask and a leading ``-`` as
    an option; the auth-userdb protocol is tab/newline framed. Such names are
    left unresolved (``account_exists: null``) rather than guessed.
    """
    if not username or len(username) > 255 or username.startswith("-"):
        return False
    if any(character in username for character in "*?%\\"):
        return False
    return not any(ord(character) < 0x20 or ord(character) == 0x7F or character.isspace()
                   for character in username)


class MailAccountResolver:
    """Short-TTL, bounded, node-local account-existence lookups.

    Answers ``True`` (userdb has the account), ``False`` (userdb says the user
    does not exist), or ``None`` (lookup disabled, unsafe name, backend error,
    or per-run budget exhausted). The cache is keyed by an HMAC of the account
    name in a separate ``mail-lookup`` domain and stored 0600 on the node; no
    plaintext account name is written anywhere. The answer never changes what
    Dovecot or Postfix tell the client.
    """

    def __init__(self, settings: Mapping[str, Any], secret: bytes, node_id: str,
                 *, now: float | None = None) -> None:
        self.settings = dict(settings or {})
        self.secret = secret
        self.node_id = node_id
        self.backend = str(self.settings.get("backend", "none"))
        self.enabled = bool(self.settings.get("enabled")) and self.backend != "none"
        self.now = float(now if now is not None else time.time())
        self.cache_path = Path(str(self.settings.get("cache_file") or "")) if self.settings.get("cache_file") else None
        self.cache: dict[str, dict[str, Any]] = {}
        self.dirty = False
        self.unavailable = False
        self.lookups = 0
        self.stats = {"cache_hits": 0, "lookups": 0, "errors": 0, "skipped": 0}
        if self.enabled:
            self._load_cache()

    # cache ------------------------------------------------------------------
    def _load_cache(self) -> None:
        if self.cache_path is None or not self.cache_path.exists():
            return
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            LOG.warning("Ignoring unreadable mail account cache %s: %s", self.cache_path, exc)
            return
        entries = data.get("entries") if isinstance(data, Mapping) else None
        if not isinstance(entries, Mapping):
            return
        for key, entry in entries.items():
            if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
                continue
            if not isinstance(entry, Mapping):
                continue
            exists = entry.get("exists")
            try:
                expires = float(entry.get("expires", 0))
            except (TypeError, ValueError):
                continue
            if exists not in (True, False, None) or expires <= self.now:
                self.dirty = True
                continue
            self.cache[key] = {"exists": exists, "expires": expires}

    def save(self) -> None:
        if not self.enabled or self.cache_path is None or not self.dirty:
            return
        live = {key: value for key, value in self.cache.items() if float(value["expires"]) > self.now}
        limit = max(1, int(self.settings.get("max_cache_entries", 5000)))
        if len(live) > limit:
            keep = sorted(live, key=lambda key: float(live[key]["expires"]), reverse=True)[:limit]
            live = {key: live[key] for key in keep}
        payload = json.dumps({"version": 1, "entries": live}, sort_keys=True, separators=(",", ":"))
        try:
            atomic_write(self.cache_path, (payload + "\n").encode(), 0o600)
        except OSError as exc:
            LOG.warning("Cannot write mail account cache %s: %s", self.cache_path, exc)
            return
        self.dirty = False

    def cache_key(self, username: str) -> str:
        return privacy_token(self.secret, self.node_id, username, MAIL_LOOKUP_PRIVACY_DOMAIN)

    def _remember(self, key: str, exists: bool | None) -> None:
        if exists is True:
            ttl = int(self.settings.get("positive_ttl_seconds", 600))
        elif exists is False:
            ttl = int(self.settings.get("negative_ttl_seconds", 300))
        else:
            ttl = int(self.settings.get("error_ttl_seconds", 60))
        if ttl <= 0:
            return
        self.cache[key] = {"exists": exists, "expires": self.now + ttl}
        self.dirty = True

    # lookup -----------------------------------------------------------------
    def lookup(self, username: str | None) -> tuple[bool | None, str | None]:
        """Return ``(exists, source)``; source is the backend, ``cache``, or None."""
        if not self.enabled or not username:
            return None, None
        if not mail_lookup_name_is_safe(username):
            self.stats["skipped"] += 1
            return None, None
        key = self.cache_key(username)
        cached = self.cache.get(key)
        if cached is not None and float(cached["expires"]) > self.now:
            self.stats["cache_hits"] += 1
            return cached["exists"], "cache" if cached["exists"] is not None else None
        if self.unavailable or self.lookups >= int(self.settings.get("max_lookups_per_run", 200)):
            self.stats["skipped"] += 1
            return None, None
        self.lookups += 1
        self.stats["lookups"] += 1
        try:
            if self.backend == "doveadm":
                exists = self._lookup_doveadm(username)
            else:
                exists = self._lookup_auth_userdb(username)
        except FileNotFoundError as exc:
            # Backend not installed / socket absent: stop for this run, do not
            # cache, so a later install takes effect immediately.
            self.unavailable = True
            self.stats["errors"] += 1
            LOG.warning("Mail account lookup backend %s unavailable: %s", self.backend, exc)
            return None, None
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            self.stats["errors"] += 1
            LOG.debug("Mail account lookup failed: %s", exc)
            exists = None
        self._remember(key, exists)
        return exists, (self.backend if exists is not None else None)

    def _timeout(self) -> float:
        return float(min(max(float(self.settings.get("timeout_seconds", 2)), 0.1), 30.0))

    def _lookup_doveadm(self, username: str) -> bool | None:
        # argv only, never a shell; the name was screened by
        # mail_lookup_name_is_safe() so it cannot be an option or a mask.
        result = subprocess.run(
            [str(self.settings.get("doveadm_path", "/usr/bin/doveadm")), "user", username],
            text=True, capture_output=True, timeout=self._timeout(), check=False,
        )
        if result.returncode == 0:
            return True
        if result.returncode == DOVEADM_EX_NOUSER:
            return False
        return None

    def _lookup_auth_userdb(self, username: str) -> bool | None:
        """Dovecot auth-master protocol USER lookup on the auth-userdb socket."""
        import socket

        path = str(self.settings.get("auth_userdb_socket", "/run/dovecot/auth-userdb"))
        if not Path(path).exists():
            raise FileNotFoundError(path)
        service = str(self.settings.get("auth_userdb_service", "argent-sentinel"))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", service):
            raise ValueError("invalid auth_userdb_service")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self._timeout())
            connection.connect(path)
            request = f"VERSION\t1\t0\nCPID\t{os.getpid()}\nUSER\t1\t{username}\tservice={service}\n"
            connection.sendall(request.encode("utf-8"))
            buffer = b""
            while len(buffer) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                for line in buffer.split(b"\n")[:-1]:
                    fields = line.decode("utf-8", "replace").split("\t")
                    if len(fields) >= 2 and fields[1] == "1":
                        if fields[0] == "USER":
                            return True
                        if fields[0] == "NOTFOUND":
                            return False
                        if fields[0] == "FAIL":
                            return None
        return None


class MailAuthVerboseHints:
    """In-memory ``auth_verbose`` correlation (fallback only; never exported).

    Indexes Dovecot auth/auth-worker detail lines by session id and by
    ``(account, source IP)`` so a later login summary or Postfix SASL line can
    learn ``unknown user`` vs ``password mismatch`` when no userdb lookup is
    available. Requires ``auth_verbose = yes``; never ``auth_verbose_passwords``.
    """

    def __init__(self) -> None:
        self.by_session: dict[str, bool] = {}
        self.by_account_ip: dict[tuple[str, str], bool] = {}

    def __len__(self) -> int:
        return len(self.by_session) + len(self.by_account_ip)

    def add_row(self, row: Mapping[str, Any]) -> None:
        match = DOVECOT_AUTH_DETAIL_RE.match(journal_message(row))
        if not match:
            return
        detail = match.group("detail")
        if DOVECOT_UNKNOWN_USER_RE.search(detail):
            exists = False
        elif DOVECOT_PASSWORD_MISMATCH_RE.search(detail):
            exists = True
        else:
            return
        source_ip = normalize_mail_ip(match.group("ip"))
        user = match.group("user").strip().casefold()
        if match.group("session"):
            self.by_session[match.group("session")] = exists
        if user and source_ip:
            self.by_account_ip[(user, source_ip)] = exists

    def match(self, session: str | None, username: str | None, source_ip: str | None) -> bool | None:
        if session and session in self.by_session:
            return self.by_session[session]
        if username and source_ip:
            return self.by_account_ip.get((username.casefold(), source_ip))
        return None


def mail_failure_reason(exists: bool | None) -> str:
    if exists is True:
        return "bad_password"
    if exists is False:
        return "unknown_user"
    return "unknown"


def parse_mail_row(
    row: Mapping[str, Any],
    *,
    node_id: str,
    secret: bytes,
    destination_ip: str,
    postfix_service_ports: Mapping[str, Any] | None = None,
    resolver: MailAccountResolver | None = None,
    hints: MailAuthVerboseHints | None = None,
) -> dict[str, Any] | None:
    """Parse one Dovecot or Postfix SASL authentication-failure row.

    Rows come from journald or from a tailed syslog-format file (normalised to
    the same journal-like mapping). Only high-confidence summary lines are
    accepted, so one failed connection produces one event:

    * Dovecot ``<proto>-login: ... (auth failed, N attempts ...): user=<..>,
      method=.., rip=.., lip=..`` disconnect/abort lines.  Auth-worker detail
      lines (``passwd-file(...)``, ``pam(...)``) never become events; they are
      only an optional ``auth_verbose`` correlation hint.
    * Postfix ``warning: host[ip]: SASL MECH authentication failed: ...`` from
      any ``postfix*/.../smtpd`` identifier.

    Account existence is classified at ingest (``account_exists`` true / false
    / null, ``failure_reason`` bad_password / unknown_user / unknown) from a
    node-local userdb lookup, falling back to ``auth_verbose`` hints. Account
    names are never exported; only an HMAC token in the ``mail`` privacy domain.
    """
    message = journal_message(row)
    if not message:
        return None
    identifier = str(row.get("SYSLOG_IDENTIFIER", "") or "")
    metadata: dict[str, Any]
    source_port: int | None = None
    destination_port: int | None = None
    local_ip: str | None = None
    session: str | None = None
    username: str | None

    login = DOVECOT_LOGIN_RE.match(message)
    if login:
        failed = DOVECOT_AUTH_FAILED_RE.search(message)
        if not failed:
            return None
        rip = DOVECOT_RIP_RE.search(message)
        source_ip = normalize_mail_ip(rip.group("ip") if rip else None)
        if source_ip is None:
            return None
        protocol = login.group("proto").lower()
        user_match = DOVECOT_USER_RE.search(message)
        username = user_match.group("user").strip() if user_match else None
        method_match = DOVECOT_METHOD_RE.search(message)
        lip = DOVECOT_LIP_RE.search(message)
        local_ip = normalize_mail_ip(lip.group("ip") if lip else None)
        rport = DOVECOT_RPORT_RE.search(message)
        lport = DOVECOT_LPORT_RE.search(message)
        source_port = _mail_port(rport.group("port") if rport else None)
        destination_port = _mail_port(lport.group("port") if lport else None)
        session_match = DOVECOT_SESSION_RE.search(message)
        session = session_match.group("session") if session_match else None
        application_protocol = protocol.upper()
        metadata = {
            "mail_component": "dovecot",
            "protocol": protocol,
            "auth_mechanism": method_match.group("method").upper() if method_match else None,
            "attempts": min(int(failed.group("attempts")), 1000),
            "tls": bool(DOVECOT_TLS_RE.search(message)),
        }
    else:
        sasl = POSTFIX_SASL_FAILED_RE.search(message)
        if not sasl:
            return None
        service = postfix_service_name(identifier) if identifier else "smtp"
        if identifier and service is None:
            return None
        service = service or "smtp"
        source_ip = normalize_mail_ip(sasl.group("ip"))
        if source_ip is None:
            return None
        username = (sasl.group("user") or "").strip() or None
        reason = sasl.group("reason").strip()
        ports = postfix_service_ports or {}
        destination_port = _mail_port(str(ports[service])) if service in ports else None
        application_protocol = "SMTP"
        metadata = {
            "mail_component": "postfix",
            "protocol": "smtp",
            "postfix_service": service[:64],
            "auth_mechanism": sasl.group("mech").upper(),
            "attempts": 1,
            "sasl_stage": POSTFIX_SASL_STAGES.get(reason, "other" if reason else "none"),
        }

    exists: bool | None = None
    lookup_source: str | None = None
    if username:
        if resolver is not None:
            exists, lookup_source = resolver.lookup(username)
        if exists is None and hints is not None:
            hinted = hints.match(session, username, source_ip)
            if hinted is not None:
                exists, lookup_source = hinted, "auth_verbose"
        # SSH-style classes: known / invalid; "submitted" when existence is
        # unresolved (unchanged pre-0.5.7.0 meaning).
        metadata["account_class"] = "known" if exists is True else "invalid" if exists is False else "submitted"
        account_key: str | None = privacy_token(secret, node_id, username, MAIL_PRIVACY_DOMAIN)
    else:
        metadata["account_class"] = "empty" if metadata["mail_component"] == "dovecot" else "unresolved"
        account_key = None
    metadata["account_exists"] = exists
    metadata["failure_reason"] = mail_failure_reason(exists)
    metadata["account_lookup"] = lookup_source
    if row.get("_ARGENT_LOG_SOURCE"):
        metadata["log_source"] = "file"
    cursor = str(row.get("__CURSOR", ""))
    identity = cursor or f"{row.get('__REALTIME_TIMESTAMP', '')}\0{message}"
    event_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"argent-sentinel:mail:{node_id}:{identity}"))
    event: dict[str, Any] = {
        "event_uuid": event_uuid,
        "occurred_at": utc_text(parse_journal_time(row)),
        "recorded_at": utc_text(),
        "event_type": "mail_auth_failed",
        "outcome": "denied",
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": local_ip or destination_ip or None,
        "destination_port": destination_port,
        "transport_protocol": "TCP",
        "application_protocol": application_protocol,
        "metadata": metadata,
    }
    if account_key:
        event["account_key"] = account_key
    return event


def load_privacy_secret(path: Path, label: str) -> bytes:
    try:
        secret = path.read_bytes()
    except FileNotFoundError as exc:
        raise AgentError(f"{label} privacy key missing: {path}") from exc
    if len(secret) < 32:
        raise AgentError(f"{label} privacy key must contain at least 32 bytes")
    return secret


def build_mail_batches(
    config: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    resolver: MailAccountResolver | None = None,
) -> list[dict[str, Any]]:
    mail = config["mail"]
    secret = load_privacy_secret(Path(str(mail["privacy_key_file"])), "Mail")
    node_id = str(config["node"]["id"])
    destination_ip = str(mail.get("destination_ip", "")).strip()
    ports = mail.get("postfix_service_ports") or {}
    own_resolver = resolver is None
    if resolver is None:
        resolver = MailAccountResolver(mail.get("account_lookup") or {}, secret, node_id)
    hints: MailAuthVerboseHints | None = None
    if (mail.get("account_lookup") or {}).get("auth_verbose_fallback", True):
        hints = MailAuthVerboseHints()
        for row in rows:
            hints.add_row(row)
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        event = parse_mail_row(
            row,
            node_id=node_id,
            secret=secret,
            destination_ip=destination_ip,
            postfix_service_ports=ports,
            resolver=resolver,
            hints=hints,
        )
        if event is not None and event["event_uuid"] not in seen:
            seen.add(event["event_uuid"])
            events.append(event)
    if own_resolver:
        resolver.save()
    if not events:
        return []
    limit = int(mail["max_events_per_batch"])
    fqdn = config["node"].get("fqdn") or node_id
    batches: list[dict[str, Any]] = []
    for offset in range(0, len(events), limit):
        batches.append({
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": utc_text(),
            "source": {
                "host": node_id,
                "site_id": f"mail-{node_id}",
                "site_url": f"mail://{fqdn}/",
                "service": "mail",
                "plugin_version": APP_VERSION,
            },
            "events": events[offset:offset + limit],
        })
    return batches


# -- syslog-format file tail (Postfix maillog_file / rsyslog mail.log) -------

def parse_syslog_time(match: re.Match[str], now: dt.datetime | None = None) -> dt.datetime | None:
    now = now or utc_now()
    if match.group("iso"):
        text = match.group("iso")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        elif re.search(r"[+-]\d{4}$", text):
            text = text[:-2] + ":" + text[-2:]
        if "." in text:
            head, _, rest = text.partition(".")
            digits = re.match(r"\d+", rest)
            fraction = digits.group(0) if digits else ""
            text = f"{head}.{(fraction + '000000')[:6]}{rest[len(fraction):]}"
        try:
            value = dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if value.tzinfo is None:
            value = value.astimezone()
        return value.astimezone(UTC)
    bsd = " ".join(match.group("bsd").split())
    local_now = now.astimezone()
    for year in (local_now.year, local_now.year - 1):
        try:
            naive = dt.datetime.strptime(f"{year} {bsd}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        value = naive.astimezone()  # host local time zone, as syslog wrote it
        # A timestamp more than a day ahead belongs to last year (Dec -> Jan).
        if value <= local_now + dt.timedelta(days=1):
            return value.astimezone(UTC)
    return None


def syslog_line_row(line: str, cursor: str, now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Normalise one syslog-format line into a journal-like row."""
    match = SYSLOG_LINE_RE.match(line)
    if not match:
        return None
    occurred = parse_syslog_time(match, now)
    if occurred is None:
        return None
    return {
        "MESSAGE": match.group("message"),
        "SYSLOG_IDENTIFIER": match.group("ident"),
        "__REALTIME_TIMESTAMP": str(int(occurred.timestamp() * 1_000_000)),
        "__CURSOR": cursor,
        "_ARGENT_LOG_SOURCE": "file",
    }


def load_mail_log_cursor(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        LOG.warning("Ignoring unreadable mail log cursor %s: %s", path, exc)
        return {}
    files = data.get("files") if isinstance(data, Mapping) else None
    return dict(files) if isinstance(files, Mapping) else {}


def _rotated_candidates(path: Path) -> list[Path]:
    return [path.with_name(path.name + suffix) for suffix in (".1", ".0", "-1")]


def read_mail_log_file(
    path: Path,
    state: Mapping[str, Any] | None,
    *,
    components: Sequence[str],
    max_bytes: int,
    initial_lookback_minutes: int,
    now: dt.datetime | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Tail one syslog-format file after a durable (device, inode, offset) cursor.

    * Same inode, size >= offset: continue at offset.
    * Same inode, size < offset: copytruncate rotation, restart at 0.
    * New inode: finish the rotated file (``.1``/``.0``/``-1`` with the old
      inode) from the old offset, then read the new file from 0.
    * No cursor: start ``initial_lookback_minutes`` back (bounded by
      ``max_bytes`` from the end of the file).

    Only complete newline-terminated lines are consumed. At most ``max_bytes``
    are read per run; the cursor resumes the remainder next run. Returns the
    rows and the new cursor entry (None when the file is absent/unreadable).
    """
    now = now or utc_now()
    try:
        info = path.stat()
    except FileNotFoundError:
        return [], dict(state) if state else None
    except OSError as exc:
        LOG.warning("Cannot stat mail log %s: %s", path, exc)
        return [], dict(state) if state else None
    wanted = set(components)
    segments: list[tuple[Path, int, int, int]] = []  # (path, dev, ino, start)
    cutoff: dt.datetime | None = None
    if state and int(state.get("dev", -1)) == info.st_dev and int(state.get("ino", -1)) == info.st_ino:
        offset = int(state.get("offset", 0))
        segments.append((path, info.st_dev, info.st_ino, offset if 0 <= offset <= info.st_size else 0))
    elif state:
        for candidate in _rotated_candidates(path):
            try:
                rotated = candidate.stat()
            except OSError:
                continue
            if rotated.st_dev == int(state.get("dev", -1)) and rotated.st_ino == int(state.get("ino", -1)):
                offset = int(state.get("offset", 0))
                if 0 <= offset < rotated.st_size:
                    segments.append((candidate, rotated.st_dev, rotated.st_ino, offset))
                break
        else:
            LOG.info("Mail log %s rotated and the previous file is gone; continuing from the new file", path)
        segments.append((path, info.st_dev, info.st_ino, 0))
    else:
        cutoff = now - dt.timedelta(minutes=int(initial_lookback_minutes))
        segments.append((path, info.st_dev, info.st_ino, max(0, info.st_size - int(max_bytes))))

    rows: list[dict[str, Any]] = []
    budget = int(max_bytes)
    new_state: dict[str, Any] = {"dev": info.st_dev, "ino": info.st_ino, "offset": 0}
    for index, (segment_path, device, inode, start) in enumerate(segments):
        new_state = {"dev": device, "ino": inode, "offset": start}
        try:
            handle = segment_path.open("rb")
        except OSError as exc:
            LOG.warning("Cannot read mail log %s: %s", segment_path, exc)
            return rows, (dict(state) if state else None)
        with handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (device, inode):
                # Rotated between stat() and open(); retry next run.
                return rows, (dict(state) if state else None)
            handle.seek(start)
            data = handle.read(max(0, budget))
        budget -= len(data)
        consumed = data.rfind(b"\n") + 1
        if consumed == 0 and budget <= 0 and data:
            consumed = len(data)  # one over-long fragment: skip it
        position = start
        first = start != 0 and index == 0 and not state  # lookback start may be mid-line
        for raw_line in data[:consumed].split(b"\n")[:-1] if consumed else []:
            line_offset = position
            position += len(raw_line) + 1
            if first:
                first = False
                continue
            if len(raw_line) > MAIL_LOG_MAX_LINE_BYTES:
                continue
            line = raw_line.decode("utf-8", "replace").rstrip("\r")
            item = syslog_line_row(line, f"file:{device}:{inode}:{line_offset}", now)
            if item is None or mail_row_component(item) not in wanted:
                continue
            if cutoff is not None and int(item["__REALTIME_TIMESTAMP"]) < int(cutoff.timestamp() * 1_000_000):
                continue
            rows.append(item)
        new_state["offset"] = start + consumed
        if budget <= 0:
            # Byte budget exhausted: resume exactly here next run.
            return rows, new_state
        # Otherwise this segment was read to EOF; a trailing partial line is
        # left for the next run (current file) or dropped (rotated file).
    return rows, new_state


def read_mail_log_files(
    mail: Mapping[str, Any],
    now: dt.datetime | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], set[str]]:
    """Read every configured ``mail.log_files`` entry.

    Returns rows, the new cursor map, and the set of components covered by a
    file that currently exists (journal rows for those components are dropped
    so one failure is never counted from both journald and the file).
    """
    cursor = load_mail_log_cursor(Path(str(mail["log_cursor_file"])))
    rows: list[dict[str, Any]] = []
    covered: set[str] = set()
    new_cursor: dict[str, Any] = {}
    max_bytes = int(mail.get("max_log_bytes_per_run", 16 * 1024 * 1024))
    for entry in mail.get("log_files") or []:
        path = Path(str(entry["path"]))
        components = [str(item) for item in entry.get("components") or ["postfix"]]
        if path.is_file() and os.access(path, os.R_OK):
            covered.update(components)
        file_rows, state = read_mail_log_file(
            path,
            cursor.get(str(path)),
            components=components,
            max_bytes=max_bytes,
            initial_lookback_minutes=int(mail["initial_lookback_minutes"]),
            now=now,
        )
        rows.extend(file_rows)
        if state is not None:
            new_cursor[str(path)] = state
    return rows, new_cursor, covered


def collect_mail(config: Mapping[str, Any]) -> int:
    mail = config.get("mail") or {}
    if not mail.get("enabled"):
        return 0
    cursor_path = Path(str(mail["cursor_file"]))
    journal, final_cursor = read_journal(
        [str(unit) for unit in mail["units"]],
        cursor_path,
        int(mail["initial_lookback_minutes"]),
    )
    file_rows, file_cursor, covered = read_mail_log_files(mail)
    # A component tailed from an existing file (Postfix with maillog_file, or
    # rsyslog mail.log) is not also counted from journald.
    rows = [row for row in journal if mail_row_component(row) not in covered] + file_rows
    batches = build_mail_batches(config, rows)
    total = 0
    for batch in batches:
        payload = (json.dumps(batch, sort_keys=True, separators=(",", ":")) + "\n").encode()
        save_envelope(config, make_envelope(str(config["node"]["id"]), "event_batch", payload))
        total += len(batch["events"])
    # Advance cursors only after every resulting batch is durably staged.
    if final_cursor:
        atomic_write(cursor_path, (final_cursor + "\n").encode(), 0o600)
    if mail.get("log_files"):
        atomic_write(
            Path(str(mail["log_cursor_file"])),
            (json.dumps({"version": 1, "files": file_cursor}, sort_keys=True) + "\n").encode(),
            0o600,
        )
    return total


def protection_inventory_digest(inventory: Mapping[str, Any]) -> str:
    """Hash meaningful protection state while ignoring volatile lifetimes."""
    canonical = dict(inventory)
    canonical.pop("inventory_uuid", None)
    canonical.pop("generated_at", None)
    addresses: list[dict[str, Any]] = []
    for raw in canonical.get("addresses", []):
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        item.pop("valid_life_time", None)
        item.pop("preferred_life_time", None)
        addresses.append(item)
    canonical["addresses"] = addresses
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def stage_protection_inventory(config: Mapping[str, Any]) -> int:
    """Stage one changed or periodic local-address protection inventory."""
    protection = config["local_address_protection"]
    inventory = local_protection.build_inventory(config)
    digest = protection_inventory_digest(inventory)
    state_path = Path(str(protection["inventory_state_file"]))
    previous: dict[str, Any] = {}
    try:
        loaded = json.loads(state_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            previous = loaded
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        previous = {}
    now_epoch = int(time.time())
    last_epoch = int(previous.get("last_staged_epoch", 0) or 0)
    heartbeat = int(protection["inventory_heartbeat_seconds"])
    if previous.get("digest") == digest and now_epoch - last_epoch < heartbeat:
        return 0
    payload = (
        json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    save_envelope(
        config,
        make_envelope(
            str(config["node"]["id"]),
            "protection_inventory",
            payload,
        ),
    )
    atomic_write(
        state_path,
        (
            json.dumps(
                {
                    "digest": digest,
                    "last_staged_at": utc_text(),
                    "last_staged_epoch": now_epoch,
                    "effective_cidrs": inventory["effective_cidrs"],
                    "configured_mode": inventory["configured_mode"],
                    "effective_mode": inventory["effective_mode"],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode(),
        0o600,
    )
    return 1


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


def pending_delivery_key(path: Path) -> tuple[int, str]:
    """Deliver local-protection changes before ordinary telemetry backlogs."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return (2, str(path))
    if isinstance(value, Mapping) and value.get("kind") == "protection_inventory":
        return (0, str(path))
    return (1, str(path))


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
        return {
            "staged": 0,
            "sshd_events": 0,
            "mail_events": 0,
            "protection_inventories": 0,
            "acknowledged": 0,
            "rejected": 0,
            "retried": 0,
        }
    # Stage the safety inventory before telemetry producers. A malformed or
    # oversized event file must not delay a changed local-address boundary.
    protection_inventories = stage_protection_inventory(config)
    staged = 0
    for path in discover_files(config.get("wordpress_globs", []), {".json"}):
        stage_file(config, path, "event_batch")
        staged += 1
    for path in discover_files(config.get("abuse_context_globs", []), {".json", ".jsonl", ".ndjson"}):
        stage_file(config, path, "abuse_context")
        staged += 1
    sshd_events = collect_sshd(config)
    mail_events = collect_mail(config)
    counts = {
        "staged": staged,
        "sshd_events": sshd_events,
        "mail_events": mail_events,
        "protection_inventories": protection_inventories,
        "acknowledged": 0,
        "rejected": 0,
        "retried": 0,
    }
    pending = sorted(
        Path(str(config["pending_dir"])).glob("*.json"),
        key=pending_delivery_key,
    )
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
    sub.add_parser("protection-discover")
    sub.add_parser("protection-inventory")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = load_config(Path(args.config))
        if args.command == "validate-config":
            print(json.dumps({"status": "ok", "version": APP_VERSION}, indent=2))
            return 0
        if args.command == "status":
            inventory = local_protection.build_inventory(config)
            print(json.dumps({
                "enabled": bool(config["enabled"]),
                "node": config["node"],
                "central_url": config["central_url"],
                "sshd_enabled": bool(config["sshd"]["enabled"]),
                "mail_enabled": bool((config.get("mail") or {}).get("enabled")),
                "local_address_protection": inventory,
                "pending": len(list(Path(config["pending_dir"]).glob("*.json"))),
            }, indent=2, sort_keys=True))
            return 0
        if args.command == "protection-discover":
            local = config["local_address_protection"]
            print(json.dumps(local_protection.discover(
                configured_interfaces=local.get("interfaces", []),
                include_unique_local=bool(local.get("include_unique_local", False)),
            ), indent=2, sort_keys=True))
            return 0
        if args.command == "protection-inventory":
            print(json.dumps(
                local_protection.build_inventory(config),
                indent=2,
                sort_keys=True,
            ))
            return 0
        with process_lock(Path(config["lock_file"])):
            counts = run_agent(config)
        LOG.info(
            "Agent run complete: staged=%d sshd_events=%d mail_events=%d "
            "protection_inventories=%d acknowledged=%d rejected=%d retried=%d",
            counts["staged"], counts["sshd_events"], counts["mail_events"],
            counts["protection_inventories"], counts["acknowledged"],
            counts["rejected"], counts["retried"],
        )
        print(json.dumps(counts, sort_keys=True))
        return 0
    except (AgentError, local_protection.ProtectionError, json.JSONDecodeError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
