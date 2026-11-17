#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel/argent-sentinel/src/ban_sync.py
# Installed: /usr/lib/argent-sentinel/ban_sync.py
"""Cross-node ban sync (0.5.8.0).

One module holds every piece of the feature so the agent, the central
ingestion API, the collector, the dashboard snapshot and the watchdog share a
single definition of an entry, its identity, its digest and its safety
filters:

* upstream  - the agent snapshots local CrowdSec decisions (origin crowdsec /
  cscli, scope Ip / Range) and current fail2ban bans into a ``decisions``
  transport payload (every node, including the central host, reports
  through its own agent);
* central   - the collector stores node reports, filters them through
  enforcement protection and publishes one effective ban set with a
  monotonic cursor into a dedicated SQLite store;
* downstream - the API serves a per-node snapshot or delta plus a SHA-256
  digest of the node's full view, signed with Ed25519 when a central signing
  key exists;
* apply     - the agent mirrors the view, re-checks local protection and
  converges CrowdSec with ``cscli decisions add|delete``, touching only
  decisions whose reason carries the sync prefix.

Nothing here talks to the network except the agent pull, and nothing changes
firewall state unless ``ban_sync.apply.enabled`` is true and ``dry_run`` is
false.
"""

from __future__ import annotations

import base64
import datetime as dt
import glob
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

APP_VERSION = "0.5.8.0"
UTC = dt.timezone.utc

SCHEMA_VERSION = 1
STORE_SCHEMA_VERSION = 1

# Every Sentinel-managed CrowdSec reason starts with "argent-sentinel".  The
# collector's own enforcement uses "argent-sentinel/<rule>"; decisions written
# by this sync use "argent-sentinel:<origin_node>:<reason>".  The colon form is
# the loop-prevention marker: it is never reported upstream, never merged and
# is the only form removal ever touches.  The collector's slash form is an
# ordinary local ban and is reported by the central host's own agent like any
# other node's bans.
SENTINEL_REASON_PREFIX = "argent-sentinel"
SYNC_REASON_PREFIX = "argent-sentinel:"

SCOPES = ("Ip", "Range")
CROWDSEC_ORIGINS = ("crowdsec", "cscli")
FAIL2BAN_ORIGIN = "fail2ban"
# Origins that are never synced: every node already receives community and
# blocklist decisions directly from CrowdSec.
EXCLUDED_ORIGINS = ("CAPI", "capi", "lists", "console", "cscli-import")
MIN_IPV4_RANGE_PREFIX = 24
MIN_IPV6_RANGE_PREFIX = 48
DEFAULT_MAX_DURATION_SECONDS = 30 * 86400  # 720h
PERMANENT_CEILING_SECONDS = 30 * 86400
MAX_REPORT_DECISIONS = 20000
REASON_SAFE_RE = re.compile(r"[^A-Za-z0-9._/@+-]+")
NODE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
GO_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(ns|us|\u00b5s|ms|s|m|h)")
GO_UNITS = {"ns": 1e-9, "us": 1e-6, "\u00b5s": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}


class BanSyncError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Shared helpers


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    current = (value or utc_now()).astimezone(UTC).replace(microsecond=0)
    return current.isoformat().replace("+00:00", "Z")


def epoch_text(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return utc_text(dt.datetime.fromtimestamp(int(epoch), UTC))


def parse_time(value: Any) -> int | None:
    """Parse an RFC 3339 timestamp into epoch seconds (None when absent)."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def parse_go_duration(value: Any) -> int | None:
    """Parse a Go duration such as ``719h57m15.5s`` into whole seconds."""
    text = str(value or "").strip()
    sign = 1
    if text.startswith("-"):
        sign = -1
        text = text[1:]
    if not text:
        return None
    position = 0
    total = 0.0
    for match in GO_DURATION_RE.finditer(text):
        if match.start() != position:
            return None
        total += float(match.group(1)) * GO_UNITS[match.group(2)]
        position = match.end()
    if position != len(text):
        return None
    return sign * int(total)


def is_sentinel_reason(reason: Any) -> bool:
    """True for any Sentinel-managed reason (collector or sync)."""
    return str(reason or "").strip().lower().startswith(SENTINEL_REASON_PREFIX)


def is_sync_reason(reason: Any) -> bool:
    """True only for reasons written by this sync ("argent-sentinel:...")."""
    return str(reason or "").strip().lower().startswith(SYNC_REASON_PREFIX)


def sanitize_reason(value: Any, limit: int = 64) -> str:
    cleaned = REASON_SAFE_RE.sub("-", str(value or "").strip()).strip("-")
    return (cleaned or "unspecified")[:limit]


def sync_reason(origin_node: str, reason: str) -> str:
    """CrowdSec reason for a synced decision: argent-sentinel:<node>:<reason>."""
    return f"{SYNC_REASON_PREFIX}{sanitize_reason(origin_node, 128)}:{sanitize_reason(reason)}"


def normalize_scope(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"ip", "ipv4", "ipv6"}:
        return "Ip"
    if text == "range":
        return "Range"
    return None


def normalize_value(scope: str, value: Any) -> str:
    """Return the canonical text of an Ip or Range value or raise ValueError."""
    if scope == "Ip":
        return str(ipaddress.ip_address(str(value).strip()))
    if scope == "Range":
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    raise ValueError(f"Unsupported scope {scope!r}")


def entry_id(scope: str, value: str) -> str:
    """Stable identity of one effective entry: one (scope, value) pair."""
    return hashlib.sha256(f"{scope}|{value}".encode()).hexdigest()[:32]


def as_network(scope: str, value: str) -> Any:
    return ipaddress.ip_network(str(value), strict=False)


def parse_networks(values: Iterable[Any]) -> list[Any]:
    result = []
    for value in values:
        try:
            result.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError as exc:
            raise BanSyncError(f"Invalid CIDR {value!r}") from exc
    return result


def target_safety(scope: str, value: str) -> str | None:
    """Return a refusal reason for an unsafe target, or None when acceptable."""
    try:
        network = as_network(scope, value)
    except ValueError:
        return "malformed value"
    if not network.network_address.is_global or not network.broadcast_address.is_global:
        return "not globally routable"
    if scope == "Range":
        minimum = MIN_IPV4_RANGE_PREFIX if network.version == 4 else MIN_IPV6_RANGE_PREFIX
        if network.prefixlen < minimum:
            return f"range broader than /{minimum}"
    return None


def protection_match(scope: str, value: str, protected: Mapping[str, Sequence[Any]]) -> str | None:
    """Return the label of the first protection that overlaps the target."""
    try:
        target = as_network(scope, value)
    except ValueError:
        return "malformed value"
    for label, networks in protected.items():
        for network in networks:
            if network.version == target.version and network.overlaps(target):
                return f"{label} {network}"
    return None


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


VIEW_FIELDS = ("id", "scope", "value", "until", "reason", "origin_node")


def view_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {name: entry.get(name) for name in VIEW_FIELDS}


def view_digest(entries: Iterable[Mapping[str, Any]], generated_epoch: int) -> str:
    """SHA-256 over the canonical active view as of ``generated_epoch``.

    Entries are active when their ``until`` is strictly later than
    ``generated_epoch`` (the server clock), so agent and central agree
    regardless of local clock skew.
    """
    active = []
    for entry in entries:
        until_epoch = parse_time(entry.get("until"))
        if until_epoch is None or until_epoch <= int(generated_epoch):
            continue
        active.append(view_entry(entry))
    active.sort(key=lambda item: str(item["id"]))
    return hashlib.sha256(canonical_json(active)).hexdigest()


# --------------------------------------------------------------------------
# Detached Ed25519 signatures over the downstream view
#
# The API signs every /v1/decisions response with the central signing key;
# agents verify with a pinned public key.  The signed message binds the
# canonical view digest, the cursor pair, the requesting node, the store
# set_id, the server timestamp and the SHA-256 of the exact delta body, under
# a fixed domain-separation prefix.  OpenSSL (already a package dependency)
# does the Ed25519 work so the code stays stdlib-only.

SIGNATURE_ALG = "ed25519"
SIGNATURE_CONTEXT = b"argent-sentinel-ban-sync-view-v1\n"
SIGNED_VIEW_FIELDS = (
    "schema_version", "set_id", "node_id", "cursor", "requested_cursor",
    "reset", "generated_epoch", "count", "snapshot_sha256",
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
PEM_PUBLIC_RE = re.compile(r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", re.S)
_SIGNING_KEY_CACHE: dict[tuple[str, int, int], str] = {}


class SignatureError(BanSyncError):
    """A downstream response failed signature policy or verification."""


def view_body_sha256(payload: Mapping[str, Any]) -> str:
    body = {name: payload.get(name, []) for name in ("entries", "upserts", "removals")}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def signed_view_message(payload: Mapping[str, Any]) -> bytes:
    header = {name: payload.get(name) for name in SIGNED_VIEW_FIELDS}
    header["body_sha256"] = view_body_sha256(payload)
    return SIGNATURE_CONTEXT + canonical_json(header)


def ed25519_public_keys(pem_text: str) -> list[bytes]:
    """DER SubjectPublicKeyInfo blobs of every Ed25519 key in a PEM text."""
    keys = []
    for block in PEM_PUBLIC_RE.findall(pem_text):
        try:
            der = base64.b64decode("".join(block.split()), validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise SignatureError("public key PEM is not valid base64") from exc
        if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
            raise SignatureError("public key is not an Ed25519 key")
        keys.append(der)
    return keys


def public_key_id(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()[:16]


def _openssl(runner: Runner, args: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return runner(list(args), capture_output=True, timeout=timeout, check=False)


def signing_key_id(key_file: Path, *, openssl: str = "openssl", runner: Runner = subprocess.run) -> str:
    """Key id of a private signing key; refuses group/other-accessible keys."""
    try:
        info = key_file.stat()
    except OSError as exc:
        raise SignatureError(f"signing key unavailable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SignatureError("signing key is not a regular file")
    if info.st_mode & 0o077:
        raise SignatureError("signing key must not be accessible by group or others (chmod 0600)")
    cache_key = (str(key_file), int(info.st_mtime_ns), int(info.st_size))
    cached = _SIGNING_KEY_CACHE.get(cache_key)
    if cached:
        return cached
    result = _openssl(runner, [openssl, "pkey", "-in", str(key_file), "-pubout"])
    if result.returncode != 0:
        raise SignatureError("cannot derive the public key from the signing key")
    keys = ed25519_public_keys(result.stdout.decode("ascii", "replace"))
    if len(keys) != 1:
        raise SignatureError("signing key is not a single Ed25519 key")
    identifier = public_key_id(keys[0])
    _SIGNING_KEY_CACHE.clear()
    _SIGNING_KEY_CACHE[cache_key] = identifier
    return identifier


def sign_view(
    view: Mapping[str, Any],
    key_file: Path,
    *,
    openssl: str = "openssl",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Return ``view`` with a detached Ed25519 ``signature`` object."""
    identifier = signing_key_id(key_file, openssl=openssl, runner=runner)
    with tempfile.TemporaryDirectory(prefix="ban-sync-sign-") as temporary:
        message = Path(temporary) / "message"
        message.write_bytes(signed_view_message(view))
        result = _openssl(runner, [openssl, "pkeyutl", "-sign", "-inkey", str(key_file), "-rawin", "-in", str(message)])
    if result.returncode != 0 or len(result.stdout) != 64:
        raise SignatureError("Ed25519 signing failed")
    signed = dict(view)
    signed["signature"] = {
        "alg": SIGNATURE_ALG,
        "key_id": identifier,
        "value": base64.b64encode(result.stdout).decode("ascii"),
    }
    return signed


def generate_signing_key(key_file: Path, *, force: bool = False, openssl: str = "openssl",
                         runner: Runner = subprocess.run) -> dict[str, str]:
    """Create a 0600 Ed25519 key (directory 0700) and its 0644 ``.pub``."""
    if key_file.exists() and not force:
        raise SignatureError(f"{key_file} already exists (use --force to replace it)")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(key_file.parent, 0o700)
    temporary = key_file.with_name(f".{key_file.name}.new")
    previous = os.umask(0o077)
    try:
        temporary.unlink(missing_ok=True)
        result = _openssl(runner, [openssl, "genpkey", "-algorithm", "ed25519", "-out", str(temporary)])
        if result.returncode != 0:
            raise SignatureError("openssl genpkey failed")
        os.chmod(temporary, 0o600)
        os.replace(temporary, key_file)
    finally:
        os.umask(previous)
        temporary.unlink(missing_ok=True)
    result = _openssl(runner, [openssl, "pkey", "-in", str(key_file), "-pubout"])
    if result.returncode != 0:
        raise SignatureError("cannot export the public key")
    public_pem = result.stdout.decode("ascii")
    public_file = key_file.with_name(key_file.name + ".pub")
    public_file.write_text(public_pem, encoding="ascii")
    os.chmod(public_file, 0o644)
    return {
        "key_file": str(key_file),
        "public_key_file": str(public_file),
        "key_id": public_key_id(ed25519_public_keys(public_pem)[0]),
        "public_key_pem": public_pem,
    }


def load_pinned_keys(paths: Sequence[str]) -> dict[str, Path]:
    """key_id -> public key file for every pinned key (fail closed)."""
    pinned: dict[str, Path] = {}
    for value in paths:
        path = Path(str(value))
        try:
            text = path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise SignatureError(f"pinned signing key {path} is unreadable: {exc}") from exc
        keys = ed25519_public_keys(text)
        if len(keys) != 1:
            raise SignatureError(f"pinned signing key {path} must hold exactly one Ed25519 public key")
        pinned[public_key_id(keys[0])] = path
    return pinned


def verify_view_signature(
    payload: Mapping[str, Any],
    pinned: Mapping[str, Path],
    *,
    node_id: str,
    requested_cursor: int,
    now_epoch: int,
    last_generated_epoch: int,
    max_age_seconds: int,
    openssl: str = "openssl",
    runner: Runner = subprocess.run,
) -> str:
    """Enforce the signature policy on a raw response; returns a status.

    No pinned key: signatures are optional (rollout phase) and the response
    is reported as ``unsigned`` or ``unverified``.  Pinned key(s): the
    response must carry a valid signature by one of them, be addressed to
    this node and this request, be fresh, and not be older than the last
    accepted response (rollback).  Any failure raises SignatureError.
    """
    signature = payload.get("signature")
    if not pinned:
        return "unsigned" if signature is None else "unverified (no pinned key)"
    if not isinstance(signature, Mapping):
        raise SignatureError("response is unsigned but a signing key is pinned")
    if signature.get("alg") != SIGNATURE_ALG:
        raise SignatureError("unsupported signature algorithm")
    key_path = pinned.get(str(signature.get("key_id", "")))
    if key_path is None:
        raise SignatureError(f"response signed by unpinned key {str(signature.get('key_id'))[:32]!r}")
    try:
        raw = base64.b64decode(str(signature.get("value", "")), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SignatureError("signature is not valid base64") from exc
    if len(raw) != 64:
        raise SignatureError("Ed25519 signature must be 64 bytes")
    if payload.get("node_id") != node_id:
        raise SignatureError("signed response is addressed to another node")
    if payload.get("requested_cursor") != int(requested_cursor):
        raise SignatureError("signed response does not answer this request's cursor")
    generated = payload.get("generated_epoch")
    if not isinstance(generated, int) or isinstance(generated, bool):
        raise SignatureError("signed response lacks generated_epoch")
    if abs(int(now_epoch) - generated) > int(max_age_seconds):
        raise SignatureError("signed response is stale or from the future (check NTP)")
    if generated < int(last_generated_epoch):
        raise SignatureError("signed response is older than the last accepted one (rollback)")
    with tempfile.TemporaryDirectory(prefix="ban-sync-verify-") as temporary:
        message = Path(temporary) / "message"
        sigfile = Path(temporary) / "signature"
        message.write_bytes(signed_view_message(payload))
        sigfile.write_bytes(raw)
        result = _openssl(runner, [
            openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path),
            "-rawin", "-in", str(message), "-sigfile", str(sigfile),
        ])
    if result.returncode != 0:
        raise SignatureError("Ed25519 signature verification failed")
    return f"verified ({signature.get('key_id')})"


def atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


Runner = Callable[..., subprocess.CompletedProcess]


def contributors_text(entry: Mapping[str, Any]) -> str:
    return ",".join(sorted({str(item) for item in entry.get("contributors") or [entry["origin_node"]]}))


def run_command(runner: Runner, args: Sequence[str], timeout: int) -> subprocess.CompletedProcess:
    return runner(list(args), text=True, capture_output=True, timeout=timeout, check=False)


# --------------------------------------------------------------------------
# Local decision sources (agent upstream)


def parse_cscli_decisions(
    raw: str,
    *,
    now_epoch: int,
    origins: Sequence[str] = CROWDSEC_ORIGINS,
    skip_reason: Callable[[Any], bool] = is_sync_reason,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse ``cscli decisions list -o json`` alerts into decision records.

    Keeps active ``ban`` decisions with scope Ip/Range whose origin is in
    ``origins``; drops simulated decisions, excluded origins (CAPI, lists,
    console) and any decision whose reason ``skip_reason`` matches (loop
    prevention).
    """
    skipped = {"origin": 0, "scope": 0, "type": 0, "simulated": 0, "loop": 0, "malformed": 0, "expired": 0}
    text = (raw or "").strip()
    if not text or text == "null":
        return [], skipped
    try:
        alerts = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BanSyncError(f"cscli returned invalid JSON: {exc}") from exc
    if not isinstance(alerts, list):
        raise BanSyncError("cscli decisions JSON root must be a list")
    allowed = {str(item) for item in origins}
    result: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, Mapping):
            continue
        started = parse_time(alert.get("start_at")) or parse_time(alert.get("created_at"))
        for decision in alert.get("decisions") or []:
            if not isinstance(decision, Mapping):
                continue
            origin = str(decision.get("origin", ""))
            if origin in EXCLUDED_ORIGINS or origin not in allowed:
                skipped["origin"] += 1
                continue
            if str(decision.get("type", "")).lower() != "ban":
                skipped["type"] += 1
                continue
            if decision.get("simulated"):
                skipped["simulated"] += 1
                continue
            scope = normalize_scope(decision.get("scope"))
            if scope is None:
                skipped["scope"] += 1
                continue
            reason = str(decision.get("scenario") or alert.get("scenario") or "")
            if skip_reason(reason):
                skipped["loop"] += 1
                continue
            try:
                value = normalize_value(scope, decision.get("value"))
            except ValueError:
                skipped["malformed"] += 1
                continue
            remaining = parse_go_duration(decision.get("duration"))
            until = now_epoch + remaining if remaining is not None else parse_time(decision.get("until"))
            if until is None or until <= now_epoch:
                skipped["expired"] += 1
                continue
            result.append(
                {
                    "source": "crowdsec",
                    "source_id": str(decision.get("id", "")),
                    "scope": scope,
                    "value": value,
                    "origin": origin,
                    "scenario": sanitize_reason(reason, 128),
                    "reason": sanitize_reason(reason),
                    "started_at": epoch_text(started),
                    "until": epoch_text(until),
                }
            )
    return result, skipped


def read_cscli_decisions(
    cscli_path: str,
    *,
    timeout: int,
    now_epoch: int,
    runner: Runner = subprocess.run,
    origins: Sequence[str] = CROWDSEC_ORIGINS,
    skip_reason: Callable[[Any], bool] = is_sync_reason,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    try:
        result = run_command(
            runner,
            [cscli_path, "decisions", "list", "-o", "json", "--limit", "0", "--type", "ban"],
            timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BanSyncError(f"cscli decisions list failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:500]
        raise BanSyncError(f"cscli decisions list exited {result.returncode}: {detail}")
    return parse_cscli_decisions(result.stdout, now_epoch=now_epoch, origins=origins, skip_reason=skip_reason)


def read_fail2ban_bans(db_path: Path, *, now_epoch: int, jails: Sequence[str] = ()) -> list[dict[str, Any]]:
    """Read current fail2ban bans from its SQLite database (read-only).

    fail2ban deletes the row on unban, so a row whose ``timeofban + bantime``
    is in the future (or whose bantime is negative, i.e. permanent) is a
    current ban.  Permanent bans are reported with ``until`` null; central
    caps them.
    """
    if not db_path.is_file():
        return []
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as exc:
        raise BanSyncError(f"Cannot open fail2ban database: {exc}") from exc
    try:
        rows = connection.execute(
            "SELECT jail, ip, MAX(timeofban), bantime FROM bans GROUP BY jail, ip"
        ).fetchall()
    except sqlite3.Error as exc:
        raise BanSyncError(f"Cannot read fail2ban bans: {exc}") from exc
    finally:
        connection.close()
    wanted = {str(item) for item in jails}
    result: list[dict[str, Any]] = []
    for jail, ip_text, time_of_ban, ban_time in rows:
        if wanted and str(jail) not in wanted:
            continue
        try:
            value = normalize_value("Ip", ip_text)
        except ValueError:
            continue
        started = int(time_of_ban or 0)
        ban_seconds = int(ban_time or 0)
        until: int | None
        if ban_seconds < 0:
            until = None
        else:
            until = started + ban_seconds
            if until <= now_epoch:
                continue
        jail_name = sanitize_reason(jail, 48)
        result.append(
            {
                "source": "fail2ban",
                "source_id": f"{jail_name}:{value}",
                "scope": "Ip",
                "value": value,
                "origin": FAIL2BAN_ORIGIN,
                "scenario": f"fail2ban/{jail_name}",
                "reason": f"fail2ban-{jail_name}",
                "started_at": epoch_text(started) if started else None,
                "until": epoch_text(until),
            }
        )
    return result


def decisions_report_digest(decisions: Sequence[Mapping[str, Any]]) -> str:
    """Digest of meaningful upstream content (ignores report uuid and times)."""
    canonical = sorted(
        (
            {
                "source": item.get("source"),
                "scope": item.get("scope"),
                "value": item.get("value"),
                "origin": item.get("origin"),
                "reason": item.get("reason"),
                "until": item.get("until"),
            }
            for item in decisions
        ),
        key=lambda item: (str(item["scope"]), str(item["value"]), str(item["source"]), str(item["reason"])),
    )
    return hashlib.sha256(canonical_json(canonical)).hexdigest()


def build_decisions_report(
    node_id: str,
    decisions: Sequence[Mapping[str, Any]],
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_uuid": str(uuid.uuid4()),
        "generated_at": utc_text(now),
        "node_id": node_id,
        "decisions": [dict(item) for item in decisions],
    }


def validate_decisions_report(report: Any, node_id: str) -> dict[str, Any]:
    """Structural validation shared by the API and the collector."""
    if not isinstance(report, Mapping) or report.get("schema_version") != SCHEMA_VERSION:
        raise BanSyncError("Unsupported decisions report schema")
    if str(report.get("node_id", "")) != node_id:
        raise BanSyncError("Decisions report node_id is not authorized")
    try:
        report_uuid = str(uuid.UUID(str(report.get("report_uuid", ""))))
    except ValueError as exc:
        raise BanSyncError("Invalid decisions report UUID") from exc
    generated = parse_time(report.get("generated_at"))
    if generated is None:
        raise BanSyncError("Invalid decisions report generated_at")
    decisions = report.get("decisions")
    if not isinstance(decisions, list) or len(decisions) > MAX_REPORT_DECISIONS:
        raise BanSyncError("decisions must be a bounded list")
    normalized: list[dict[str, Any]] = []
    dropped_loop = 0
    for index, raw in enumerate(decisions):
        where = f"decisions[{index}]"
        if not isinstance(raw, Mapping):
            raise BanSyncError(f"{where} must be an object")
        # Central loop-prevention backstop.  Must run before sanitising,
        # which rewrites the ":" of the sync marker.
        if is_sync_reason(raw.get("reason")) or is_sync_reason(raw.get("scenario")):
            dropped_loop += 1
            continue
        scope = normalize_scope(raw.get("scope"))
        if scope is None:
            raise BanSyncError(f"{where}.scope must be Ip or Range")
        try:
            value = normalize_value(scope, raw.get("value"))
        except ValueError as exc:
            raise BanSyncError(f"{where}.value is invalid") from exc
        source = str(raw.get("source", ""))
        if source not in {"crowdsec", "fail2ban"}:
            raise BanSyncError(f"{where}.source must be crowdsec or fail2ban")
        until_text = raw.get("until")
        until = parse_time(until_text) if until_text is not None else None
        if until_text is not None and until is None:
            raise BanSyncError(f"{where}.until is invalid")
        normalized.append(
            {
                "source": source,
                "source_id": str(raw.get("source_id", ""))[:128],
                "scope": scope,
                "value": value,
                "origin": str(raw.get("origin", ""))[:32],
                "scenario": sanitize_reason(raw.get("scenario"), 128),
                "reason": sanitize_reason(raw.get("reason")),
                "started_epoch": parse_time(raw.get("started_at")),
                "until_epoch": until,
            }
        )
    return {
        "report_uuid": report_uuid,
        "node_id": node_id,
        "generated_epoch": generated,
        "decisions": normalized,
        "dropped_loop": dropped_loop,
    }


# --------------------------------------------------------------------------
# Central store


STORE_DDL = (
    """CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS node_reports (
        node_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        report_uuid TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        generated_epoch INTEGER NOT NULL,
        received_epoch INTEGER NOT NULL,
        decision_count INTEGER NOT NULL,
        PRIMARY KEY (node_id, channel)
    )""",
    """CREATE TABLE IF NOT EXISTS report_receipts (
        report_uuid TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        received_epoch INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS node_decisions (
        node_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        source TEXT NOT NULL,
        source_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        value TEXT NOT NULL,
        origin TEXT NOT NULL,
        scenario TEXT NOT NULL,
        reason TEXT NOT NULL,
        started_epoch INTEGER,
        until_epoch INTEGER,
        first_seen_epoch INTEGER NOT NULL,
        PRIMARY KEY (node_id, channel, source, source_id, scope, value)
    )""",
    """CREATE TABLE IF NOT EXISTS effective (
        id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        value TEXT NOT NULL,
        until_epoch INTEGER NOT NULL,
        reason TEXT NOT NULL,
        scenario TEXT NOT NULL,
        origin TEXT NOT NULL,
        origin_node TEXT NOT NULL,
        first_seen_epoch INTEGER NOT NULL,
        active INTEGER NOT NULL,
        removed_reason TEXT,
        seq INTEGER NOT NULL,
        updated_epoch INTEGER NOT NULL,
        contributors TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS effective_seq ON effective(seq)",
    """CREATE TABLE IF NOT EXISTS node_pulls (
        node_id TEXT PRIMARY KEY,
        first_pull_epoch INTEGER NOT NULL,
        last_pull_epoch INTEGER NOT NULL,
        requested_cursor INTEGER NOT NULL,
        served_cursor INTEGER NOT NULL,
        last_reset INTEGER NOT NULL,
        served_entries INTEGER NOT NULL,
        pulls INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS merge_runs (
        run_epoch INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        detail TEXT NOT NULL,
        candidates INTEGER NOT NULL,
        active INTEGER NOT NULL,
        added INTEGER NOT NULL,
        updated INTEGER NOT NULL,
        removed INTEGER NOT NULL,
        protected INTEGER NOT NULL
    )""",
)


class BanSyncStore:
    """Dedicated SQLite store shared by the collector (writer of entries) and
    the API (reader of entries, writer of pull records).

    It lives beside the ingress receipt database, not inside the collector
    state database, so the collector schema version does not change and the
    API never opens collector state.
    """

    def __init__(self, path: Path, *, readonly: bool = False) -> None:
        self.path = path
        self.readonly = readonly
        if readonly:
            if not path.is_file():
                raise BanSyncError(f"Ban-sync store is unavailable: {path}")
            self.conn = sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, timeout=10, check_same_thread=False,
                isolation_level=None,
            )
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(path, timeout=10, check_same_thread=False, isolation_level=None)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        if not readonly:
            self.install()

    def close(self) -> None:
        self.conn.close()

    def transaction(self) -> "_Transaction":
        return _Transaction(self.conn)

    def install(self) -> None:
        with self.transaction():
            for statement in STORE_DDL:
                self.conn.execute(statement)
            columns = {row[1] for row in self.conn.execute("PRAGMA table_info(effective)")}
            if "contributors" not in columns:  # pre-release 0.5.8.0 stores
                self.conn.execute("ALTER TABLE effective ADD COLUMN contributors TEXT NOT NULL DEFAULT ''")
            existing = self.meta("schema_version")
            if existing is None:
                self.set_meta("schema_version", str(STORE_SCHEMA_VERSION))
                self.set_meta("set_id", str(uuid.uuid4()))
                self.set_meta("head_seq", "0")
                self.set_meta("min_cursor", "0")
            elif int(existing) > STORE_SCHEMA_VERSION:
                raise BanSyncError(
                    f"Ban-sync store schema {existing} is newer than supported {STORE_SCHEMA_VERSION}"
                )

    def meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # -- node reports -----------------------------------------------------

    def record_node_report(
        self,
        report: Mapping[str, Any],
        payload_sha256: str,
        *,
        channel: str = "agent",
        now_epoch: int | None = None,
    ) -> str:
        """Replace one node channel's decision snapshot.

        Returns ``accepted``, ``duplicate`` or ``stale``.  A report UUID reused
        with different content raises.  An older report (by generated time)
        never overwrites a newer one.
        """
        now = int(now_epoch if now_epoch is not None else time.time())
        node_id = str(report["node_id"])
        with self.transaction():
            receipt = self.conn.execute(
                "SELECT node_id, payload_sha256 FROM report_receipts WHERE report_uuid=?",
                (report["report_uuid"],),
            ).fetchone()
            if receipt is not None:
                if receipt["node_id"] != node_id or receipt["payload_sha256"] != payload_sha256:
                    raise BanSyncError("report_uuid was previously used with different content")
                return "duplicate"
            self.conn.execute(
                "INSERT INTO report_receipts VALUES (?, ?, ?, ?)",
                (report["report_uuid"], node_id, payload_sha256, now),
            )
            self.conn.execute("DELETE FROM report_receipts WHERE received_epoch < ?", (now - 30 * 86400,))
            current = self.conn.execute(
                "SELECT generated_epoch FROM node_reports WHERE node_id=? AND channel=?",
                (node_id, channel),
            ).fetchone()
            if current is not None and int(current["generated_epoch"]) > int(report["generated_epoch"]):
                return "stale"
            first_seen = {
                (row["source"], row["source_id"], row["scope"], row["value"]): int(row["first_seen_epoch"])
                for row in self.conn.execute(
                    "SELECT source, source_id, scope, value, first_seen_epoch FROM node_decisions "
                    "WHERE node_id=? AND channel=?",
                    (node_id, channel),
                )
            }
            self.conn.execute("DELETE FROM node_decisions WHERE node_id=? AND channel=?", (node_id, channel))
            for item in report["decisions"]:
                key = (item["source"], item["source_id"], item["scope"], item["value"])
                self.conn.execute(
                    "INSERT OR REPLACE INTO node_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        node_id, channel, item["source"], item["source_id"], item["scope"], item["value"],
                        item["origin"], item["scenario"], item["reason"], item.get("started_epoch"),
                        item.get("until_epoch"), first_seen.get(key, now),
                    ),
                )
            self.conn.execute(
                "INSERT INTO node_reports VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(node_id, channel) DO UPDATE SET report_uuid=excluded.report_uuid, "
                "payload_sha256=excluded.payload_sha256, generated_epoch=excluded.generated_epoch, "
                "received_epoch=excluded.received_epoch, decision_count=excluded.decision_count",
                (
                    node_id, channel, report["report_uuid"], payload_sha256,
                    int(report["generated_epoch"]), now, len(report["decisions"]),
                ),
            )
        return "accepted"

    def candidate_decisions(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM node_decisions ORDER BY node_id, scope, value")]

    # -- effective set ----------------------------------------------------

    def head_seq(self) -> int:
        return int(self.meta("head_seq") or 0)

    def reconcile(
        self,
        computed: Mapping[str, Mapping[str, Any]],
        removed_reasons: Mapping[str, str],
        *,
        now_epoch: int,
        tombstone_retention_seconds: int,
        update_tolerance_seconds: int = 60,
    ) -> dict[str, int]:
        """Converge the effective table to ``computed``; bump the cursor once
        per changed entry.  Returns change counts."""
        counts = {"added": 0, "updated": 0, "removed": 0}
        with self.transaction():
            seq = self.head_seq()
            existing = {row["id"]: row for row in self.conn.execute("SELECT * FROM effective")}
            for identifier, entry in sorted(computed.items()):
                row = existing.get(identifier)
                if row is not None and int(row["active"]) == 1:
                    changed = (
                        abs(int(row["until_epoch"]) - int(entry["until_epoch"])) > update_tolerance_seconds
                        or row["origin_node"] != entry["origin_node"]
                        or row["reason"] != entry["reason"]
                        or (row["contributors"] or "") != contributors_text(entry)
                    )
                    if not changed:
                        continue
                    counts["updated"] += 1
                else:
                    counts["added"] += 1
                seq += 1
                first_seen = int(row["first_seen_epoch"]) if row is not None else int(entry["first_seen_epoch"])
                self.conn.execute(
                    "INSERT INTO effective (id, scope, value, until_epoch, reason, scenario, origin, origin_node, "
                    "first_seen_epoch, active, removed_reason, seq, updated_epoch, contributors) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET scope=excluded.scope, value=excluded.value, "
                    "until_epoch=excluded.until_epoch, reason=excluded.reason, scenario=excluded.scenario, "
                    "origin=excluded.origin, origin_node=excluded.origin_node, active=1, removed_reason=NULL, "
                    "seq=excluded.seq, updated_epoch=excluded.updated_epoch, contributors=excluded.contributors",
                    (
                        identifier, entry["scope"], entry["value"], int(entry["until_epoch"]),
                        entry["reason"], entry["scenario"], entry["origin"], entry["origin_node"],
                        first_seen, seq, now_epoch, contributors_text(entry),
                    ),
                )
            for identifier, row in sorted(existing.items()):
                if int(row["active"]) != 1 or identifier in computed:
                    continue
                seq += 1
                counts["removed"] += 1
                reason = removed_reasons.get(identifier)
                if reason is None:
                    reason = "expired" if int(row["until_epoch"]) <= now_epoch else "revoked"
                self.conn.execute(
                    "UPDATE effective SET active=0, removed_reason=?, seq=?, updated_epoch=? WHERE id=?",
                    (reason[:200], seq, now_epoch, identifier),
                )
            # Tombstone collection.  A client whose cursor predates the newest
            # collected tombstone must take a full snapshot.
            horizon = now_epoch - int(tombstone_retention_seconds)
            collected = self.conn.execute(
                "SELECT MAX(seq) FROM effective WHERE active=0 AND updated_epoch < ?", (horizon,)
            ).fetchone()[0]
            if collected is not None:
                self.conn.execute("DELETE FROM effective WHERE active=0 AND updated_epoch < ?", (horizon,))
                self.set_meta("min_cursor", str(max(int(self.meta("min_cursor") or 0), int(collected))))
            self.set_meta("head_seq", str(seq))
        return counts

    def purge_channel(self, channel: str) -> int:
        """Drop every report and decision of one channel (legacy cleanup)."""
        with self.transaction():
            removed = self.conn.execute("DELETE FROM node_decisions WHERE channel=?", (channel,)).rowcount
            self.conn.execute("DELETE FROM node_reports WHERE channel=?", (channel,))
        return int(removed or 0)

    def record_merge_run(self, now_epoch: int, status: str, detail: str, stats: Mapping[str, int]) -> None:
        with self.transaction():
            self.conn.execute(
                "INSERT OR REPLACE INTO merge_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    now_epoch, status, detail[:500], int(stats.get("candidates", 0)),
                    int(stats.get("active", 0)), int(stats.get("added", 0)), int(stats.get("updated", 0)),
                    int(stats.get("removed", 0)), int(stats.get("protected", 0)),
                ),
            )
            self.conn.execute("DELETE FROM merge_runs WHERE run_epoch < ?", (now_epoch - 7 * 86400,))

    def last_merge_run(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM merge_runs ORDER BY run_epoch DESC LIMIT 1").fetchone()
        return None if row is None else dict(row)

    # -- downstream view ----------------------------------------------------

    def node_view(self, node_id: str, cursor: int, *, now_epoch: int | None = None) -> dict[str, Any]:
        """Snapshot (cursor 0, unknown, ahead or collected) or delta for one
        node, read inside one transaction so cursor, rows and digest agree.

        Entries the requesting node itself currently reports (it is one of
        the entry's contributors, not only the winning origin) are withheld
        from it: the node already holds that ban locally, and receiving it
        back would only add a redundant synced decision that churns whenever
        the winning origin changes.  Once the node stops reporting the target
        (its local ban ended) the entry becomes visible to it on the next
        merge if another node still bans it.
        """
        now = int(now_epoch if now_epoch is not None else time.time())
        with self.transaction():
            set_id = self.meta("set_id") or ""
            head = self.head_seq()
            min_cursor = int(self.meta("min_cursor") or 0)
            rows = list(self.conn.execute("SELECT * FROM effective ORDER BY id"))

        def own(row: sqlite3.Row) -> bool:
            return row["origin_node"] == node_id or node_id in str(row["contributors"] or "").split(",")

        def visible(row: sqlite3.Row) -> bool:
            return int(row["active"]) == 1 and not own(row) and int(row["until_epoch"]) > now

        def to_entry(row: sqlite3.Row) -> dict[str, Any]:
            return {
                "id": row["id"],
                "scope": row["scope"],
                "value": row["value"],
                "until": epoch_text(int(row["until_epoch"])),
                "reason": row["reason"],
                "origin_node": row["origin_node"],
            }

        view = [to_entry(row) for row in rows if visible(row)]
        reset = cursor <= 0 or cursor < min_cursor or cursor > head
        response: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "set_id": set_id,
            "node_id": node_id,
            "cursor": head,
            "requested_cursor": int(cursor),
            "reset": reset,
            "generated_at": epoch_text(now),
            "generated_epoch": now,
            "count": len(view),
            "snapshot_sha256": view_digest(view, now),
            "entries": view if reset else [],
            "upserts": [],
            "removals": [],
        }
        if not reset:
            for row in rows:
                if int(row["seq"]) <= cursor:
                    continue
                if visible(row):
                    response["upserts"].append(to_entry(row))
                else:
                    reason = row["removed_reason"]
                    if not reason:
                        reason = "origin-node" if own(row) else "expired"
                    response["removals"].append({"id": row["id"], "reason": reason})
        return response

    def record_pull(
        self,
        node_id: str,
        requested: int,
        served: int,
        reset: bool,
        entries: int,
        now_epoch: int | None = None,
    ) -> None:
        now = int(now_epoch if now_epoch is not None else time.time())
        with self.transaction():
            self.conn.execute(
                "INSERT INTO node_pulls VALUES (?, ?, ?, ?, ?, ?, ?, 1) "
                "ON CONFLICT(node_id) DO UPDATE SET last_pull_epoch=excluded.last_pull_epoch, "
                "requested_cursor=excluded.requested_cursor, served_cursor=excluded.served_cursor, "
                "last_reset=excluded.last_reset, served_entries=excluded.served_entries, pulls=pulls+1",
                (node_id, now, now, int(requested), int(served), 1 if reset else 0, int(entries)),
            )

    def node_pulls(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM node_pulls ORDER BY node_id")]

    def summary(self, now_epoch: int | None = None) -> dict[str, Any]:
        """Dashboard / status view: head cursor, active count and per-node lag."""
        now = int(now_epoch if now_epoch is not None else time.time())
        head = self.head_seq()
        active = self.conn.execute(
            "SELECT COUNT(*) FROM effective WHERE active=1 AND until_epoch > ?", (now,)
        ).fetchone()[0]
        by_origin = {
            str(row[0]): int(row[1])
            for row in self.conn.execute(
                "SELECT origin_node, COUNT(*) FROM effective WHERE active=1 AND until_epoch > ? "
                "GROUP BY origin_node",
                (now,),
            )
        }
        reports = []
        for row in self.conn.execute("SELECT * FROM node_reports ORDER BY node_id, channel"):
            item = dict(row)
            item["received_at"] = epoch_text(int(row["received_epoch"]))
            item["age_seconds"] = max(0, now - int(row["received_epoch"]))
            reports.append(item)
        nodes = []
        for pull in self.node_pulls():
            nodes.append(
                {
                    "node_id": pull["node_id"],
                    "last_pull_at": epoch_text(int(pull["last_pull_epoch"])),
                    "last_pull_epoch": int(pull["last_pull_epoch"]),
                    "lag_seconds": max(0, now - int(pull["last_pull_epoch"])),
                    "cursor": int(pull["served_cursor"]),
                    "cursor_behind": max(0, head - int(pull["served_cursor"])),
                    "last_reset": bool(pull["last_reset"]),
                    "served_entries": int(pull["served_entries"]),
                    "pulls": int(pull["pulls"]),
                }
            )
        return {
            "set_id": self.meta("set_id"),
            "head_cursor": head,
            "min_cursor": int(self.meta("min_cursor") or 0),
            "active_entries": int(active),
            "active_by_origin_node": by_origin,
            "node_reports": reports,
            "nodes": nodes,
            "last_merge": self.last_merge_run(),
        }


class _Transaction:
    """Explicit BEGIN IMMEDIATE / COMMIT for an autocommit connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.outer = False

    def __enter__(self) -> "_Transaction":
        if self.conn.in_transaction:
            return self
        self.outer = True
        try:
            self.conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            # Read-only connections cannot take a write lock.
            self.conn.execute("BEGIN")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if not self.outer:
            return
        if exc_type is None:
            self.conn.execute("COMMIT")
        else:
            self.conn.execute("ROLLBACK")


# --------------------------------------------------------------------------
# Central merge


CENTRAL_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "store_db": "/var/lib/argent-sentinel/server/ban-sync.sqlite3",
    "incoming_globs": ["/var/lib/argent-sentinel/drop/remote/*/decisions/incoming/*.json"],
    "archive_dir": "/var/lib/argent-sentinel/collector/decisions-archive",
    "rejected_dir": "/var/lib/argent-sentinel/collector/decisions-rejected",
    "max_file_bytes": 8 * 1024 * 1024,
    "allowed_origins": list(CROWDSEC_ORIGINS) + [FAIL2BAN_ORIGIN],
    "max_duration_seconds": DEFAULT_MAX_DURATION_SECONDS,
    "protected_cidrs": [],
    "tombstone_retention_seconds": 8 * 86400,
    "refresh_seconds": 60,
    # Sanitized summary (no entries) for the dashboard snapshot and the lag
    # watchdog, whose sandboxes cannot open the store's WAL files.
    "status_file": "/var/lib/argent-sentinel/collector/ban-sync-status.json",
}


def validate_central_settings(settings: Mapping[str, Any]) -> None:
    if not isinstance(settings, Mapping):
        raise BanSyncError("ban_sync must be an object")
    if not isinstance(settings.get("enabled", False), bool):
        raise BanSyncError("ban_sync.enabled must be boolean")
    # include_central_crowdsec / central_origins (pre-release) are ignored:
    # the central host reports through its own agent like every node.
    if not str(settings.get("store_db", "")).startswith("/"):
        raise BanSyncError("ban_sync.store_db must be an absolute path")
    values = settings.get("allowed_origins", [])
    if not isinstance(values, list) or any(str(item) in EXCLUDED_ORIGINS for item in values):
        raise BanSyncError("ban_sync.allowed_origins must be a list without CAPI/lists/console")
    if int(settings.get("max_duration_seconds", 0)) < 0:
        raise BanSyncError("ban_sync.max_duration_seconds must be zero (no cap) or positive")
    if int(settings.get("tombstone_retention_seconds", 0)) < 86400:
        raise BanSyncError("ban_sync.tombstone_retention_seconds must be at least 86400")
    if not isinstance(settings.get("protected_cidrs", []), list):
        raise BanSyncError("ban_sync.protected_cidrs must be a list")
    if not str(settings.get("status_file", "/")).startswith("/"):
        raise BanSyncError("ban_sync.status_file must be an absolute path")
    parse_networks(settings.get("protected_cidrs", []))


def central_protection(config: Mapping[str, Any], *, now_epoch: int) -> tuple[dict[str, list[Any]], str | None]:
    """Build the central never-ban boundary.

    Returns (labelled networks, problem).  ``problem`` is set when the dynamic
    protected state is missing or stale; the merge then fails closed.
    """
    protection = config.get("enforcement_protection") or {}
    protected: dict[str, list[Any]] = {
        "trusted_cidrs": parse_networks(config.get("trusted_cidrs", [])),
        "enforcement_protection.protected_cidrs": parse_networks(protection.get("protected_cidrs", [])),
        "ban_sync.protected_cidrs": parse_networks((config.get("ban_sync") or {}).get("protected_cidrs", [])),
    }
    state_file = protection.get("dynamic_state_file") or (config.get("protection_inventory") or {}).get(
        "state_file", "/var/lib/argent-sentinel/collector/effective-protected-cidrs.json"
    )
    state_path = Path(str(state_file))
    max_age = int(protection.get("dynamic_state_max_age_seconds", 600))
    state = load_json_file(state_path)
    if not state or state.get("schema_version") != 1:
        return protected, f"dynamic protected state unavailable: {state_path}"
    generated = int(state.get("generated_epoch", 0) or 0)
    if generated < 1 or now_epoch - generated > max_age:
        return protected, "dynamic protected state is stale"
    try:
        protected["dynamic protected state"] = parse_networks(state.get("dynamic_cidrs", []))
    except BanSyncError as exc:
        return protected, f"dynamic protected state is invalid: {exc}"
    # Every node's protection inventory, including expired ones: a stale
    # inventory is a reason to protect, never a reason to ban.
    node_networks: list[Any] = []
    for node in state.get("nodes", []) if isinstance(state.get("nodes"), list) else []:
        if not isinstance(node, Mapping):
            continue
        try:
            node_networks.extend(parse_networks(node.get("effective_cidrs", [])))
        except BanSyncError:
            continue
    protected["node protection inventory"] = node_networks
    return protected, None


def capped_until(
    until_epoch: int | None,
    *,
    started_epoch: int | None,
    first_seen_epoch: int,
    max_duration_seconds: int,
) -> int:
    """Keep the original expiry, capped at start + max_duration_seconds.

    The cap anchors on the decision's own start time (CrowdSec alert
    ``start_at`` or fail2ban ``timeofban``) and falls back to when central
    first saw it, so the cap never slides forward on later reports.
    Permanent decisions (no expiry) take the cap, or a 30-day ceiling when the
    cap is disabled.
    """
    anchor = int(started_epoch) if started_epoch else int(first_seen_epoch)
    if int(max_duration_seconds) > 0:
        ceiling = anchor + int(max_duration_seconds)
        return ceiling if until_epoch is None else min(int(until_epoch), ceiling)
    if until_epoch is None:
        return anchor + PERMANENT_CEILING_SECONDS
    return int(until_epoch)


def compute_effective(
    candidates: Iterable[Mapping[str, Any]],
    protected: Mapping[str, Sequence[Any]],
    *,
    now_epoch: int,
    max_duration_seconds: int = DEFAULT_MAX_DURATION_SECONDS,
    allowed_origins: Sequence[str] = CROWDSEC_ORIGINS + (FAIL2BAN_ORIGIN,),
) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, int]]:
    """Merge candidate decisions into one effective entry per (scope, value).

    Order: origin allowlist (drops CAPI / lists / console), loop prevention,
    target safety (global, bounded ranges), protection overlap, expiry cap,
    then the latest-expiring candidate per target wins (ties: node id).

    Returns (entries by id, removal reasons for filtered targets, stats).
    """
    allowed = {str(item) for item in allowed_origins}
    stats = {"candidates": 0, "origin": 0, "loop": 0, "unsafe": 0, "protected": 0, "expired": 0}
    removed: dict[str, str] = {}
    best: dict[str, dict[str, Any]] = {}
    contributors: dict[str, set[str]] = {}
    for item in candidates:
        stats["candidates"] += 1
        origin = str(item.get("origin", ""))
        if origin in EXCLUDED_ORIGINS or origin not in allowed:
            stats["origin"] += 1
            continue
        reason = str(item.get("reason", ""))
        scenario = str(item.get("scenario", ""))
        channel = str(item.get("channel", "agent"))
        # Never re-originate a synced decision.  Agents already skip them;
        # this is the central backstop.  Legacy "central" channel rows (0.5.8.0
        # pre-release direct read) are ignored.
        if is_sync_reason(reason) or is_sync_reason(scenario):
            stats["loop"] += 1
            continue
        if channel != "agent":
            stats["origin"] += 1
            continue
        scope = str(item["scope"])
        value = str(item["value"])
        identifier = entry_id(scope, value)
        refusal = target_safety(scope, value)
        if refusal is not None:
            stats["unsafe"] += 1
            removed[identifier] = f"unsafe: {refusal}"
            continue
        match = protection_match(scope, value, protected)
        if match is not None:
            stats["protected"] += 1
            removed[identifier] = f"protected: {match}"
            continue
        first_seen = int(item.get("first_seen_epoch") or now_epoch)
        until_epoch = capped_until(
            item.get("until_epoch"),
            started_epoch=item.get("started_epoch"),
            first_seen_epoch=first_seen,
            max_duration_seconds=max_duration_seconds,
        )
        if until_epoch <= now_epoch:
            stats["expired"] += 1
            continue
        entry = {
            "id": identifier,
            "scope": scope,
            "value": value,
            "until_epoch": until_epoch,
            "reason": sanitize_reason(reason),
            "scenario": sanitize_reason(scenario, 128),
            "origin": origin,
            "origin_node": str(item["node_id"]),
            "first_seen_epoch": first_seen,
        }
        contributors.setdefault(identifier, set()).add(entry["origin_node"])
        current = best.get(identifier)
        if current is None or (entry["until_epoch"], entry["origin_node"]) > (
            current["until_epoch"], current["origin_node"]
        ):
            best[identifier] = entry
    for identifier, entry in best.items():
        removed.pop(identifier, None)
        entry["contributors"] = sorted(contributors.get(identifier, {entry["origin_node"]}))
    stats["active"] = len(best)
    return best, removed, stats


def ingest_report_files(store: BanSyncStore, settings: Mapping[str, Any], *, now_epoch: int, log: Any = None) -> int:
    """Import node decision reports dropped by the API into the store."""
    imported = 0
    day = dt.datetime.fromtimestamp(now_epoch, UTC)
    archive_root = Path(str(settings["archive_dir"])) / f"{day:%Y}" / f"{day:%m}" / f"{day:%d}"
    rejected_root = Path(str(settings["rejected_dir"])) / f"{day:%Y-%m-%d}"
    max_bytes = int(settings["max_file_bytes"])
    paths: set[Path] = set()
    for pattern in settings.get("incoming_globs", []):
        for value in glob.glob(str(pattern)):
            path = Path(value)
            if not path.name.startswith(".") and path.suffix == ".json":
                paths.add(path)
    for path in sorted(paths, key=str):
        destination = archive_root
        error: str | None = None
        try:
            if path.is_symlink() or not path.is_file():
                raise BanSyncError("decisions report must be a regular, non-symlink file")
            data = path.read_bytes()
            if not data or len(data) > max_bytes:
                raise BanSyncError("decisions report size is outside limits")
            raw = json.loads(data.decode("utf-8"))
            parts = path.parts
            if "remote" in parts and parts.index("remote") + 1 < len(parts):
                expected = parts[parts.index("remote") + 1]
            else:
                expected = str(raw.get("node_id", "")) if isinstance(raw, Mapping) else ""
            report = validate_decisions_report(raw, expected)
            store.record_node_report(report, hashlib.sha256(data).hexdigest(), now_epoch=now_epoch)
            imported += 1
        except (BanSyncError, ValueError, UnicodeDecodeError, OSError, sqlite3.Error) as exc:
            destination = rejected_root
            error = str(exc)[:2000]
            if log is not None:
                log.warning("Rejecting decisions report %s: %s", path, exc)
        try:
            destination.mkdir(parents=True, exist_ok=True, mode=0o750)
            final = destination / path.name
            if final.exists():
                final = destination / f"{path.stem}-{uuid.uuid4()}{path.suffix}"
            if not path.is_symlink():
                os.replace(path, final)
            else:
                path.unlink()
            if error is not None:
                final.with_suffix(final.suffix + ".error.txt").write_text(error, encoding="utf-8")
        except OSError as exc:
            if log is not None:
                log.warning("Could not move decisions report %s: %s", path, exc)
    return imported


def publish_status(config: Mapping[str, Any], *, now_epoch: int | None = None) -> dict[str, Any]:
    """Write the sanitized store summary (per-node lag, counts; no entries)."""
    settings = dict(CENTRAL_DEFAULTS) | dict(config.get("ban_sync") or {})
    if not settings.get("enabled"):
        return {"status": "disabled"}
    now = int(now_epoch if now_epoch is not None else time.time())
    store = BanSyncStore(Path(str(settings["store_db"])))
    try:
        summary = store.summary(now_epoch=now)
    finally:
        store.close()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_epoch": now,
        "generated_at": epoch_text(now),
        "version": APP_VERSION,
    } | summary
    atomic_write_json(Path(str(settings["status_file"])), payload, 0o640)
    return payload


def run_central_merge(
    config: Mapping[str, Any],
    *,
    now_epoch: int | None = None,
    log: Any = None,
    force: bool = False,
) -> dict[str, Any]:
    """One collector-side merge pass.  No-op unless ``ban_sync.enabled``.

    Inputs are node reports only; the central host's local CrowdSec bans
    arrive through its own agent like any other node's."""
    settings = dict(CENTRAL_DEFAULTS) | dict(config.get("ban_sync") or {})
    if not settings.get("enabled"):
        return {"status": "disabled"}
    now = int(now_epoch if now_epoch is not None else time.time())
    store = BanSyncStore(Path(str(settings["store_db"])))
    try:
        last = store.last_merge_run()
        if not force and last is not None and now - int(last["run_epoch"]) < int(settings["refresh_seconds"]):
            return {"status": "not-due"}
        imported = ingest_report_files(store, settings, now_epoch=now, log=log)
        # The central host's own bans arrive through its own agent's node
        # report like every other node's; there is no direct central read.
        # Rows from the pre-release direct-read channel are purged.
        store.purge_channel("central")
        protected, problem = central_protection(config, now_epoch=now)
        if problem is not None:
            # Fail closed: publish nothing while the never-ban boundary is
            # unknown.  Existing entries stay; agents re-check locally.
            store.record_merge_run(now, "protection-unavailable", problem, {})
            return {"status": "protection-unavailable", "detail": problem, "imported": imported}
        candidates = store.candidate_decisions()
        computed, removed, stats = compute_effective(
            candidates,
            protected,
            now_epoch=now,
            max_duration_seconds=int(settings["max_duration_seconds"]),
            allowed_origins=tuple(settings["allowed_origins"]),
        )
        changes = store.reconcile(
            computed,
            removed,
            now_epoch=now,
            tombstone_retention_seconds=int(settings["tombstone_retention_seconds"]),
        )
        stats.update(changes)
        store.record_merge_run(now, "ok", f"imported {imported} report(s)", stats)
        return {"status": "ok", "imported": imported, "head_cursor": store.head_seq()} | stats
    finally:
        store.close()


# --------------------------------------------------------------------------
# Agent: upstream reporting


AGENT_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "cscli_path": "/usr/bin/cscli",
    "command_timeout_seconds": 20,
    "upstream": {
        "enabled": True,
        "crowdsec_origins": list(CROWDSEC_ORIGINS),
        "fail2ban_enabled": True,
        "fail2ban_db": "/var/lib/fail2ban/fail2ban.sqlite3",
        "fail2ban_jails": [],
        "heartbeat_seconds": 900,
        "max_decisions": MAX_REPORT_DECISIONS,
        "state_file": "/var/lib/argent-sentinel/agent/ban-sync-upstream-state.json",
    },
    "apply": {
        "enabled": True,
        "dry_run": True,
        "endpoint_path": "/v1/decisions",
        "interval_minutes": 5,
        "state_file": "/var/lib/argent-sentinel/agent/ban-sync-state.json",
        "local_allowlist": [],
        "check_crowdsec_allowlists": True,
        "min_remaining_seconds": 60,
        "update_tolerance_seconds": 300,
        "max_changes_per_run": 500,
        "max_response_bytes": 16 * 1024 * 1024,
        "max_preview_entries": 200,
        # Pinned central signing public key(s).  Empty: signatures optional
        # (rollout).  Non-empty: every response must be signed by one of them.
        "signing_public_key_files": [],
        "max_view_age_seconds": 900,
        "openssl_path": "openssl",
    },
}


def validate_agent_settings(settings: Mapping[str, Any]) -> None:
    if not isinstance(settings, Mapping):
        raise BanSyncError("ban_sync must be an object")
    if not isinstance(settings.get("enabled", False), bool):
        raise BanSyncError("ban_sync.enabled must be boolean")
    if not str(settings.get("cscli_path", "")).startswith("/"):
        raise BanSyncError("ban_sync.cscli_path must be an absolute path")
    if not 1 <= int(settings.get("command_timeout_seconds", 0)) <= 120:
        raise BanSyncError("ban_sync.command_timeout_seconds must be between 1 and 120")
    upstream = settings.get("upstream", {})
    apply = settings.get("apply", {})
    if not isinstance(upstream, Mapping) or not isinstance(apply, Mapping):
        raise BanSyncError("ban_sync.upstream and ban_sync.apply must be objects")
    for name in ("enabled", "fail2ban_enabled"):
        if not isinstance(upstream.get(name, False), bool):
            raise BanSyncError(f"ban_sync.upstream.{name} must be boolean")
    origins = upstream.get("crowdsec_origins", [])
    if not isinstance(origins, list) or any(str(item) in EXCLUDED_ORIGINS for item in origins):
        raise BanSyncError("ban_sync.upstream.crowdsec_origins must be a list without CAPI/lists/console")
    if not isinstance(upstream.get("fail2ban_jails", []), list):
        raise BanSyncError("ban_sync.upstream.fail2ban_jails must be a list")
    if int(upstream.get("heartbeat_seconds", 0)) < 60:
        raise BanSyncError("ban_sync.upstream.heartbeat_seconds must be at least 60")
    if not 1 <= int(upstream.get("max_decisions", 0)) <= MAX_REPORT_DECISIONS:
        raise BanSyncError(f"ban_sync.upstream.max_decisions must be between 1 and {MAX_REPORT_DECISIONS}")
    for name in ("enabled", "dry_run", "check_crowdsec_allowlists"):
        if not isinstance(apply.get(name, False), bool):
            raise BanSyncError(f"ban_sync.apply.{name} must be boolean")
    if not str(apply.get("endpoint_path", "")).startswith("/"):
        raise BanSyncError("ban_sync.apply.endpoint_path must begin with /")
    if not 1 <= int(apply.get("interval_minutes", 0)) <= 1440:
        raise BanSyncError("ban_sync.apply.interval_minutes must be between 1 and 1440")
    for name in ("max_changes_per_run", "max_response_bytes", "max_preview_entries"):
        if int(apply.get(name, 0)) < 1:
            raise BanSyncError(f"ban_sync.apply.{name} must be positive")
    for name in ("min_remaining_seconds", "update_tolerance_seconds"):
        if int(apply.get(name, -1)) < 0:
            raise BanSyncError(f"ban_sync.apply.{name} must not be negative")
    keys = apply.get("signing_public_key_files", [])
    if not isinstance(keys, list) or not all(str(item).startswith("/") for item in keys):
        raise BanSyncError("ban_sync.apply.signing_public_key_files must be a list of absolute paths")
    if not 60 <= int(apply.get("max_view_age_seconds", 900)) <= 86400:
        raise BanSyncError("ban_sync.apply.max_view_age_seconds must be between 60 and 86400")
    allowlist = apply.get("local_allowlist", [])
    if not isinstance(allowlist, list):
        raise BanSyncError("ban_sync.apply.local_allowlist must be a list")
    parse_networks(allowlist)
    for section in ("upstream", "apply"):
        value = (settings.get(section) or {}).get("state_file", "")
        if not str(value).startswith("/"):
            raise BanSyncError(f"ban_sync.{section}.state_file must be an absolute path")


def collect_upstream_decisions(
    settings: Mapping[str, Any],
    *,
    now_epoch: int,
    runner: Runner = subprocess.run,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Local decisions eligible for upstream reporting.

    Loop prevention: every decision written by this sync (reason prefix
    ``argent-sentinel:``) is skipped.  Collector bans (``argent-sentinel/``)
    are ordinary local bans and are reported.
    """
    upstream = settings["upstream"]
    info: dict[str, Any] = {"crowdsec": "absent", "fail2ban": "disabled"}
    decisions: list[dict[str, Any]] = []
    cscli = str(settings["cscli_path"])
    if runner is not subprocess.run or Path(cscli).is_file():
        found, skipped = read_cscli_decisions(
            cscli,
            timeout=int(settings["command_timeout_seconds"]),
            now_epoch=now_epoch,
            runner=runner,
            origins=tuple(upstream.get("crowdsec_origins", CROWDSEC_ORIGINS)),
            skip_reason=is_sync_reason,
        )
        decisions.extend(found)
        info["crowdsec"] = {"decisions": len(found), "skipped": skipped}
    if upstream.get("fail2ban_enabled"):
        bans = read_fail2ban_bans(
            Path(str(upstream["fail2ban_db"])),
            now_epoch=now_epoch,
            jails=upstream.get("fail2ban_jails", []),
        )
        decisions.extend(bans)
        info["fail2ban"] = {"bans": len(bans)}
    decisions.sort(key=lambda item: (item["scope"], item["value"], item["source"], item["source_id"]))
    maximum = int(upstream["max_decisions"])
    if len(decisions) > maximum:
        info["truncated"] = len(decisions) - maximum
        decisions = decisions[:maximum]
    return decisions, info


def upstream_due(state: Mapping[str, Any], digest: str, now_epoch: int, heartbeat: int) -> bool:
    """Stage a report when the content digest changes or the heartbeat lapses."""
    if state.get("digest") != digest:
        return True
    return now_epoch - int(state.get("last_staged_epoch", 0) or 0) >= int(heartbeat)


# --------------------------------------------------------------------------
# Agent: pull, mirror and apply


def local_interface_networks(runner: Runner = subprocess.run) -> list[Any]:
    """Every address on every interface (both families) as host networks."""
    try:
        result = run_command(runner, ["ip", "-j", "address", "show"], 15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BanSyncError(f"Cannot list local addresses: {exc}") from exc
    if result.returncode != 0:
        raise BanSyncError(f"ip address show exited {result.returncode}")
    try:
        rows = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise BanSyncError(f"Invalid ip -j output: {exc}") from exc
    networks = []
    for row in rows if isinstance(rows, list) else []:
        for item in row.get("addr_info", []) if isinstance(row, Mapping) else []:
            if not isinstance(item, Mapping):
                continue
            try:
                address = ipaddress.ip_address(str(item.get("local", "")))
            except ValueError:
                continue
            networks.append(ipaddress.ip_network(address))
    return networks


def local_protection_sets(
    config: Mapping[str, Any],
    *,
    interfaces: Sequence[Any] | None = None,
    inventory_cidrs: Sequence[str] | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, list[Any]]:
    """The node's own never-ban boundary: own interfaces, the effective
    local_address_protection CIDRs (plus manual CIDRs), and the local
    allowlist."""
    settings = config["ban_sync"]
    local = config.get("local_address_protection") or {}
    return {
        "own interface": list(interfaces) if interfaces is not None else local_interface_networks(runner),
        "local_address_protection": parse_networks(
            list(inventory_cidrs or []) + list(local.get("manual_cidrs", []))
        ),
        "ban_sync.apply.local_allowlist": parse_networks(settings["apply"].get("local_allowlist", [])),
    }


def crowdsec_allowlisted(cscli: str, value: str, timeout: int, runner: Runner) -> str | None:
    """Refusal reason when CrowdSec allowlists cover the value or the check
    cannot be completed (fail closed); None when clear."""
    try:
        result = run_command(runner, [cscli, "allowlists", "check", value], timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"allowlist check failed: {exc}"
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "is allowlisted" in combined:
        return "CrowdSec allowlist"
    if result.returncode not in (0, 1):
        return f"allowlist check exited {result.returncode}"
    return None


def validate_view(payload: Any) -> dict[str, Any]:
    """Validate a downstream response; every entry id must match its value."""
    if not isinstance(payload, Mapping) or payload.get("schema_version") != SCHEMA_VERSION:
        raise BanSyncError("Unsupported decisions response schema")
    if not isinstance(payload.get("set_id"), str) or not payload.get("set_id"):
        raise BanSyncError("decisions response lacks set_id")
    if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("snapshot_sha256", ""))):
        raise BanSyncError("snapshot_sha256 must be a SHA-256 hex digest")
    for name in ("cursor", "generated_epoch"):
        value = payload.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BanSyncError(f"decisions response {name} must be a non-negative integer")
    cleaned: dict[str, list[dict[str, Any]]] = {}
    for name in ("entries", "upserts"):
        values = payload.get(name, [])
        if not isinstance(values, list):
            raise BanSyncError(f"decisions response {name} must be a list")
        items = []
        for raw in values:
            if not isinstance(raw, Mapping):
                raise BanSyncError(f"{name} entries must be objects")
            scope = str(raw.get("scope", ""))
            if scope not in SCOPES:
                raise BanSyncError(f"{name} entry scope must be Ip or Range")
            try:
                value = normalize_value(scope, raw.get("value"))
            except ValueError as exc:
                raise BanSyncError(f"{name} entry value is invalid") from exc
            if str(raw.get("id", "")) != entry_id(scope, value):
                raise BanSyncError(f"{name} entry id does not match its scope and value")
            if parse_time(raw.get("until")) is None:
                raise BanSyncError(f"{name} entry until is invalid")
            origin_node = str(raw.get("origin_node", ""))
            if not NODE_ID_RE.fullmatch(origin_node):
                raise BanSyncError(f"{name} entry origin_node is invalid")
            items.append(
                {
                    "id": entry_id(scope, value),
                    "scope": scope,
                    "value": value,
                    "until": str(raw.get("until")),
                    "reason": sanitize_reason(raw.get("reason")),
                    "origin_node": origin_node,
                }
            )
        cleaned[name] = items
    removals = payload.get("removals", [])
    if not isinstance(removals, list) or not all(isinstance(item, Mapping) and item.get("id") for item in removals):
        raise BanSyncError("decisions response removals must be objects with id")
    result = dict(payload)
    result["entries"] = cleaned["entries"]
    result["upserts"] = cleaned["upserts"]
    result["removals"] = [{"id": str(item["id"]), "reason": str(item.get("reason", ""))[:200]} for item in removals]
    result["reset"] = bool(payload.get("reset"))
    return result


def fetch_view(
    config: Mapping[str, Any],
    cursor: int,
    *,
    opener: Callable[..., Any] | None = None,
    verifier: Callable[[Mapping[str, Any], int], str] | None = None,
) -> dict[str, Any]:
    """GET <central_url>/v1/decisions?cursor=N over the agent's mTLS identity."""
    settings = config["ban_sync"]["apply"]
    base = str(config["central_url"]).rstrip("/")
    url = f"{base}{settings['endpoint_path']}?{urllib.parse.urlencode({'cursor': int(cursor)})}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": f"Argent-Sentinel-Agent/{APP_VERSION}"},
    )
    if opener is None:
        context = ssl.create_default_context(cafile=str(config["ca_file"]))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(config["cert_file"]), str(config["key_file"]))

        def opener(req: Any, timeout: int) -> Any:
            return urllib.request.urlopen(req, timeout=timeout, context=context)

    limit = int(settings["max_response_bytes"])
    try:
        with opener(request, timeout=int(config.get("timeout_seconds", 30))) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise BanSyncError(f"decisions pull HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError, ssl.SSLError) as exc:
        raise BanSyncError(f"decisions pull failed: {exc}") from exc
    if len(data) > limit:
        raise BanSyncError("decisions response exceeds max_response_bytes")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BanSyncError(f"decisions response is invalid JSON: {exc}") from exc
    # The signature covers the raw response, so it is checked before any
    # normalisation in validate_view.
    signature_status = verifier(payload, int(cursor)) if verifier is not None else "unchecked"
    view = validate_view(payload)
    view["signature_status"] = signature_status
    return view


def merge_view(state: Mapping[str, Any], view: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], bool]:
    """Apply one snapshot or delta to the local mirror of central's view.

    Returns (new mirror, digest_ok).  Local protection is evaluated later, so
    the mirror always matches central and the digest check is meaningful.
    """
    if view["reset"] or view["set_id"] != state.get("set_id"):
        mirror = {entry["id"]: dict(entry) for entry in view["entries"]}
    else:
        mirror = {key: dict(value) for key, value in (state.get("mirror") or {}).items()}
        for removal in view["removals"]:
            mirror.pop(removal["id"], None)
        for entry in view["upserts"]:
            mirror[entry["id"]] = dict(entry)
    generated = int(view["generated_epoch"])
    mirror = {key: value for key, value in mirror.items() if (parse_time(value.get("until")) or 0) > generated}
    return mirror, view_digest(mirror.values(), generated) == view["snapshot_sha256"]


def plan_changes(
    mirror: Mapping[str, Mapping[str, Any]],
    applied: Mapping[str, Mapping[str, Any]],
    protected: Mapping[str, Sequence[Any]],
    *,
    now_epoch: int,
    min_remaining_seconds: int,
    update_tolerance_seconds: int,
    node_id: str,
) -> dict[str, Any]:
    """Compute adds (with replace flag), removals and protection skips."""
    adds: list[dict[str, Any]] = []
    removes: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    desired: dict[str, dict[str, Any]] = {}
    for identifier, entry in sorted(mirror.items()):
        until = parse_time(entry.get("until")) or 0
        if until - now_epoch < int(min_remaining_seconds) or entry.get("origin_node") == node_id:
            continue
        refusal = target_safety(entry["scope"], entry["value"]) or protection_match(
            entry["scope"], entry["value"], protected
        )
        if refusal is not None:
            skipped.append({"id": identifier, "scope": entry["scope"], "value": entry["value"], "reason": refusal})
            continue
        desired[identifier] = dict(entry) | {"until_epoch": until}
    for identifier, entry in desired.items():
        current = applied.get(identifier)
        if current is None:
            adds.append(entry)
            continue
        expiry_moved = abs(int(current.get("until_epoch", 0)) - int(entry["until_epoch"])) > int(update_tolerance_seconds)
        reason_changed = current.get("reason_text") != sync_reason(entry["origin_node"], entry["reason"])
        if expiry_moved or reason_changed:
            adds.append(entry | {"replace": True})
    for identifier, current in sorted(applied.items()):
        if identifier not in desired:
            removes.append(dict(current) | {"id": identifier})
    return {"adds": adds, "removes": removes, "skipped": skipped, "desired": len(desired)}


def owned_decision_ids(cscli: str, scope: str, value: str, timeout: int, runner: Runner) -> list[int]:
    """IDs of sync-owned decisions on one target.  Never returns a decision
    whose reason lacks the ``argent-sentinel:`` prefix."""
    flag = "--ip" if scope == "Ip" else "--range"
    result = run_command(runner, [cscli, "decisions", "list", flag, value, "-o", "json", "--limit", "0"], timeout)
    if result.returncode != 0:
        raise BanSyncError(f"cscli decisions list {flag} {value} exited {result.returncode}")
    text = (result.stdout or "").strip()
    if not text or text == "null":
        return []
    try:
        alerts = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BanSyncError(f"cscli returned invalid JSON: {exc}") from exc
    ids: list[int] = []
    for alert in alerts if isinstance(alerts, list) else []:
        for decision in (alert.get("decisions") or []) if isinstance(alert, Mapping) else []:
            if not isinstance(decision, Mapping) or not is_sync_reason(decision.get("scenario")):
                continue
            try:
                if normalize_value(scope, decision.get("value")) != value:
                    continue
                ids.append(int(decision.get("id")))
            except (TypeError, ValueError):
                continue
    return ids


def delete_owned(cscli: str, scope: str, value: str, timeout: int, runner: Runner) -> int:
    deleted = 0
    for identifier in owned_decision_ids(cscli, scope, value, timeout, runner):
        result = run_command(runner, [cscli, "decisions", "delete", "--id", str(identifier)], timeout)
        if result.returncode != 0:
            raise BanSyncError(f"cscli decisions delete --id {identifier} exited {result.returncode}")
        deleted += 1
    return deleted


def add_decision(cscli: str, entry: Mapping[str, Any], now_epoch: int, timeout: int, runner: Runner) -> str:
    remaining = int(entry["until_epoch"]) - int(now_epoch)
    reason = sync_reason(str(entry["origin_node"]), str(entry["reason"]))
    flag = "--ip" if entry["scope"] == "Ip" else "--range"
    result = run_command(
        runner,
        [
            cscli, "decisions", "add", flag, str(entry["value"]),
            "--duration", f"{remaining}s", "--reason", reason, "--type", "ban",
        ],
        timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:300]
        raise BanSyncError(f"cscli decisions add exited {result.returncode}: {detail}")
    return reason


def run_agent_sync(
    config: Mapping[str, Any],
    *,
    force: bool = False,
    runner: Runner = subprocess.run,
    opener: Callable[..., Any] | None = None,
    now_epoch: int | None = None,
    interfaces: Sequence[Any] | None = None,
    inventory_cidrs: Sequence[str] | None = None,
    crowdsec_present: bool | None = None,
) -> dict[str, Any]:
    """Pull, mirror and (unless dry-run or CrowdSec is absent) apply.

    Safe to call on every agent run: honours ``apply.interval_minutes`` unless
    ``force``.  Idempotent: the state file records the cursor, the mirror of
    central's view and exactly what this node applied, so a repeated pull with
    no central change issues no cscli command.
    """
    settings = config["ban_sync"]
    apply = settings["apply"]
    if not settings.get("enabled") or not apply.get("enabled"):
        return {"status": "disabled"}
    node_id = str(config["node"]["id"])
    state_path = Path(str(apply["state_file"]))
    state = load_json_file(state_path)
    now = int(now_epoch if now_epoch is not None else time.time())
    last_attempt = int(state.get("last_attempt_epoch", 0) or 0)
    if not force and last_attempt and now - last_attempt < int(apply["interval_minutes"]) * 60:
        return {"status": "not-due"}
    state["schema_version"] = SCHEMA_VERSION
    state["last_attempt_epoch"] = now
    state["last_attempt_at"] = epoch_text(now)
    cscli = str(settings["cscli_path"])
    timeout = int(settings["command_timeout_seconds"])
    if crowdsec_present is None:
        crowdsec_present = Path(cscli).is_file()
    signature_state = dict(state.get("signature") or {})
    key_files = [str(item) for item in apply.get("signing_public_key_files", [])]
    signature_state["required"] = bool(key_files)
    state["signature"] = signature_state
    try:
        pinned = load_pinned_keys(key_files)

        def verifier(payload: Mapping[str, Any], requested: int) -> str:
            return verify_view_signature(
                payload,
                pinned,
                node_id=node_id,
                requested_cursor=requested,
                now_epoch=now,
                last_generated_epoch=int(state.get("last_generated_epoch", 0) or 0),
                max_age_seconds=int(apply.get("max_view_age_seconds", 900)),
                openssl=str(apply.get("openssl_path", "openssl")),
            )

        view = fetch_view(config, int(state.get("cursor", 0) or 0), opener=opener, verifier=verifier)
        mirror, digest_ok = merge_view(state, view)
        if not digest_ok and not view["reset"]:
            view = fetch_view(config, 0, opener=opener, verifier=verifier)
            mirror, digest_ok = merge_view({}, view)
        if not digest_ok:
            raise BanSyncError("snapshot digest mismatch after full resync; nothing applied")
        state.update(
            {
                "set_id": view["set_id"],
                "cursor": view["cursor"],
                "mirror": mirror,
                "last_pull_epoch": now,
                "last_pull_at": epoch_text(now),
                "last_reset": bool(view["reset"]),
                "snapshot_sha256": view["snapshot_sha256"],
                "last_generated_epoch": int(view["generated_epoch"]),
            }
        )
        signature_state["last_status"] = view.get("signature_status")
        signature_state["last_checked_at"] = epoch_text(now)
        protected = local_protection_sets(
            config, interfaces=interfaces, inventory_cidrs=inventory_cidrs, runner=runner
        )
        applied = {key: dict(value) for key, value in (state.get("applied") or {}).items()}
        # Applied entries whose expiry passed were already dropped by CrowdSec.
        for key in [key for key, value in applied.items() if int(value.get("until_epoch", 0)) <= now]:
            applied.pop(key)
        plan = plan_changes(
            mirror,
            applied,
            protected,
            now_epoch=now,
            min_remaining_seconds=int(apply["min_remaining_seconds"]),
            update_tolerance_seconds=int(apply["update_tolerance_seconds"]),
            node_id=node_id,
        )
        dry_run = bool(apply.get("dry_run", True))
        mode = "dry-run" if dry_run else ("crowdsec-absent" if not crowdsec_present else "apply")
        if mode == "apply" and apply.get("check_crowdsec_allowlists", True):
            kept = []
            for entry in plan["adds"]:
                refusal = crowdsec_allowlisted(cscli, entry["value"], timeout, runner)
                if refusal is None:
                    kept.append(entry)
                else:
                    plan["skipped"].append(
                        {"id": entry["id"], "scope": entry["scope"], "value": entry["value"], "reason": refusal}
                    )
            plan["adds"] = kept
        counts = {
            "applied": 0,
            "removed": 0,
            "failed": 0,
            "skipped_protection": len(plan["skipped"]),
            "would_apply": 0,
            "would_remove": 0,
            "desired": plan["desired"],
            "mirror": len(mirror),
        }
        errors: list[str] = []
        if mode != "apply":
            counts["would_apply"] = len(plan["adds"])
            counts["would_remove"] = len(plan["removes"])
        else:
            budget = int(apply["max_changes_per_run"])
            for current in plan["removes"]:
                if budget <= 0:
                    break
                budget -= 1
                try:
                    delete_owned(cscli, current["scope"], current["value"], timeout, runner)
                    applied.pop(current["id"], None)
                    counts["removed"] += 1
                except (BanSyncError, OSError, subprocess.SubprocessError) as exc:
                    counts["failed"] += 1
                    errors.append(str(exc))
            for entry in plan["adds"]:
                if budget <= 0:
                    break
                budget -= 1
                try:
                    if entry.get("replace"):
                        delete_owned(cscli, entry["scope"], entry["value"], timeout, runner)
                    reason = add_decision(cscli, entry, now, timeout, runner)
                except (BanSyncError, OSError, subprocess.SubprocessError) as exc:
                    counts["failed"] += 1
                    errors.append(str(exc))
                    continue
                applied[entry["id"]] = {
                    "scope": entry["scope"],
                    "value": entry["value"],
                    "until_epoch": int(entry["until_epoch"]),
                    "origin_node": entry["origin_node"],
                    "reason_text": reason,
                    "applied_epoch": now,
                }
                counts["applied"] += 1
        preview = int(apply["max_preview_entries"])
        state["applied"] = applied
        state["mode"] = mode
        state["last_status"] = "ok" if not errors else "partial"
        state["last_counts"] = counts
        state["would_apply"] = [] if mode == "apply" else [
            {
                "scope": entry["scope"],
                "value": entry["value"],
                "until": entry["until"],
                "origin_node": entry["origin_node"],
                "crowdsec_reason": sync_reason(entry["origin_node"], entry["reason"]),
            }
            for entry in plan["adds"][:preview]
        ]
        state["would_remove"] = [] if mode == "apply" else [
            {"scope": entry.get("scope"), "value": entry.get("value"), "origin_node": entry.get("origin_node")}
            for entry in plan["removes"][:preview]
        ]
        state["skipped"] = plan["skipped"][:preview]
        if errors:
            state["last_error"] = errors[-1][:500]
        else:
            state.pop("last_error", None)
        result = {"status": state["last_status"], "mode": mode, "cursor": view["cursor"], "reset": view["reset"]} | counts
    except SignatureError as exc:
        # Reject the whole response: no mirror, cursor or CrowdSec change.
        signature_state["last_status"] = f"failed: {exc}"[:300]
        signature_state["failures"] = int(signature_state.get("failures", 0) or 0) + 1
        signature_state["last_failure_at"] = epoch_text(now)
        state["last_status"] = "signature-failed"
        state["last_error"] = f"signature verification failed: {exc}"[:500]
        result = {"status": "signature-failed", "error": str(exc)[:500]}
    except (BanSyncError, OSError, ValueError, subprocess.SubprocessError) as exc:
        state["last_status"] = "error"
        state["last_error"] = str(exc)[:500]
        result = {"status": "error", "error": str(exc)[:500]}
    atomic_write_json(state_path, state, 0o600)
    return result


def agent_status(config: Mapping[str, Any]) -> dict[str, Any]:
    """Compact ban-sync section for ``argent-sentinel-agent status``."""
    settings = config.get("ban_sync") or {}
    apply = settings.get("apply") or {}
    upstream = settings.get("upstream") or {}
    state = load_json_file(Path(str(apply.get("state_file", AGENT_DEFAULTS["apply"]["state_file"]))))
    upstream_state = load_json_file(Path(str(upstream.get("state_file", AGENT_DEFAULTS["upstream"]["state_file"]))))
    counts = state.get("last_counts") or {}
    return {
        "enabled": bool(settings.get("enabled")),
        "dry_run": bool(apply.get("dry_run", True)),
        "interval_minutes": apply.get("interval_minutes"),
        "mode": state.get("mode"),
        "last_pull_at": state.get("last_pull_at"),
        "last_attempt_at": state.get("last_attempt_at"),
        "last_status": state.get("last_status"),
        "last_error": state.get("last_error"),
        "cursor": state.get("cursor"),
        "set_id": state.get("set_id"),
        "mirror_entries": len(state.get("mirror") or {}),
        "applied_entries": len(state.get("applied") or {}),
        "applied": int(counts.get("applied", 0)),
        "removed": int(counts.get("removed", 0)),
        "failed": int(counts.get("failed", 0)),
        "skipped_protection": int(counts.get("skipped_protection", 0)),
        "would_apply": int(counts.get("would_apply", 0)),
        "would_remove": int(counts.get("would_remove", 0)),
        "signature_required": bool(apply.get("signing_public_key_files")),
        "signature_status": (state.get("signature") or {}).get("last_status"),
        "signature_failures": int((state.get("signature") or {}).get("failures", 0) or 0),
        "signature_last_failure_at": (state.get("signature") or {}).get("last_failure_at"),
        "upstream_last_staged_at": upstream_state.get("last_staged_at"),
        "upstream_decisions": upstream_state.get("decisions"),
        "upstream_last_error": upstream_state.get("last_error"),
    }


# EOF: src/ban_sync.py
