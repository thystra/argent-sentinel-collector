#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/local_protection.py
# Installed: /usr/lib/argent-sentinel/local_protection.py
"""Discover and configure dynamic local-address enforcement protection.

The module is intentionally independent from the collector database. Remote
agents use it to describe the addresses that must never be targeted by
Sentinel-managed enforcement. The central collector treats the authenticated
inventory as an additional safety boundary, not as a trust exemption.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

APP_VERSION = "0.5.5.0"
UTC = dt.timezone.utc
PUBLIC_IPV6 = ipaddress.ip_network("2000::/3")
UNIQUE_LOCAL_IPV6 = ipaddress.ip_network("fc00::/7")
MODES = ("host", "lan-prefix", "manual", "off")
MIN_DYNAMIC_IPV4_PREFIX_LENGTH = 24
MIN_DYNAMIC_IPV6_PREFIX_LENGTH = 48
EXCLUDED_INTERFACE_RE = re.compile(
    r"^(?:lo|docker\d*|br-|veth|virbr|tun\d*|tap\d*|wg\d*|tailscale\d*|"
    r"zt\w*|cni\d*|flannel\d*|podman\d*|lxc\w*|lxd\w*|dummy\d*|"
    r"sit\d*|ip6tnl\d*|gre\d*|gretap\d*|vxlan\d*)",
    re.IGNORECASE,
)


class ProtectionError(RuntimeError):
    pass


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_text(value: dt.datetime | None = None) -> str:
    current = (value or utc_now()).astimezone(UTC).replace(microsecond=0)
    return current.isoformat().replace("+00:00", "Z")


def normalize_cidrs(values: Sequence[Any], *, limit: int = 256) -> list[str]:
    result: list[str] = []
    for value in values:
        try:
            network = str(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError as exc:
            raise ProtectionError(f"Invalid protected CIDR {value!r}") from exc
        if network not in result:
            result.append(network)
        if len(result) > limit:
            raise ProtectionError(f"Protected CIDR count exceeds {limit}")
    return result


def normalize_inventory_cidrs(
    values: Sequence[Any],
    *,
    limit: int = 256,
) -> list[str]:
    result = normalize_cidrs(values, limit=limit)
    for value in result:
        network = ipaddress.ip_network(value, strict=False)
        minimum = (
            MIN_DYNAMIC_IPV4_PREFIX_LENGTH
            if network.version == 4
            else MIN_DYNAMIC_IPV6_PREFIX_LENGTH
        )
        if network.prefixlen < minimum:
            raise ProtectionError(
                f"Dynamic protected CIDR {network} is broader than /{minimum}"
            )
    return result


def interface_is_excluded(name: str) -> bool:
    return not name or EXCLUDED_INTERFACE_RE.match(name) is not None


def _command_json(
    command: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    try:
        result = runner(
            list(command),
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProtectionError(f"Unable to execute {' '.join(command)}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ProtectionError(
            detail or f"{' '.join(command)} exited {result.returncode}"
        )
    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ProtectionError(f"Invalid JSON from {' '.join(command)}: {exc}") from exc
    if not isinstance(payload, list):
        raise ProtectionError(f"Unexpected JSON root from {' '.join(command)}")
    return [dict(item) for item in payload if isinstance(item, Mapping)]


def detect_virtualization(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    try:
        result = runner(
            ["systemd-detect-virt"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"type": "unknown", "is_virtual": None}
    value = (result.stdout or "").strip().lower()
    if result.returncode == 0 and value and value != "none":
        return {"type": value, "is_virtual": True}
    if value == "none" or result.returncode == 1:
        return {"type": "none", "is_virtual": False}
    return {"type": value or "unknown", "is_virtual": None}


def _flagged(info: Mapping[str, Any], name: str) -> bool:
    if bool(info.get(name)):
        return True
    flags = info.get("flags", [])
    return isinstance(flags, list) and name.lower() in {
        str(value).lower() for value in flags
    }


def parse_default_routes(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for row in rows:
        interface = str(row.get("dev") or "").strip()
        if not interface:
            continue
        routes.append(
            {
                "interface": interface,
                "gateway": str(row.get("gateway") or "").strip() or None,
                "protocol": str(row.get("protocol") or row.get("proto") or "").strip() or None,
                "metric": row.get("metric"),
                "preference": row.get("pref"),
            }
        )
    return routes


def parse_ipv6_addresses(
    rows: Sequence[Mapping[str, Any]],
    *,
    default_interfaces: Sequence[str],
    configured_interfaces: Sequence[str] = (),
    include_unique_local: bool = False,
) -> list[dict[str, Any]]:
    configured = {str(value).strip() for value in configured_interfaces if str(value).strip()}
    defaults = {str(value).strip() for value in default_interfaces if str(value).strip()}
    result: list[dict[str, Any]] = []
    for interface_row in rows:
        interface = str(interface_row.get("ifname") or "").strip()
        if not interface:
            continue
        explicitly_selected = bool(configured) and interface in configured
        if configured and not explicitly_selected:
            continue
        if not configured and defaults and interface not in defaults:
            continue
        if not explicitly_selected and interface_is_excluded(interface):
            continue
        entries = interface_row.get("addr_info", [])
        if not isinstance(entries, list):
            continue
        for raw in entries:
            if not isinstance(raw, Mapping) or str(raw.get("family")) != "inet6":
                continue
            address_text = str(raw.get("local") or raw.get("address") or "").strip()
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            if not isinstance(address, ipaddress.IPv6Address):
                continue
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                continue
            address_class = "public" if address in PUBLIC_IPV6 else (
                "unique-local" if address in UNIQUE_LOCAL_IPV6 else "other"
            )
            if address_class == "other":
                continue
            if address_class == "unique-local" and not include_unique_local:
                continue
            if any(_flagged(raw, flag) for flag in ("tentative", "dadfailed", "deprecated")):
                continue
            try:
                prefix_length = int(raw.get("prefixlen", 128))
            except (TypeError, ValueError):
                continue
            if not 1 <= prefix_length <= 128:
                continue
            result.append(
                {
                    "interface": interface,
                    "address": str(address),
                    "prefix_length": prefix_length,
                    "network": str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False)),
                    "address_class": address_class,
                    "scope": str(raw.get("scope") or "global"),
                    "dynamic": _flagged(raw, "dynamic"),
                    "temporary": _flagged(raw, "temporary") or _flagged(raw, "mngtmpaddr"),
                    "valid_life_time": raw.get("valid_life_time"),
                    "preferred_life_time": raw.get("preferred_life_time"),
                }
            )
    return sorted(result, key=lambda item: (item["interface"], item["address"]))


def recommend_mode(
    addresses: Sequence[Mapping[str, Any]],
    routes: Sequence[Mapping[str, Any]],
    virtualization: Mapping[str, Any],
) -> dict[str, Any]:
    public = [item for item in addresses if item.get("address_class") == "public"]
    interfaces = sorted({str(item.get("interface")) for item in public if item.get("interface")})
    prefixes = sorted({str(item.get("network")) for item in public if item.get("network")})
    route_protocols = {
        str(item.get("protocol") or "").lower() for item in routes
    }
    has_ra_signal = "ra" in route_protocols or any(bool(item.get("dynamic")) for item in public)
    prefixes_are_safely_bounded = all(
        int(item.get("prefix_length", 128)) >= MIN_DYNAMIC_IPV6_PREFIX_LENGTH
        for item in public
    )
    if virtualization.get("is_virtual") is True:
        return {
            "mode": "host",
            "reason": (
                f"Virtualization type {virtualization.get('type')} was detected. "
                "A provider-visible /64 does not prove control of the whole prefix."
            ),
            "interfaces": interfaces,
            "prefixes": prefixes,
        }
    if (
        public
        and virtualization.get("is_virtual") is False
        and has_ra_signal
        and prefixes_are_safely_bounded
    ):
        return {
            "mode": "lan-prefix",
            "reason": (
                "The system appears to be a physical host using router-advertised "
                "or dynamically assigned public IPv6 on a local network. Choose "
                "LAN-prefix mode only when you own or control the displayed prefix."
            ),
            "interfaces": interfaces,
            "prefixes": prefixes,
        }
    if public:
        reason = (
            "A connected prefix broader than /48 cannot be published as dynamic "
            "LAN protection, so individual host /128 protection is recommended."
            if not prefixes_are_safely_bounded
            else (
                "The environment is not confidently classifiable as an operator-owned "
                "LAN, so individual host /128 protection is the conservative choice."
            )
        )
        return {
            "mode": "host",
            "reason": reason,
            "interfaces": interfaces,
            "prefixes": prefixes,
        }
    return {
        "mode": "host",
        "reason": (
            "No qualifying public IPv6 address was found. Host mode remains the safe "
            "default and will begin protecting /128 addresses when they appear."
        ),
        "interfaces": interfaces,
        "prefixes": prefixes,
    }


def discover(
    *,
    configured_interfaces: Sequence[str] = (),
    include_unique_local: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    address_rows = _command_json(["ip", "-j", "-6", "address", "show"], runner=runner)
    route_rows = _command_json(["ip", "-j", "-6", "route", "show", "default"], runner=runner)
    routes = parse_default_routes(route_rows)
    default_interfaces = sorted({str(item["interface"]) for item in routes})
    addresses = parse_ipv6_addresses(
        address_rows,
        default_interfaces=default_interfaces,
        configured_interfaces=configured_interfaces,
        include_unique_local=include_unique_local,
    )
    virtualization = detect_virtualization(runner=runner)
    recommendation = recommend_mode(addresses, routes, virtualization)
    return {
        "generated_at": utc_text(),
        "virtualization": virtualization,
        "default_routes": routes,
        "default_route_interfaces": default_interfaces,
        "addresses": addresses,
        "recommendation": recommendation,
    }


def validate_local_config(value: Mapping[str, Any]) -> None:
    mode = str(value.get("mode", "host"))
    if mode not in MODES:
        raise ProtectionError(f"local_address_protection.mode must be one of {', '.join(MODES)}")
    if not isinstance(value.get("enabled", True), bool):
        raise ProtectionError("local_address_protection.enabled must be boolean")
    if not isinstance(value.get("operator_confirmed", False), bool):
        raise ProtectionError("local_address_protection.operator_confirmed must be boolean")
    interfaces = value.get("interfaces", [])
    if not isinstance(interfaces, list):
        raise ProtectionError("local_address_protection.interfaces must be a list")
    if len(interfaces) > 128:
        raise ProtectionError("local_address_protection.interfaces exceeds 128 entries")
    for interface in interfaces:
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", str(interface)):
            raise ProtectionError(f"Invalid interface name {interface!r}")
    if not isinstance(value.get("include_unique_local", False), bool):
        raise ProtectionError("local_address_protection.include_unique_local must be boolean")
    manual = value.get("manual_cidrs", [])
    if not isinstance(manual, list):
        raise ProtectionError("local_address_protection.manual_cidrs must be a list")
    normalize_inventory_cidrs(manual)
    heartbeat = int(value.get("inventory_heartbeat_seconds", 3600))
    if heartbeat < 60:
        raise ProtectionError("local_address_protection.inventory_heartbeat_seconds must be at least 60")
    if mode == "manual" and value.get("enabled", True) and not manual:
        raise ProtectionError("manual mode requires at least one manual CIDR")


def build_inventory(
    config: Mapping[str, Any],
    *,
    discovery: Mapping[str, Any] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    local = config.get("local_address_protection", {})
    if not isinstance(local, Mapping):
        raise ProtectionError("local_address_protection must be an object")
    validate_local_config(local)
    enabled = bool(local.get("enabled", True))
    mode = str(local.get("mode", "host"))
    confirmed = bool(local.get("operator_confirmed", False))
    interfaces = [str(value) for value in local.get("interfaces", [])]
    include_unique_local = bool(local.get("include_unique_local", False))
    current = dict(discovery or discover(
        configured_interfaces=interfaces,
        include_unique_local=include_unique_local,
    ))
    addresses = [dict(value) for value in current.get("addresses", []) if isinstance(value, Mapping)]
    effective: list[str]
    status = "active"
    effective_mode = mode
    if not enabled or mode == "off":
        effective = []
        status = "disabled"
    elif mode == "manual":
        effective = normalize_inventory_cidrs(local.get("manual_cidrs", []))
    elif mode == "host":
        effective = normalize_inventory_cidrs([f"{item['address']}/128" for item in addresses])
    else:
        if confirmed:
            candidate_networks = [
                str(item["network"])
                for item in addresses
                if int(item.get("prefix_length", 128))
                >= MIN_DYNAMIC_IPV6_PREFIX_LENGTH
            ]
            if len(candidate_networks) == len(addresses):
                effective = normalize_inventory_cidrs(candidate_networks)
            else:
                effective = normalize_inventory_cidrs(
                    [f"{item['address']}/128" for item in addresses]
                )
                effective_mode = "host"
                status = "unsafe-prefix-fallback"
        else:
            # Never silently broaden protection beyond the individual host.
            effective = normalize_inventory_cidrs([f"{item['address']}/128" for item in addresses])
            effective_mode = "host"
            status = "confirmation-required"
    if enabled and mode in {"host", "lan-prefix"} and not addresses:
        status = "waiting-for-public-ipv6"
    node = config.get("node", {})
    node_id = str(node.get("id", "")).strip()
    if not node_id:
        raise ProtectionError("node.id is required for protection inventory")
    current_time = now or utc_now()
    return {
        "schema_version": 1,
        "inventory_uuid": str(uuid.uuid4()),
        "generated_at": utc_text(current_time),
        "node_id": node_id,
        "enabled": enabled,
        "configured_mode": mode,
        "effective_mode": effective_mode,
        "operator_confirmed": confirmed,
        "selection_source": str(local.get("selection_source", "configuration")),
        "status": status,
        "configured_interfaces": interfaces,
        "effective_cidrs": effective,
        "addresses": addresses,
        "default_route_interfaces": list(current.get("default_route_interfaces", [])),
        "virtualization": dict(current.get("virtualization", {})),
        "recommendation": dict(current.get("recommendation", {})),
    }


def discovery_summary(value: Mapping[str, Any]) -> str:
    addresses = value.get("addresses", [])
    lines: list[str] = []
    for item in addresses if isinstance(addresses, list) else []:
        if not isinstance(item, Mapping):
            continue
        lines.append(
            f"{item.get('interface')}: {item.get('address')}/{item.get('prefix_length')} "
            f"({item.get('address_class')})"
        )
    virtualization = value.get("virtualization", {})
    recommendation = value.get("recommendation", {})
    prefix = ", ".join(str(item) for item in recommendation.get("prefixes", [])) or "none"
    return "\n".join(
        [
            f"Virtualization: {virtualization.get('type', 'unknown')}",
            "Detected IPv6 addresses:",
            *(f"  {line}" for line in lines),
            f"Candidate prefixes: {prefix}",
            f"Recommendation: {recommendation.get('mode', 'host')}",
            str(recommendation.get("reason", "")),
        ]
    )


def atomic_write_json(path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    existing = path.stat() if path.exists() else None
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", dir=path.parent, mode="w", encoding="utf-8", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode if existing is None else existing.st_mode & 0o777)
    if existing is not None and os.geteuid() == 0:
        os.chown(temporary, existing.st_uid, existing.st_gid)
    os.replace(temporary, path)


def apply_config(
    path: Path,
    *,
    mode: str,
    interfaces: Sequence[str],
    manual_cidrs: Sequence[str],
    selection_source: str,
    operator_confirmed: bool,
) -> dict[str, Any]:
    if mode not in MODES:
        raise ProtectionError(f"Unsupported protection mode {mode!r}")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProtectionError(f"Agent configuration not found: {path}") from exc
    if not isinstance(config, dict):
        raise ProtectionError("Agent configuration root must be an object")
    local = config.setdefault("local_address_protection", {})
    if not isinstance(local, dict):
        raise ProtectionError("local_address_protection must be an object")
    local.update(
        {
            "enabled": mode != "off",
            "mode": mode,
            "interfaces": sorted({value.strip() for value in interfaces if value.strip()}),
            "manual_cidrs": normalize_inventory_cidrs(manual_cidrs),
            "include_unique_local": bool(local.get("include_unique_local", False)),
            "selection_source": selection_source,
            "operator_confirmed": operator_confirmed,
            "inventory_state_file": str(
                local.get(
                    "inventory_state_file",
                    "/var/lib/argent-sentinel/agent/protection-inventory-state.json",
                )
            ),
            "inventory_heartbeat_seconds": int(local.get("inventory_heartbeat_seconds", 3600)),
        }
    )
    validate_local_config(local)
    atomic_write_json(path, config, 0o600)
    return local


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argent Sentinel local-address protection")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    discover_parser = sub.add_parser("discover")
    discover_parser.add_argument("--interface", action="append", default=[])
    discover_parser.add_argument("--include-unique-local", action="store_true")
    inventory_parser = sub.add_parser("inventory")
    inventory_parser.add_argument("--config", default="/etc/argent-sentinel/agent.json")
    apply_parser = sub.add_parser("apply-config")
    apply_parser.add_argument("--config", default="/etc/argent-sentinel/agent.json")
    apply_parser.add_argument("--mode", choices=MODES, required=True)
    apply_parser.add_argument("--interfaces", default="")
    apply_parser.add_argument("--manual-cidrs", default="")
    apply_parser.add_argument("--selection-source", default="command-line")
    apply_parser.add_argument("--operator-confirmed", choices=("true", "false"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            payload = discover(
                configured_interfaces=args.interface,
                include_unique_local=args.include_unique_local,
            )
        elif args.command == "inventory":
            config = json.loads(Path(args.config).read_text(encoding="utf-8"))
            payload = build_inventory(config)
        else:
            payload = apply_config(
                Path(args.config),
                mode=args.mode,
                interfaces=[item for item in args.interfaces.split(",") if item.strip()],
                manual_cidrs=[item for item in re.split(r"[\s,]+", args.manual_cidrs) if item],
                selection_source=args.selection_source,
                operator_confirmed=args.operator_confirmed == "true",
            )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (ProtectionError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# EOF: /home/alan/src/argent-sentinel-collector/src/local_protection.py
