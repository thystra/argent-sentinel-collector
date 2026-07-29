#!/usr/bin/env python3
"""Provision and update normalized per-site AWStats reports."""

from __future__ import annotations

import argparse
import glob
import grp
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence

APP_VERSION = "0.5.1.1"

DEFAULTS: dict[str, Any] = {
    "log_globs": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/*access*.log",
        "/var/log/nginx/*.access.log",
        "/var/log/nginx/access.log.*",
        "/var/log/nginx/*access*.log.*",
        "/var/log/nginx/*.access.log.*",
    ],
    "sites": [],
    "awstats_config_dir": "/etc/awstats",
    "awstats_data_root": "/var/lib/awstats",
    "static_root": "/var/lib/argent-sentinel/dashboard/awstats",
    "static_group": "www-data",
    "awstats_program": "/usr/lib/cgi-bin/awstats.pl",
    "build_static_program": (
        "/usr/share/awstats/tools/awstats_buildstaticpages.pl"
    ),
    "log_merge_program": (
        "/usr/share/awstats/tools/logresolvemerge.pl"
    ),
    "manager_program": "/usr/sbin/argent-sentinel-awstats",
    "nginx_program": "/usr/sbin/nginx",
    "max_discovery_bytes_per_file": 16 * 1024 * 1024,
    "max_inspect_lines": 1000,
}

HOST_RE = re.compile(r'\bhost="(?P<host>[^"]+)"')
SITE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
ACCESS_RE = re.compile(
    r'^(?P<remote>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referer>(?:[^"\\]|\\.)*)"\s+'
    r'"(?P<user_agent>(?:[^"\\]|\\.)*)"'
    r'(?P<extra>.*)$'
)
SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);")


class AWStatsError(RuntimeError):
    pass


def deep_merge(
    base: Mapping[str, Any],
    override: Mapping[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in base.items():
        result[key] = (
            deep_merge(value, {})
            if isinstance(value, Mapping)
            else value
        )
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def canonical_domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if normalized.startswith("www.") and DNS_RE.fullmatch(normalized[4:]):
        return normalized[4:]
    return normalized


def valid_site_id(value: str) -> bool:
    return bool(SITE_ID_RE.fullmatch(value))


def safe_site(site: Mapping[str, Any]) -> dict[str, Any]:
    domain = canonical_domain(str(site.get("domain") or ""))
    site_id = str(site.get("id") or domain).strip()
    if not valid_site_id(site_id):
        raise AWStatsError(f"Invalid AWStats site id: {site_id!r}")
    if not DNS_RE.fullmatch(domain):
        raise AWStatsError(f"Invalid site domain: {domain!r}")

    aliases: set[str] = set()
    supplied_domain = str(site.get("domain") or "").strip().lower().rstrip(".")
    if supplied_domain and supplied_domain != domain:
        aliases.add(supplied_domain)
    for value in site.get("aliases", []):
        alias = str(value).strip().lower().rstrip(".")
        if alias and DNS_RE.fullmatch(alias) and alias != domain:
            aliases.add(alias)

    log_globs = sorted(
        {
            str(value).strip()
            for value in site.get("log_globs", [])
            if str(value).strip()
        }
    )
    return {
        "id": site_id,
        "domain": domain,
        "aliases": sorted(aliases),
        "enabled": bool(site.get("enabled", True)),
        "log_globs": log_globs,
    }


def normalize_sites(raw_sites: Sequence[Any]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for raw in raw_sites:
        if not isinstance(raw, Mapping):
            continue
        site = safe_site(raw)
        key = site["domain"]
        current = merged.setdefault(
            key,
            {
                "id": key,
                "domain": key,
                "aliases": set(),
                "enabled": False,
                "log_globs": set(),
            },
        )
        current["enabled"] = current["enabled"] or site["enabled"]
        current["aliases"].update(site["aliases"])
        if site["id"] != key and DNS_RE.fullmatch(site["id"]):
            current["aliases"].add(site["id"])
        current["log_globs"].update(site["log_globs"])
    result = []
    for key in sorted(merged):
        item = merged[key]
        result.append(
            {
                "id": item["id"],
                "domain": item["domain"],
                "aliases": sorted(item["aliases"] - {item["domain"]}),
                "enabled": bool(item["enabled"]),
                "log_globs": sorted(item["log_globs"]),
            }
        )
    return result


def load_config(path: Path) -> dict[str, Any]:
    try:
        supplied = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AWStatsError(f"Traffic configuration missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AWStatsError(
            f"Invalid traffic configuration JSON: {exc}"
        ) from exc
    if not isinstance(supplied, dict):
        raise AWStatsError("Traffic configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    if not isinstance(config.get("sites"), list):
        raise AWStatsError("sites must be an array")
    config["sites"] = normalize_sites(config["sites"])
    config["_config_path"] = str(path.resolve())
    return config


def expand_patterns(patterns: Iterable[str]) -> list[Path]:
    result: set[Path] = set()
    for pattern in patterns:
        for value in glob.glob(str(pattern)):
            path = Path(value)
            try:
                if path.is_file() and not path.is_symlink():
                    result.add(path.resolve())
            except OSError:
                continue
    return sorted(result, key=str)


def expanded_logs(config: Mapping[str, Any]) -> list[Path]:
    return expand_patterns(
        str(pattern) for pattern in config.get("log_globs", [])
    )


def iter_tail_lines(path: Path, max_bytes: int) -> Iterable[str]:
    size = path.stat().st_size
    start = max(0, size - max_bytes)
    with path.open("rb") as handle:
        handle.seek(start)
        if start:
            handle.readline()
        for raw in handle:
            yield raw.decode("utf-8", "replace")


def configured_server_names(config: Mapping[str, Any]) -> set[str]:
    nginx = Path(str(config.get("nginx_program") or ""))
    if not nginx.is_file():
        return set()
    try:
        result = subprocess.run(
            [str(nginx), "-T"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    names: set[str] = set()
    for match in SERVER_NAME_RE.finditer(result.stdout):
        for token in match.group(1).split():
            name = token.strip().lower().rstrip(".")
            if (
                name
                and "*" not in name
                and "$" not in name
                and name not in {"_", "localhost"}
                and DNS_RE.fullmatch(name)
            ):
                names.add(name)
    return names


def line_host(line: str) -> str | None:
    match = HOST_RE.search(line)
    if not match:
        return None
    host = match.group("host").split(":", 1)[0].lower().rstrip(".")
    return host if DNS_RE.fullmatch(host) else None


def discover_inventory(
    config: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    allowed = configured_server_names(config)
    inventory: dict[str, dict[str, Any]] = {}
    max_bytes = int(config["max_discovery_bytes_per_file"])
    for path in expanded_logs(config):
        if path.suffix in {".gz", ".bz2", ".xz"}:
            continue
        try:
            for line in iter_tail_lines(path, max_bytes):
                host = line_host(line)
                if not host:
                    continue
                if allowed and host not in allowed:
                    continue
                if host == "sentinel.argentwolf.org":
                    continue
                entry = inventory.setdefault(
                    host,
                    {"requests": 0, "logs": set()},
                )
                entry["requests"] += 1
                entry["logs"].add(str(path))
        except OSError:
            continue
    return inventory


def proposed_sites(
    inventory: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for host, data in inventory.items():
        domain = canonical_domain(host)
        entry = grouped.setdefault(
            domain,
            {
                "id": domain,
                "domain": domain,
                "aliases": set(),
                "enabled": True,
                "log_globs": set(),
                "requests": 0,
            },
        )
        if host != domain:
            entry["aliases"].add(host)
        entry["requests"] += int(data.get("requests", 0))
        for path in data.get("logs", set()):
            entry["log_globs"].add(str(path))
            entry["log_globs"].add(str(path) + ".*")
    result: list[dict[str, Any]] = []
    for domain in sorted(
        grouped,
        key=lambda value: (
            -int(grouped[value]["requests"]),
            value,
        ),
    ):
        entry = grouped[domain]
        result.append(
            {
                "id": entry["id"],
                "domain": entry["domain"],
                "aliases": sorted(entry["aliases"]),
                "enabled": True,
                "log_globs": sorted(entry["log_globs"]),
            }
        )
    return result


def write_config(path: Path, config: Mapping[str, Any]) -> None:
    payload = {
        key: value
        for key, value in config.items()
        if not str(key).startswith("_")
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)


def write_missing_sites(
    path: Path,
    config: dict[str, Any],
    proposals: Sequence[Mapping[str, Any]],
) -> int:
    sites = normalize_sites(config.get("sites", []))
    by_domain = {site["domain"]: site for site in sites}
    added = 0
    for proposal in proposals:
        site = safe_site(proposal)
        current = by_domain.get(site["domain"])
        if current is None:
            sites.append(site)
            by_domain[site["domain"]] = site
            added += 1
            continue
        current["aliases"] = sorted(
            set(current["aliases"]) | set(site["aliases"])
        )
        current["log_globs"] = sorted(
            set(current["log_globs"]) | set(site["log_globs"])
        )
    config["sites"] = normalize_sites(sites)
    if added:
        write_config(path, config)
    return added


def write_proposed_config(
    destination: Path,
    config: Mapping[str, Any],
    proposals: Sequence[Mapping[str, Any]],
) -> None:
    proposed = {
        key: value
        for key, value in config.items()
        if not str(key).startswith("_") and key != "sites"
    }
    proposed["sites"] = normalize_sites(list(proposals))
    write_config(destination, proposed)


def site_names(site: Mapping[str, Any]) -> set[str]:
    normalized = safe_site(site)
    return {
        normalized["domain"],
        *normalized["aliases"],
    }


def filename_tokens(site: Mapping[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for name in site_names(site):
        canonical = canonical_domain(name)
        tokens.add(name)
        tokens.add(canonical)
        tokens.add(canonical.split(".", 1)[0])
    return {
        token.replace("*", "").lower()
        for token in tokens
        if len(token) >= 4
    }


def filename_matches(path: Path, site: Mapping[str, Any]) -> bool:
    name = path.name.lower()
    if name in {"access.log", "default.access.log", "catchall.access.log"}:
        return False
    return any(token in name for token in filename_tokens(site))


def log_contains_site(
    path: Path,
    site: Mapping[str, Any],
    max_bytes: int,
) -> bool:
    if path.suffix in {".gz", ".bz2", ".xz"}:
        return False
    names = site_names(site)
    try:
        return any(
            (host := line_host(line)) is not None and host in names
            for line in iter_tail_lines(path, max_bytes)
        )
    except OSError:
        return False


def resolve_site_sources(
    config: Mapping[str, Any],
    site: Mapping[str, Any],
) -> list[dict[str, Any]]:
    normalized = safe_site(site)
    all_logs = expanded_logs(config)
    explicit_patterns = normalized["log_globs"]
    explicit_logs = (
        expand_patterns(explicit_patterns)
        if explicit_patterns
        else []
    )
    candidates = explicit_logs or all_logs
    max_bytes = int(config["max_discovery_bytes_per_file"])
    result: dict[Path, bool] = {}

    named_candidates = [
        path for path in candidates if filename_matches(path, normalized)
    ]
    # Prefer site-specific filenames. This preserves hostless legacy rotations
    # and avoids mixing them with shared logs where host filtering is required.
    if named_candidates:
        candidates = named_candidates

    for path in candidates:
        named = filename_matches(path, normalized)
        host_match = log_contains_site(path, normalized, max_bytes)
        if named:
            result[path] = False
        elif host_match:
            result[path] = True
        elif explicit_patterns:
            # An explicitly configured generic/shared file is safe only when
            # it supplies an extended host field for this site.
            continue

    return [
        {
            "path": path,
            "require_host": require_host,
        }
        for path, require_host in sorted(
            result.items(),
            key=lambda item: str(item[0]),
        )
    ]


def parse_access_line(line: str) -> dict[str, str] | None:
    match = ACCESS_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    result = match.groupdict()
    result["virtual_host"] = line_host(line) or ""
    return result


def canonical_combined(record: Mapping[str, str]) -> str:
    byte_count = record.get("bytes") or "0"
    if byte_count == "-":
        byte_count = "0"
    return (
        f'{record["remote"]} {record["ident"]} {record["user"]} '
        f'[{record["time"]}] "{record["request"]}" '
        f'{record["status"]} {byte_count} '
        f'"{record["referer"]}" "{record["user_agent"]}"'
    )


def merged_lines(
    config: Mapping[str, Any],
    paths: Sequence[Path],
) -> Iterable[str]:
    merge_program = Path(str(config["log_merge_program"]))
    if not merge_program.is_file():
        raise AWStatsError(
            f"AWStats log merge program not found: {merge_program}"
        )
    process = subprocess.Popen(
        [str(merge_program), *[str(path) for path in paths]],
        text=True,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    )
    assert process.stdout is not None
    try:
        yield from process.stdout
    finally:
        process.stdout.close()
        return_code = process.wait()
        if return_code != 0:
            raise AWStatsError(
                f"logresolvemerge exited with status {return_code}"
            )


def stream_site(
    config: Mapping[str, Any],
    site: Mapping[str, Any],
) -> dict[str, int]:
    normalized = safe_site(site)
    sources = resolve_site_sources(config, normalized)
    if not sources:
        raise AWStatsError(
            f"No unambiguous Nginx logs found for {normalized['domain']}"
        )
    requirements = {
        Path(item["path"]): bool(item["require_host"])
        for item in sources
    }
    names = site_names(normalized)
    accepted = 0
    malformed = 0
    wrong_host = 0

    # logresolvemerge does not expose which source file produced each line.
    # Hostless records are therefore accepted only when every selected source
    # is site-specific. Shared sources require the extended host field.
    require_host_for_hostless = any(requirements.values())
    for line in merged_lines(config, list(requirements)):
        record = parse_access_line(line)
        if record is None:
            malformed += 1
            continue
        host = record.get("virtual_host") or ""
        if host:
            if host not in names:
                wrong_host += 1
                continue
        elif require_host_for_hostless:
            wrong_host += 1
            continue
        print(canonical_combined(record))
        accepted += 1
    return {
        "accepted": accepted,
        "malformed": malformed,
        "wrong_host": wrong_host,
        "sources": len(sources),
    }


def site_by_id(
    config: Mapping[str, Any],
    site_id: str,
) -> dict[str, Any]:
    for site in config["sites"]:
        normalized = safe_site(site)
        if normalized["id"] == site_id:
            return normalized
    raise AWStatsError(f"Unknown AWStats site id: {site_id}")


def log_command(
    config: Mapping[str, Any],
    site_id: str,
) -> str:
    manager = Path(str(config["manager_program"]))
    config_path = Path(str(config["_config_path"]))
    return " ".join(
        [
            shlex.quote(str(manager)),
            "--config",
            shlex.quote(str(config_path)),
            "stream",
            "--site",
            shlex.quote(site_id),
        ]
    ) + " |"


def render_site_config(
    config: Mapping[str, Any],
    site: Mapping[str, Any],
) -> str:
    normalized = safe_site(site)
    site_id = normalized["id"]
    domain = normalized["domain"]
    aliases = " ".join(normalized["aliases"])
    data_dir = Path(str(config["awstats_data_root"])) / site_id
    return (
        f"# Generated by Argent Sentinel {APP_VERSION}\n"
        f'LogFile="{log_command(config, site_id)}"\n'
        "LogType=W\n"
        "LogFormat=1\n"
        f'SiteDomain="{domain}"\n'
        f'HostAliases="{aliases}"\n'
        f'DirData="{data_dir}"\n'
        'DirCgi="/"\n'
        'DirIcons="/awstats-icon"\n'
        "AllowToUpdateStatsFromBrowser=0\n"
        "DNSLookup=0\n"
        "ShowLinksOnUrl=0\n"
        "# Explicit report sections are required by awstats_buildstaticpages.pl.\n"
        "ShowSummary=UVPHB\n"
        "ShowMonthStats=UVPHB\n"
        "ShowDaysOfMonthStats=VPHB\n"
        "ShowDaysOfWeekStats=PHB\n"
        "ShowHoursStats=PHB\n"
        "ShowDomainsStats=PHB\n"
        "ShowHostsStats=PHBL\n"
        "ShowRobotsStats=HBL\n"
        "ShowSessionsStats=1\n"
        "ShowPagesStats=PBEX\n"
        "ShowFileTypesStats=HB\n"
        "ShowOSStats=1\n"
        "ShowBrowsersStats=1\n"
        "ShowOriginStats=PH\n"
        "ShowKeyphrasesStats=1\n"
        "ShowKeywordsStats=1\n"
        "ShowMiscStats=a\n"
        "ShowHTTPErrorsStats=1\n"
        'ShowFlagLinks=""\n'
        "KeepBackupOfHistoricFiles=1\n"
        "CreateDirDataIfNotExists=1\n"
        'SkipHosts=""\n'
        'SkipFiles=""\n'
    )


def install_site_configs(
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    config_dir = Path(str(config["awstats_config_dir"]))
    data_root = Path(str(config["awstats_data_root"]))
    static_root = Path(str(config["static_root"]))
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    data_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    static_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    set_static_group(config, static_root, recursive=False)
    result: list[dict[str, Any]] = []
    for raw_site in config["sites"]:
        site = safe_site(raw_site)
        if not site["enabled"]:
            continue
        sources = resolve_site_sources(config, site)
        if not sources:
            result.append(
                {
                    "id": site["id"],
                    "domain": site["domain"],
                    "status": "skipped",
                    "reason": "no unambiguous matching logs",
                    "logs": [],
                }
            )
            continue
        site_id = site["id"]
        data_dir = data_root / site_id
        output_dir = static_root / site_id
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        set_static_group(config, output_dir, recursive=False)
        destination = config_dir / f"awstats.{site_id}.conf"
        temporary = destination.with_suffix(".conf.tmp")
        temporary.write_text(
            render_site_config(config, site),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o640)
        os.replace(temporary, destination)
        result.append(
            {
                "id": site_id,
                "domain": site["domain"],
                "status": "ready",
                "config": str(destination),
                "output_dir": str(output_dir),
                "logs": [
                    {
                        "path": str(item["path"]),
                        "require_host": bool(item["require_host"]),
                    }
                    for item in sources
                ],
            }
        )
    return result


def set_static_group(
    config: Mapping[str, Any],
    path: Path,
    *,
    recursive: bool = True,
) -> None:
    try:
        group_id = grp.getgrnam(str(config["static_group"])).gr_gid
    except KeyError:
        return
    items = [path, *path.rglob("*")] if recursive else [path]
    for item in items:
        try:
            os.chown(item, -1, group_id)
            if item.is_dir():
                os.chmod(item, 0o750)
            elif item.is_file():
                os.chmod(item, 0o640)
        except OSError:
            continue


def run_command(arguments: list[str]) -> tuple[int, str]:
    result = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=3600,
    )
    return result.returncode, result.stdout


def update(config: Mapping[str, Any]) -> dict[str, Any]:
    awstats = Path(str(config["awstats_program"]))
    builder = Path(str(config["build_static_program"]))
    if not awstats.is_file() or not builder.is_file():
        return {
            "status": "unavailable",
            "reason": "Install the awstats package",
            "version": APP_VERSION,
        }
    sites = install_site_configs(config)
    results: list[dict[str, Any]] = []
    for site in sites:
        if site["status"] == "skipped":
            results.append(site)
            continue
        site_id = site["id"]
        update_code, update_output = run_command(
            [
                str(awstats),
                f"-config={site_id}",
                f"-configdir={config['awstats_config_dir']}",
                "-update",
            ]
        )
        build_code = -1
        build_output = ""
        if update_code == 0:
            build_code, build_output = run_command(
                [
                    str(builder),
                    f"-config={site_id}",
                    f"-configdir={config['awstats_config_dir']}",
                    f"-dir={site['output_dir']}",
                    f"-awstatsprog={awstats}",
                    "-staticlinks",
                ]
            )
        output_dir = Path(site["output_dir"])
        set_static_group(config, output_dir)
        results.append(
            {
                **site,
                "status": (
                    "ok"
                    if update_code == 0 and build_code == 0
                    else "failed"
                ),
                "update_status": update_code,
                "build_status": build_code,
                "update_output": update_output[-2000:],
                "build_output": build_output[-2000:],
            }
        )
    status = (
        "ok"
        if all(item["status"] in {"ok", "skipped"} for item in results)
        else "partial"
    )
    return {
        "status": status,
        "version": APP_VERSION,
        "sites": results,
    }


def inspect(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": APP_VERSION,
        "sites": install_site_configs(config),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="/etc/argent-sentinel/traffic-sites.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover")
    discover_parser.add_argument("--write-missing", action="store_true")
    discover_parser.add_argument("--write-proposed")

    subparsers.add_parser("render")
    subparsers.add_parser("inspect")
    subparsers.add_parser("update")

    stream_parser = subparsers.add_parser("stream")
    stream_parser.add_argument("--site", required=True)

    args = parser.parse_args()
    try:
        path = Path(args.config)
        config = load_config(path)
        if args.command == "stream":
            site = site_by_id(config, args.site)
            summary = stream_site(config, site)
            print(
                json.dumps(summary, sort_keys=True),
                file=sys.stderr,
            )
            return 0

        if args.command == "discover":
            inventory = discover_inventory(config)
            proposals = proposed_sites(inventory)
            added = (
                write_missing_sites(path, config, proposals)
                if args.write_missing
                else 0
            )
            if args.write_proposed:
                write_proposed_config(
                    Path(args.write_proposed),
                    config,
                    proposals,
                )
            result = {
                "status": "ok",
                "version": APP_VERSION,
                "hosts": {
                    host: {
                        "requests": int(data["requests"]),
                        "logs": sorted(data["logs"]),
                    }
                    for host, data in inventory.items()
                },
                "proposed_sites": proposals,
                "added": added,
                "proposed_path": args.write_proposed,
            }
        elif args.command == "render":
            result = {
                "status": "ok",
                "version": APP_VERSION,
                "sites": install_site_configs(config),
            }
        elif args.command == "inspect":
            result = inspect(config)
        else:
            result = update(config)
    except (
        AWStatsError,
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"ok", "unavailable"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
