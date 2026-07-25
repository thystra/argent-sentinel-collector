#!/usr/bin/env python3
"""Provision and update per-site static AWStats reports for Argent Sentinel."""

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
from typing import Any, Iterable, Mapping

APP_VERSION = "0.5.0"

DEFAULTS: dict[str, Any] = {
    "log_globs": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/*access*.log",
        "/var/log/nginx/*.access.log",
        "/var/log/nginx/access.log.*",
        "/var/log/nginx/*access*.log.*",
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
    "max_discovery_bytes_per_file": 16 * 1024 * 1024,
}

HOST_RE = re.compile(r'\bhost="(?P<host>[^"]+)"')
SITE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


class AWStatsError(RuntimeError):
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
        raise AWStatsError(f"Traffic configuration missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AWStatsError(f"Invalid traffic configuration JSON: {exc}") from exc
    if not isinstance(supplied, dict):
        raise AWStatsError("Traffic configuration root must be an object")
    config = deep_merge(DEFAULTS, supplied)
    if not isinstance(config.get("sites"), list):
        raise AWStatsError("sites must be an array")
    return config


def valid_site_id(value: str) -> bool:
    return bool(SITE_ID_RE.fullmatch(value))


def safe_site(site: Mapping[str, Any]) -> dict[str, Any]:
    site_id = str(site.get("id") or "").strip()
    domain = str(site.get("domain") or "").strip().lower()
    if not valid_site_id(site_id):
        raise AWStatsError(f"Invalid AWStats site id: {site_id!r}")
    if not DNS_RE.fullmatch(domain):
        raise AWStatsError(f"Invalid site domain: {domain!r}")
    aliases = []
    for value in site.get("aliases", []):
        alias = str(value).strip().lower()
        if alias and DNS_RE.fullmatch(alias):
            aliases.append(alias)
    return {
        "id": site_id,
        "domain": domain,
        "aliases": sorted(set(aliases)),
        "enabled": bool(site.get("enabled", True)),
    }


def expanded_logs(config: Mapping[str, Any]) -> list[Path]:
    result: set[Path] = set()
    for pattern in config.get("log_globs", []):
        for value in glob.glob(str(pattern)):
            path = Path(value)
            try:
                if path.is_file() and not path.is_symlink():
                    result.add(path.resolve())
            except OSError:
                continue
    return sorted(result, key=str)


def iter_tail_lines(path: Path, max_bytes: int) -> Iterable[str]:
    size = path.stat().st_size
    start = max(0, size - max_bytes)
    with path.open("rb") as handle:
        handle.seek(start)
        if start:
            handle.readline()
        for raw in handle:
            yield raw.decode("utf-8", "replace")


def discover_hosts(config: Mapping[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    max_bytes = int(config["max_discovery_bytes_per_file"])
    for path in expanded_logs(config):
        if path.suffix in {".gz", ".bz2", ".xz"}:
            continue
        try:
            for line in iter_tail_lines(path, max_bytes):
                match = HOST_RE.search(line)
                if not match:
                    continue
                host = match.group("host").split(":", 1)[0].lower()
                if DNS_RE.fullmatch(host):
                    counts[host] = counts.get(host, 0) + 1
        except OSError:
            continue
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def write_missing_sites(
    path: Path,
    config: dict[str, Any],
    discovered: Mapping[str, int],
) -> int:
    existing_domains = {
        str(site.get("domain") or "").strip().lower()
        for site in config.get("sites", [])
        if isinstance(site, Mapping)
    }
    added = 0
    for host in discovered:
        if host in existing_domains or host == "sentinel.argentwolf.org":
            continue
        config["sites"].append(
            {
                "id": host,
                "domain": host,
                "aliases": [],
                "enabled": True,
            }
        )
        existing_domains.add(host)
        added += 1
    if added:
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    return added


def awstats_log_format() -> str:
    return (
        '%host %other %logname %time1 %methodurl %code %bytesd '
        '%refererquot %uaquot '
        'src_ip="%other" src_port="%other" '
        'dst_ip="%other" dst_port="%other" '
        'host="%virtualname" server_name="%other" scheme="%other"'
    )


def log_command(config: Mapping[str, Any], logs: list[Path]) -> str:
    program = Path(str(config["log_merge_program"]))
    if not program.is_file():
        raise AWStatsError(f"AWStats log merge program not found: {program}")
    if not logs:
        raise AWStatsError("No Nginx access logs matched log_globs")
    return " ".join(
        [shlex.quote(str(program))]
        + [shlex.quote(str(path)) for path in logs]
    ) + " |"


def render_site_config(
    config: Mapping[str, Any],
    site: Mapping[str, Any],
    logs: list[Path],
) -> str:
    normalized = safe_site(site)
    site_id = normalized["id"]
    domain = normalized["domain"]
    aliases = " ".join(normalized["aliases"])
    data_dir = Path(str(config["awstats_data_root"])) / site_id
    return (
        f"# Generated by Argent Sentinel {APP_VERSION}\n"
        f'LogFile="{log_command(config, logs)}"\n'
        "LogType=W\n"
        f'LogFormat="{awstats_log_format()}"\n'
        f'SiteDomain="{domain}"\n'
        f'HostAliases="{aliases}"\n'
        f'DirData="{data_dir}"\n'
        'DirCgi="/"\n'
        'DirIcons="/awstats-icon"\n'
        "AllowToUpdateStatsFromBrowser=0\n"
        "DNSLookup=0\n"
        "ShowLinksOnUrl=0\n"
        "KeepBackupOfHistoricFiles=1\n"
        "CreateDirDataIfNotExists=1\n"
        'SkipHosts=""\n'
        'SkipFiles=""\n'
    )


def install_site_configs(
    config: Mapping[str, Any],
    logs: list[Path],
) -> list[dict[str, Any]]:
    config_dir = Path(str(config["awstats_config_dir"]))
    data_root = Path(str(config["awstats_data_root"]))
    static_root = Path(str(config["static_root"]))
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    data_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    static_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    result: list[dict[str, Any]] = []
    for raw_site in config["sites"]:
        if not isinstance(raw_site, Mapping):
            continue
        site = safe_site(raw_site)
        if not site["enabled"]:
            continue
        site_id = site["id"]
        data_dir = data_root / site_id
        output_dir = static_root / site_id
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        destination = config_dir / f"awstats.{site_id}.conf"
        payload = render_site_config(config, site, logs)
        temporary = destination.with_suffix(".conf.tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o640)
        os.replace(temporary, destination)
        result.append(
            {
                "id": site_id,
                "domain": site["domain"],
                "config": str(destination),
                "output_dir": str(output_dir),
            }
        )
    return result


def set_static_group(config: Mapping[str, Any], path: Path) -> None:
    try:
        group_id = grp.getgrnam(str(config["static_group"])).gr_gid
    except KeyError:
        return
    for item in [path, *path.rglob("*")]:
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
    logs = expanded_logs(config)
    sites = install_site_configs(config, logs)
    results: list[dict[str, Any]] = []
    for site in sites:
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
                "id": site_id,
                "domain": site["domain"],
                "update_status": update_code,
                "build_status": build_code,
                "update_output": update_output[-2000:],
                "build_output": build_output[-2000:],
            }
        )
    status = (
        "ok"
        if all(
            item["update_status"] == 0 and item["build_status"] == 0
            for item in results
        )
        else "partial"
    )
    return {
        "status": status,
        "version": APP_VERSION,
        "logs": len(logs),
        "sites": results,
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
    subparsers.add_parser("render")
    subparsers.add_parser("update")
    args = parser.parse_args()
    try:
        path = Path(args.config)
        config = load_config(path)
        if args.command == "discover":
            discovered = discover_hosts(config)
            added = (
                write_missing_sites(path, config, discovered)
                if args.write_missing
                else 0
            )
            result = {
                "status": "ok",
                "version": APP_VERSION,
                "hosts": discovered,
                "added": added,
            }
        elif args.command == "render":
            logs = expanded_logs(config)
            result = {
                "status": "ok",
                "version": APP_VERSION,
                "logs": [str(path) for path in logs],
                "sites": install_site_configs(config, logs),
            }
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
