#!/usr/bin/env python3
# /home/alan/src/argent-sentinel-collector/src/watchdogs/unbound.py
"""Unbound health, evidence capture, and bounded remediation watchdog."""

from __future__ import annotations

from pathlib import Path
import shutil
import tarfile
import time
from typing import Any, Mapping

from watchdog_runtime import (
    command_ok,
    local_text,
    run_command,
    utc_text,
    write_command_capture,
)


def validate(config: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(config.get("mode", "")) not in {"observe", "remediate"}:
        errors.append("mode must be observe or remediate")
    if int(config.get("interval_seconds", 0)) < 60:
        errors.append("interval_seconds must be at least 60")
    if int(config.get("dig_timeout_seconds", 0)) < 1:
        errors.append("dig_timeout_seconds must be positive")
    if config.get("enabled"):
        dig_command = Path(str(config.get("dig_command", "/usr/bin/dig")))
        if not dig_command.is_file():
            errors.append(f"dig command does not exist: {dig_command}")
    return errors


def _probe(config: Mapping[str, Any]) -> dict[str, Any]:
    return run_command(
        [
            str(config.get("dig_command", "/usr/bin/dig")),
            f"@{config.get('test_server', '127.0.0.1')}",
            str(config.get("test_domain", "google.com")),
            f"+time={int(config.get('dig_timeout_seconds', 5))}",
            "+tries=1",
        ],
        timeout=int(config.get("dig_timeout_seconds", 5)) + 3,
    )


def _prepare_incident(
    context: Mapping[str, Any],
    config: Mapping[str, Any],
    failed_probe: Mapping[str, Any],
) -> tuple[Path, Path]:
    incident_root = Path(str(context["incident_dir"])) / "unbound"
    stamp = time.strftime("%Y%m%dT%H%M%S%z")
    work = incident_root / stamp
    work.mkdir(parents=True, exist_ok=False, mode=0o700)
    (work / "incident.txt").write_text(
        "\n".join(
            [
                "===== ARGENT SENTINEL UNBOUND INCIDENT =====",
                f"Host: {context['hostname']}",
                f"Local time: {local_text()}",
                f"UTC time: {utc_text()}",
                "Initial DNS probe: FAILED",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (work / "incident.txt").chmod(0o600)
    write_command_capture(work / "failed-probe.txt", "failed DNS probe", failed_probe)

    commands = [
        ("hostname", ["/usr/bin/hostnamectl"], 15),
        ("uptime", ["/usr/bin/uptime"], 10),
        ("memory", ["/usr/bin/free", "-h"], 10),
        ("vmstat", ["/usr/bin/vmstat", "1", "5"], 15),
        ("processes", ["/usr/bin/ps", "-ef"], 10),
        ("service", ["/usr/bin/systemctl", "status", str(config.get("service", "unbound.service")), "--no-pager", "--full"], 20),
        ("journal", ["/usr/bin/journalctl", "-u", str(config.get("service", "unbound.service")), "-n", "300", "--no-pager"], 20),
        ("sockets", ["/usr/bin/ss", "-lntup"], 15),
        ("socket-summary", ["/usr/bin/ss", "-s"], 15),
        ("unbound-status", ["/usr/sbin/unbound-control", "status"], 15),
        ("unbound-stats", ["/usr/sbin/unbound-control", "stats_noreset"], 20),
        ("addresses", ["/usr/sbin/ip", "addr"], 15),
        ("routes", ["/usr/sbin/ip", "route"], 15),
        ("resolv-conf", ["/usr/bin/cat", "/etc/resolv.conf"], 10),
        ("kernel-journal", ["/usr/bin/journalctl", "-k", "-n", "300", "--no-pager"], 20),
    ]
    for name, args, timeout in commands:
        write_command_capture(work / f"{name}.txt", name, run_command(args, timeout=timeout))

    pid_result = run_command(["/usr/bin/pidof", "unbound"], timeout=10)
    pid = str(pid_result.get("stdout", "")).strip().split(" ")[0]
    if pid:
        write_command_capture(
            work / "threads.txt",
            "Unbound threads",
            run_command(["/usr/bin/ps", "-T", "-p", pid], timeout=15),
        )
        write_command_capture(
            work / "limits.txt",
            "Unbound process limits",
            run_command(["/usr/bin/cat", f"/proc/{pid}/limits"], timeout=10),
        )
        lsof = shutil.which("lsof")
        if lsof:
            write_command_capture(
                work / "open-files.txt",
                "Unbound open files",
                run_command([lsof, "-p", pid], timeout=20),
            )
        gdb = shutil.which("gdb")
        if gdb:
            write_command_capture(
                work / "gdb-backtrace.txt",
                "gdb thread backtraces",
                run_command(
                    [
                        gdb,
                        "-batch",
                        "-ex",
                        "set pagination off",
                        "-ex",
                        "thread apply all bt full",
                        "-p",
                        pid,
                    ],
                    timeout=30,
                ),
            )

    archive = incident_root / f"unbound-watchdog-{stamp}.tar.gz"
    return work, archive


def _finish_incident(
    work: Path,
    archive: Path,
    restart: Mapping[str, Any],
    recovered: Mapping[str, Any],
    success: bool,
) -> None:
    write_command_capture(work / "restart.txt", "systemd restart", restart)
    write_command_capture(work / "recovery-probe.txt", "recovery DNS probe", recovered)
    with (work / "incident.txt").open("a", encoding="utf-8") as handle:
        handle.write(f"Recovery status: {'SUCCESSFUL' if success else 'FAILED'}\n")
        handle.write(f"Completed UTC: {utc_text()}\n")
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(work, arcname=work.name)
    archive.chmod(0o600)
    shutil.rmtree(work)


def check(
    context: Mapping[str, Any],
    config: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> dict[str, Any]:
    del previous
    started = time.monotonic()
    probe = _probe(config)
    if command_ok(probe):
        return {
            "status": "healthy",
            "severity": "info",
            "summary": "Unbound DNS health check succeeded",
            "metrics": {"probe_duration_ms": probe["duration_ms"]},
            "details": {
                "test_domain": config.get("test_domain"),
                "test_server": config.get("test_server"),
            },
            "public_details": {
                "test_domain": config.get("test_domain"),
                "test_server": config.get("test_server"),
            },
            "duration_ms": round((time.monotonic() - started) * 1000),
        }

    if str(config.get("mode", "observe")) != "remediate":
        return {
            "status": "critical",
            "severity": "critical",
            "summary": "Unbound DNS health check failed; observe-only mode did not restart it",
            "metrics": {"probe_duration_ms": probe["duration_ms"]},
            "details": {"probe_stderr": str(probe.get("stderr", ""))[-2000:]},
            "public_details": {
                "test_domain": config.get("test_domain"),
                "test_server": config.get("test_server"),
            },
            "notify_admin": True,
            "notify_emergency": True,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }

    work, archive = _prepare_incident(context, config, probe)
    restart = run_command(
        ["/usr/bin/systemctl", "restart", str(config.get("service", "unbound.service"))],
        timeout=int(config.get("restart_timeout_seconds", 60)),
    )
    time.sleep(max(0, int(config.get("recovery_delay_seconds", 5))))
    recovered = _probe(config)
    success = command_ok(restart) and command_ok(recovered)
    _finish_incident(work, archive, restart, recovered, success)
    summary = (
        "Unbound failed its DNS probe and recovered after an automatic restart"
        if success
        else "Unbound failed its DNS probe and automatic recovery did not restore service"
    )
    return {
        "status": "healthy" if success else "critical",
        "severity": "recovered" if success else "critical",
        "summary": summary,
        "metrics": {
            "probe_duration_ms": probe["duration_ms"],
            "recovery_probe_duration_ms": recovered["duration_ms"],
            "restart_returncode": restart.get("returncode"),
        },
        "details": {
            "incident_archive": str(archive),
            "restart_timed_out": bool(restart.get("timed_out")),
            "restart_stderr": str(restart.get("stderr", ""))[-2000:],
            "recovery_probe_stderr": str(recovered.get("stderr", ""))[-2000:],
        },
        "public_details": {
            "incident_archive": str(archive),
            "recovery_successful": success,
        },
        "event": "automatic-recovery",
        "notify_admin": True,
        "notify_emergency": not success,
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


# EOF: /home/alan/src/argent-sentinel-collector/src/watchdogs/unbound.py
