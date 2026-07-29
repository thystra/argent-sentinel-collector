#!/usr/bin/env python3
"""Build Argent Sentinel binary Debian packages without external Python modules."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAINTAINER = "Argent Sentinel Project <postmaster@argentwolf.org>"
SECTION = "admin"
PRIORITY = "optional"


def run(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def install_file(source: Path, destination: Path, mode: int = 0o644) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, mode)


def write_file(destination: Path, content: str, mode: int = 0o644) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    os.chmod(destination, mode)


def installed_size_kib(root: Path) -> int:
    total = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    return max(1, (total + 1023) // 1024)


def md5sums(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "DEBIAN" in path.parts:
            continue
        digest = hashlib.md5(path.read_bytes()).hexdigest()  # noqa: S324 - Debian file manifest format
        lines.append(f"{digest}  {path.relative_to(root)}")
    return "\n".join(lines) + ("\n" if lines else "")


def normalize_mtimes(root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def control_text(
    package: str,
    version: str,
    description: str,
    *,
    depends: str = "",
    recommends: str = "",
    suggests: str = "",
    provides: str = "",
    installed_size: int,
) -> str:
    fields = [
        f"Package: {package}",
        f"Version: {version}",
        f"Section: {SECTION}",
        f"Priority: {PRIORITY}",
        "Architecture: all",
        f"Maintainer: {MAINTAINER}",
        f"Installed-Size: {installed_size}",
    ]
    for name, value in (
        ("Depends", depends),
        ("Recommends", recommends),
        ("Suggests", suggests),
        ("Provides", provides),
    ):
        if value:
            fields.append(f"{name}: {value}")
    summary, *body = description.strip().splitlines()
    fields.append(f"Description: {summary}")
    for line in body:
        fields.append(f" {line}" if line else " .")
    return "\n".join(fields) + "\n"


def add_doc(root: Path, package: str, source: Path, name: str | None = None) -> None:
    install_file(source, root / "usr/share/doc" / package / (name or source.name))


def make_common(root: Path, version: str) -> dict[str, str]:
    for source, target in (
        ("collector.py", "collector.py"),
        ("report_batcher.py", "report_batcher.py"),
        ("reporting_view.py", "reporting_view.py"),
        ("review_queue.py", "review_queue.py"),
        ("review_processor.py", "review_processor.py"),
        ("wordpress_sites.py", "wordpress_sites.py"),
        ("agent.py", "agent.py"),
        ("server_api.py", "server_api.py"),
        ("fail2ban_export.py", "fail2ban_export.py"),
        ("review_digest.py", "review_digest.py"),
        ("nginx_429_export.py", "nginx_429_export.py"),
        ("dashboard.py", "dashboard.py"),
        ("dashboard_snapshot.py", "dashboard_snapshot.py"),
        ("awstats_manager.py", "awstats_manager.py"),
    ):
        install_file(ROOT / "src" / source, root / "usr/lib/argent-sentinel" / target, 0o755)
    for source, target in (
        ("argent-sentinel", "usr/bin/argent-sentinel"),
        (
            "argent-sentinel-report-batch",
            "usr/sbin/argent-sentinel-report-batch",
        ),
        (
            "argent-sentinel-wordpress-sites",
            "usr/sbin/argent-sentinel-wordpress-sites",
        ),
        ("argent-sentinel-agent", "usr/bin/argent-sentinel-agent"),
        ("argent-sentinel-api", "usr/sbin/argent-sentinel-api"),
        ("argent-sentinel-fail2ban-export", "usr/sbin/argent-sentinel-fail2ban-export"),
        ("argent-sentinel-review-digest", "usr/sbin/argent-sentinel-review-digest"),
        ("argent-sentinel-nginx-429-export", "usr/sbin/argent-sentinel-nginx-429-export"),
        ("argent-sentinel-dashboard", "usr/sbin/argent-sentinel-dashboard"),
        ("argent-sentinel-dashboard-snapshot", "usr/sbin/argent-sentinel-dashboard-snapshot"),
        ("argent-sentinel-review-processor", "usr/sbin/argent-sentinel-review-processor"),
        ("argent-sentinel-awstats", "usr/sbin/argent-sentinel-awstats"),
        (
            "argent-sentinel-config-migrate",
            "usr/sbin/argent-sentinel-config-migrate",
        ),
    ):
        install_file(ROOT / "packaging/bin" / source, root / target, 0o755)
    for name in ("collector.json.example", "agent.json.example", "server-api.json.example", "node.json.example", "nginx-sentinel.conf.example", "dashboard.json.example", "dashboard-snapshot.json.example", "review-processor.json.example", "traffic-sites.json.example", "nginx-site-access-log-format.conf.example", "nginx-crawler-map.conf.example", "nginx-crawler-enforcement.conf.example", "nginx-sentinel-dashboard.conf.example"):
        install_file(ROOT / "config" / name, root / "usr/share/argent-sentinel" / name)
    install_file(ROOT / "VERSION", root / "usr/share/argent-sentinel/VERSION")
    docs = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "ARCHITECTURE.md", ROOT / "TODO.md", ROOT / "AGENTS.md", ROOT / "AGENTS-PROFILE.md", ROOT / "docs-abuse-context.md", ROOT / "docs/debian-packaging.md"]
    docs.extend(sorted((ROOT / "docs").glob("*.md")))
    for source in docs:
        add_doc(root, "argent-sentinel-common", source)
    return {
        "description": "Argent Sentinel shared engines and command-line interfaces\nContains the collector, remote node agent, central ingestion API, schema\nmigrations, reporting logic, configuration examples, and documentation.",
        "depends": "python3 (>= 3.10), ca-certificates",
        "suggests": "sqlite3",
        "provides": "argent-sentinel-collector-common",
    }


def make_agent(root: Path, version: str) -> dict[str, str]:
    for source_name, target_name in (
        ("create-wordpress-drop.sh", "argent-sentinel-create-wordpress-drop"),
        ("onboard-wordpress-site.sh", "argent-sentinel-onboard-wordpress"),
        ("stage-abuse-context-log.sh", "argent-sentinel-stage-abuse-context"),
        ("configure-agent.sh", "argent-sentinel-configure-agent"),
        ("create-node-csr.sh", "argent-sentinel-create-node-csr"),
    ):
        install_file(ROOT / "scripts" / source_name, root / "usr/sbin" / target_name, 0o755)
    install_file(ROOT / "packaging/systemd/argent-sentinel-agent.service", root / "usr/lib/systemd/system/argent-sentinel-agent.service")
    install_file(ROOT / "packaging/systemd/argent-sentinel-agent.timer", root / "usr/lib/systemd/system/argent-sentinel-agent.timer")
    add_doc(root, "argent-sentinel-agent", ROOT / "docs/debian-packaging.md")
    return {
        "description": "Argent Sentinel authenticated remote node agent\nStages WordPress and Nginx events, captures privacy-preserving OpenSSH failures,\nand delivers idempotent mTLS batches to sentinel.argentwolf.org.",
        "depends": f"argent-sentinel-common (= {version}), adduser, openssl, systemd | systemd-sysv",
        "suggests": "wp-cli",
        "provides": "argent-sentinel-client",
    }


def make_server(root: Path, version: str) -> dict[str, str]:
    install_file(ROOT / "packaging/bin/argent-sentinel-status", root / "usr/sbin/argent-sentinel-status", 0o755)
    for unit in (
        "argent-sentinel-collector.service",
        "argent-sentinel-collector.timer",
        "argent-sentinel-report-batch.service",
        "argent-sentinel-report-batch.timer",
        "argent-sentinel-api.service",
        "argent-sentinel-nginx-logrotate.service",
        "argent-sentinel-nginx-logrotate.timer",
        "argent-sentinel-fail2ban-export.service",
        "argent-sentinel-fail2ban-export.timer",
        "argent-sentinel-review-digest.service",
        "argent-sentinel-review-digest.timer",
        "argent-sentinel-nginx-429-export.service",
        "argent-sentinel-nginx-429-export.timer",
        "argent-sentinel-dashboard.service",
        "argent-sentinel-dashboard-snapshot.service",
        "argent-sentinel-dashboard-snapshot.timer",
        "argent-sentinel-review-processor.service",
        "argent-sentinel-review-processor.path",
        "argent-sentinel-awstats.service",
        "argent-sentinel-awstats.timer",
    ):
        install_file(
            ROOT / "packaging/systemd" / unit,
            root / "usr/lib/systemd/system" / unit,
        )
    install_file(
        ROOT / "packaging/logrotate/argent-sentinel-nginx",
        root / "usr/share/argent-sentinel/argent-sentinel-nginx.logrotate",
    )
    for source_name, target_name in (
        ("init-sentinel-ca.sh", "argent-sentinel-init-ca"),
        ("sign-node-csr.sh", "argent-sentinel-sign-node-csr"),
        ("cutover-legacy-reporting.sh", "argent-sentinel-cutover-reporting"),
        ("setup-dashboard.sh", "argent-sentinel-dashboard-setup"),
        ("install-nginx-crawler-policy.sh", "argent-sentinel-install-crawler-policy"),
        ("install-nginx-site-log-format.sh", "argent-sentinel-install-site-log-format"),
    ):
        install_file(ROOT / "scripts" / source_name, root / "usr/sbin" / target_name, 0o755)
    add_doc(root, "argent-sentinel-server", ROOT / "docs/debian-packaging.md")
    return {
        "description": "Argent Sentinel central ingestion and policy server\nRuns the mTLS ingestion API and scheduled collector, correlates WordPress,\nNginx, and OpenSSH incidents, manages CrowdSec decisions, and sends reports.",
        "depends": f"argent-sentinel-common (= {version}), argent-sentinel-agent (= {version}), init-system-helpers (>= 1.18~), systemd | systemd-sysv, adduser, acl, openssl, logrotate",
        "recommends": "nginx, awstats, crowdsec, sqlite3, default-mta | mail-transport-agent",
        "provides": "argent-sentinel-collector",
    }


def make_meta(root: Path, version: str) -> dict[str, str]:
    write_file(
        root / "usr/share/doc/argent-sentinel/README.Debian",
        "Install this metapackage on a combined Argent Sentinel agent/server host.\n",
    )
    return {
        "description": "Argent Sentinel combined agent and server installation\nMetapackage for a host that receives local events and runs the central policy engine.",
        "depends": f"argent-sentinel-agent (= {version}), argent-sentinel-server (= {version})",
    }


PACKAGE_BUILDERS = {
    "argent-sentinel-common": make_common,
    "argent-sentinel-agent": make_agent,
    "argent-sentinel-server": make_server,
    "argent-sentinel": make_meta,
}

MAINTAINER_SCRIPTS = {
    "argent-sentinel-agent": {
        "preinst": ROOT / "packaging/deb/agent.preinst",
        "postinst": ROOT / "packaging/deb/agent.postinst",
        "prerm": ROOT / "packaging/deb/agent.prerm",
        "postrm": ROOT / "packaging/deb/agent.postrm",
    },
    "argent-sentinel-server": {
        "preinst": ROOT / "packaging/deb/server.preinst",
        "postinst": ROOT / "packaging/deb/server.postinst",
        "prerm": ROOT / "packaging/deb/server.prerm",
        "postrm": ROOT / "packaging/deb/server.postrm",
    },
}


def source_date_epoch() -> int:
    supplied = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if supplied:
        return int(supplied)
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct"], cwd=ROOT, check=True, text=True, capture_output=True
        )
        if result.stdout.strip():
            return int(result.stdout.strip())
    except (OSError, subprocess.CalledProcessError, ValueError):
        pass
    return int((ROOT / "VERSION").stat().st_mtime)


def build_package(package: str, full_version: str, output_dir: Path, work_dir: Path, epoch: int) -> Path:
    root = work_dir / package
    root.mkdir(parents=True)
    metadata = PACKAGE_BUILDERS[package](root, full_version)
    debian = root / "DEBIAN"
    debian.mkdir(mode=0o755)
    for name, source in MAINTAINER_SCRIPTS.get(package, {}).items():
        content = source.read_text(encoding="utf-8").replace("@PACKAGE_VERSION@", full_version)
        write_file(debian / name, content, 0o755)
    write_file(debian / "md5sums", md5sums(root))
    control = control_text(
        package,
        full_version,
        metadata.pop("description"),
        installed_size=installed_size_kib(root),
        **metadata,
    )
    write_file(debian / "control", control)
    normalize_mtimes(root, epoch)
    destination = output_dir / f"{package}_{full_version}_all.deb"
    run("dpkg-deb", "--build", "--root-owner-group", str(root), str(destination))
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=str(ROOT / "dist/deb"))
    parser.add_argument("--revision", default=os.environ.get("DEB_REVISION", "1"))
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    if shutil.which("dpkg-deb") is None:
        parser.error("dpkg-deb is required (install dpkg-dev/build-essential)")
    upstream = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if upstream != "0.5.2.1":
        parser.error(f"VERSION must be 0.5.2.1, found {upstream!r}")
    if not args.revision.isdigit() or int(args.revision) < 1:
        parser.error("--revision must be a positive integer")
    full_version = f"{upstream}-{args.revision}"
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_tests:
        for source in ("collector.py", "report_batcher.py", "reporting_view.py", "review_queue.py", "review_processor.py", "wordpress_sites.py", "agent.py", "server_api.py", "fail2ban_export.py", "review_digest.py", "nginx_429_export.py", "dashboard.py", "dashboard_snapshot.py", "awstats_manager.py"):
            run(sys.executable, "-m", "py_compile", str(ROOT / "src" / source))
        for test in ("test_collector.py", "test_reporting_guardrails.py", "test_network_context.py", "test_v040.py", "test_v041.py", "test_v042.py", "test_v043.py", "test_v044.py", "test_v045.py", "test_v046.py", "test_v047.py", "test_v048.py", "test_v049.py", "test_v0410.py", "test_v050.py", "test_v0501.py", "test_v0503.py", "test_v0504.py", "test_v0505.py", "test_v0510.py", "test_v0511.py", "test_v0511_revision2.py", "test_v0520.py", "test_v0521.py", "test_packaging.py"):
            run(sys.executable, str(ROOT / "tests" / test), cwd=ROOT)
        for script in sorted((ROOT / "scripts").glob("*.sh")):
            run("bash", "-n", str(script))
        for script in sorted((ROOT / "packaging/deb").glob("*")):
            if script.is_file():
                run("sh", "-n", str(script))

    epoch = source_date_epoch()
    os.environ["SOURCE_DATE_EPOCH"] = str(epoch)
    with tempfile.TemporaryDirectory(prefix="argent-sentinel-deb-") as temporary:
        work_dir = Path(temporary)
        packages = [build_package(name, full_version, output_dir, work_dir, epoch) for name in PACKAGE_BUILDERS]

    checksums = []
    for package in packages:
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {package.name}")
        run("dpkg-deb", "--info", str(package))
    write_file(output_dir / "SHA256SUMS", "\n".join(checksums) + "\n")
    print("\nBuilt:")
    for package in packages:
        print(package)
    print(output_dir / "SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
