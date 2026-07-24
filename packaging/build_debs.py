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
    install_file(ROOT / "src/collector.py", root / "usr/lib/argent-sentinel/collector.py", 0o755)
    install_file(ROOT / "packaging/bin/argent-sentinel", root / "usr/bin/argent-sentinel", 0o755)
    install_file(ROOT / "config/collector.json.example", root / "usr/share/argent-sentinel/collector.json.example")
    install_file(ROOT / "VERSION", root / "usr/share/argent-sentinel/VERSION")
    for source in (ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "docs-abuse-context.md", ROOT / "docs/debian-packaging.md"):
        add_doc(root, "argent-sentinel-common", source)
    return {
        "description": "Argent Sentinel shared collector engine and command-line interface\nContains the Python policy engine, database migrations, reporting logic,\nconfiguration example, and shared documentation.",
        "depends": "python3 (>= 3.10), ca-certificates",
        "suggests": "sqlite3",
        "provides": "argent-sentinel-collector-common",
    }


def make_agent(root: Path, version: str) -> dict[str, str]:
    for source_name, target_name in (
        ("create-wordpress-drop.sh", "argent-sentinel-create-wordpress-drop"),
        ("onboard-wordpress-site.sh", "argent-sentinel-onboard-wordpress"),
        ("stage-abuse-context-log.sh", "argent-sentinel-stage-abuse-context"),
    ):
        install_file(ROOT / "scripts" / source_name, root / "usr/sbin" / target_name, 0o755)
    add_doc(root, "argent-sentinel-agent", ROOT / "docs/debian-packaging.md")
    return {
        "description": "Argent Sentinel local event submission and onboarding helpers\nCreates protected WordPress and Nginx spools and provides site onboarding tools.\nRemote HTTPS delivery is intentionally deferred to the v0.4 transport release.",
        "depends": f"argent-sentinel-common (= {version}), adduser, sudo",
        "suggests": "wp-cli",
        "provides": "argent-sentinel-client",
    }


def make_server(root: Path, version: str) -> dict[str, str]:
    install_file(ROOT / "packaging/bin/argent-sentinel-status", root / "usr/sbin/argent-sentinel-status", 0o755)
    install_file(ROOT / "packaging/systemd/argent-sentinel-collector.service", root / "usr/lib/systemd/system/argent-sentinel-collector.service")
    install_file(ROOT / "packaging/systemd/argent-sentinel-collector.timer", root / "usr/lib/systemd/system/argent-sentinel-collector.timer")
    add_doc(root, "argent-sentinel-server", ROOT / "docs/debian-packaging.md")
    return {
        "description": "Argent Sentinel central collector service and policy engine\nRuns the scheduled central collector, correlates incidents, manages CrowdSec\ndecisions, enriches sources, and sends guarded abuse reports.",
        "depends": f"argent-sentinel-common (= {version}), argent-sentinel-agent (= {version}), init-system-helpers (>= 1.18~), systemd | systemd-sysv",
        "recommends": "crowdsec, sqlite3, default-mta | mail-transport-agent",
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
    "argent-sentinel-agent": {"postinst": ROOT / "packaging/deb/agent.postinst"},
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
    if upstream != "0.3.1":
        parser.error(f"VERSION must be 0.3.1, found {upstream!r}")
    if not args.revision.isdigit() or int(args.revision) < 1:
        parser.error("--revision must be a positive integer")
    full_version = f"{upstream}-{args.revision}"
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_tests:
        run(sys.executable, "-m", "py_compile", str(ROOT / "src/collector.py"))
        for test in ("test_collector.py", "test_reporting_guardrails.py", "test_network_context.py", "test_packaging.py"):
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
