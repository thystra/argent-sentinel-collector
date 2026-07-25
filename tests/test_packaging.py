#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackagingTest(unittest.TestCase):
    def test_release_version_is_consistent(self) -> None:
        self.assertEqual("0.4.10", (ROOT / "VERSION").read_text().strip())
        source = (ROOT / "src/collector.py").read_text()
        self.assertIn('APP_VERSION = "0.4.10"', source)
        self.assertIn("Argent-Sentinel/{APP_VERSION}", source)

    def test_packaging_assets_exist(self) -> None:
        required = [
            "packaging/build_debs.py",
            "packaging/bin/argent-sentinel",
            "packaging/bin/argent-sentinel-status",
            "packaging/bin/argent-sentinel-agent",
            "packaging/bin/argent-sentinel-api",
            "packaging/bin/argent-sentinel-config-migrate",
            "packaging/systemd/argent-sentinel-agent.service",
            "packaging/systemd/argent-sentinel-agent.timer",
            "packaging/systemd/argent-sentinel-api.service",
            "packaging/systemd/argent-sentinel-collector.service",
            "packaging/systemd/argent-sentinel-collector.timer",
            "packaging/systemd/argent-sentinel-nginx-logrotate.service",
            "packaging/systemd/argent-sentinel-nginx-logrotate.timer",
            "packaging/logrotate/argent-sentinel-nginx",
            "packaging/deb/agent.preinst",
            "packaging/deb/agent.postinst",
            "packaging/deb/agent.prerm",
            "packaging/deb/agent.postrm",
            "packaging/deb/server.preinst",
            "packaging/deb/server.postinst",
            "packaging/deb/server.prerm",
            "packaging/deb/server.postrm",
        ]
        for name in required:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_packaged_service_uses_package_cli(self) -> None:
        service = (ROOT / "packaging/systemd/argent-sentinel-collector.service").read_text()
        self.assertIn("ExecStartPre=/usr/bin/argent-sentinel", service)
        self.assertIn("ExecStart=/usr/bin/argent-sentinel", service)
        self.assertNotIn("/usr/local/", service)

    def test_server_postinst_preserves_existing_config(self) -> None:
        script = (ROOT / "packaging/deb/server.postinst").read_text()
        self.assertIn('if [ ! -e "$CONFIG" ]', script)
        self.assertIn("Preserved existing", script)
        self.assertIn("migrate --backup-dir", script)
        self.assertIn("@PACKAGE_VERSION@", script)

    def test_migrate_command_creates_consistent_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            config = json.loads((ROOT / "config/collector.json.example").read_text())
            config["state_db"] = str(temp_path / "state.sqlite3")
            config["lock_file"] = str(temp_path / "collector.lock")
            config["incoming_globs"] = [str(temp_path / "incoming/*.json")]
            config["processing_dir"] = str(temp_path / "processing")
            config["archive_dir"] = str(temp_path / "archive")
            config["rejected_dir"] = str(temp_path / "rejected")
            config["abuse_context"]["enabled"] = False
            config["crowdsec"]["enabled"] = False
            config["abuse_reporting"]["enabled"] = False
            path = temp_path / "collector.json"
            path.write_text(json.dumps(config))
            first = subprocess.run(
                [str(ROOT / "src/collector.py"), "--config", str(path), "migrate"],
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertEqual(5, json.loads(first.stdout)["schema_version"])
            backup_dir = temp_path / "backup"
            second = subprocess.run(
                [str(ROOT / "src/collector.py"), "--config", str(path), "migrate", "--backup-dir", str(backup_dir)],
                check=True,
                text=True,
                capture_output=True,
            )
            payload = json.loads(second.stdout)
            self.assertTrue(Path(payload["backup"]).is_file())


if __name__ == "__main__":
    unittest.main()
