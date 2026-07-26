#!/usr/bin/env python3
# Argent Sentinel v0.5.0.5 SSH/config migration regression tests.

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import collector  # noqa: E402


def load_builder():
    path = ROOT / "packaging/build_debs.py"
    spec = importlib.util.spec_from_file_location(
        "argent_sentinel_build_debs_v047",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load packaging/build_debs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class V047Test(unittest.TestCase):
    def test_release_versions_are_consistent(self) -> None:
        self.assertEqual("0.5.0.5", (ROOT / "VERSION").read_text().strip())
        for relative in (
            "src/collector.py",
            "src/agent.py",
            "src/server_api.py",
        ):
            self.assertIn(
                'APP_VERSION = "0.5.0.5"',
                (ROOT / relative).read_text(),
            )
        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('if upstream != "0.5.0.5":', builder)
        self.assertIn('"test_v047.py"', builder)

    def test_agent_emits_canonical_account_key(self) -> None:
        event = agent.parse_sshd_row(
            {
                "MESSAGE": (
                    "Invalid user sentinel-test from "
                    "198.51.100.77 port 42310"
                ),
                "__REALTIME_TIMESTAMP": "1784940000000000",
                "__CURSOR": "s=v047-test",
            },
            node_id="node-a",
            secret=b"x" * 32,
            destination_ip="203.0.113.10",
            destination_port=22,
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertIn("account_key", event)
        self.assertNotIn("account_hash", event)
        self.assertEqual(64, len(event["account_key"]))

    def test_collector_imports_legacy_account_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = collector.StateDB(root / "state.sqlite3")
            try:
                batch_uuid = str(uuid.uuid4())
                event_uuid = str(uuid.uuid4())
                batch = {
                    "schema_version": 1,
                    "batch_uuid": batch_uuid,
                    "created_at": "2026-07-25T02:40:00Z",
                    "source": {
                        "host": "nidhoggur",
                        "site_id": "sshd-nidhoggur",
                        "site_url": "ssh://nidhoggur.example:22/",
                        "service": "sshd",
                        "plugin_version": "0.4.6",
                    },
                }
                event = {
                    "event_uuid": event_uuid,
                    "occurred_epoch": 1784946110,
                    "occurred_at": "2026-07-25T02:21:50Z",
                    "recorded_at": "2026-07-25T02:40:00Z",
                    "event_type": "ssh_auth_failed",
                    "outcome": "denied",
                    "source_ip": "36.64.131.68",
                    "source_port": 40510,
                    "destination_ip": "108.226.59.220",
                    "destination_port": 22,
                    "transport_protocol": "TCP",
                    "application_protocol": "SSH",
                    "account_hash": "legacy-hash-value",
                    "metadata": {
                        "account_class": "invalid",
                        "auth_method": "invalid-user-preauth",
                    },
                }
                db.import_batch(
                    batch,
                    "a" * 64,
                    root / "legacy-sshd.json",
                    [event],
                )
                row = db.conn.execute(
                    "SELECT service, event_type, account_key "
                    "FROM events WHERE event_uuid=?",
                    (event_uuid,),
                ).fetchone()
                self.assertIsNotNone(row)
                assert row is not None
                self.assertEqual("sshd", row["service"])
                self.assertEqual("ssh_auth_failed", row["event_type"])
                self.assertEqual("legacy-hash-value", row["account_key"])
            finally:
                db.close()

    def test_config_migrator_preserves_custom_policy(self) -> None:
        migrator = (
            ROOT / "packaging/bin/argent-sentinel-config-migrate"
        )
        example = ROOT / "config/collector.json.example"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "collector.json"
            backup = root / "backup/collector.json"
            original = {
                "incoming_globs": [
                    "/var/lib/argent-sentinel/drop/wordpress/*/"
                    "incoming/*.json"
                ],
                "abuse_context": {
                    "enabled": True,
                },
                "abuse_reporting": {
                    "enabled": True,
                    "test_mode": True,
                    "recipient_override": "operator@example.org",
                    "max_reports_per_run": 2,
                },
                "policy": {
                    "failure_threshold": 99,
                },
            }
            config.write_text(
                json.dumps(original, indent=2) + "\n",
                encoding="utf-8",
            )
            config.chmod(0o600)

            result = subprocess.run(
                [
                    sys.executable,
                    str(migrator),
                    "--config",
                    str(config),
                    "--example",
                    str(example),
                    "--backup",
                    str(backup),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            updated = json.loads(config.read_text())
            saved = json.loads(backup.read_text())

            self.assertEqual(original, saved)
            self.assertEqual(
                original["abuse_reporting"],
                updated["abuse_reporting"],
            )
            self.assertEqual(original["policy"], updated["policy"])
            self.assertIn(
                "/var/lib/argent-sentinel/drop/remote/*/"
                "events/incoming/*.json",
                updated["incoming_globs"],
            )
            self.assertIn(
                "/var/lib/argent-sentinel/drop/remote/*/"
                "abuse-context/incoming/*.jsonl",
                updated["abuse_context"]["incoming_globs"],
            )
            self.assertIn(
                "/var/lib/argent-sentinel/drop/remote/*/"
                "abuse-context/incoming/*.json",
                updated["abuse_context"]["incoming_globs"],
            )

            second = subprocess.run(
                [
                    sys.executable,
                    str(migrator),
                    "--config",
                    str(config),
                    "--example",
                    str(example),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertEqual(updated, json.loads(config.read_text()))

    def test_common_package_contains_config_migrator(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builder.make_common(root, "0.5.0.5-1")
            self.assertTrue(
                (
                    root
                    / "usr/sbin/argent-sentinel-config-migrate"
                ).is_file()
            )

    def test_server_postinst_runs_backed_up_migration(self) -> None:
        postinst = (ROOT / "packaging/deb/server.postinst").read_text()
        self.assertIn(
            "/usr/sbin/argent-sentinel-config-migrate",
            postinst,
        )
        self.assertIn(
            '--backup "$BACKUP/collector.json.pre-v047"',
            postinst,
        )

    def test_collector_log_uses_generic_batch_wording(self) -> None:
        source = (ROOT / "src/collector.py").read_text()
        self.assertIn(
            "Collector run complete: %d event batch files",
            source,
        )
        self.assertNotIn(
            "Collector run complete: %d WordPress files",
            source,
        )


if __name__ == "__main__":
    unittest.main()
