#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/tests/test_v0511_revision2.py
"""Debian revision-2 regression coverage for Argent Sentinel 0.5.1.1."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATOR = ROOT / "packaging/bin/argent-sentinel-config-migrate"
POSTINST = ROOT / "packaging/deb/server.postinst"


class V0511Revision2Test(unittest.TestCase):
    def run_migrator(self, *args: str) -> dict[str, object]:
        result = subprocess.run(
            [sys.executable, str(MIGRATOR), *args],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        return json.loads(result.stdout)

    def test_preserved_collector_gets_reporting_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "collector.json"
            example_path = root / "collector.example.json"
            backup_path = root / "backup/collector.json"
            config_path.write_text(
                json.dumps(
                    {
                        "incoming_globs": [],
                        "abuse_context": {"incoming_globs": []},
                        "report_batching": {
                            "enabled": True,
                            "ban_only": {"asns": [32934]},
                        },
                    }
                ),
                encoding="utf-8",
            )
            example_path.write_text(
                json.dumps(
                    {
                        "incoming_globs": [],
                        "abuse_context": {"incoming_globs": []},
                        "report_batching": {
                            "enabled": False,
                            "state_file": "/var/lib/argent-sentinel/collector/report-batch-state.json",
                            "grouping": {
                                "minimum_ipv4_prefix_length": 24,
                                "minimum_ipv6_prefix_length": 48,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_migrator(
                "--config",
                str(config_path),
                "--example",
                str(example_path),
                "--backup",
                str(backup_path),
            )
            self.assertEqual("updated", result["status"])
            migrated = json.loads(config_path.read_text(encoding="utf-8"))
            batching = migrated["report_batching"]
            self.assertTrue(batching["enabled"])
            self.assertEqual([32934], batching["ban_only"]["asns"])
            self.assertEqual(
                "/var/lib/argent-sentinel/collector/report-batch-state.json",
                batching["state_file"],
            )
            self.assertEqual(
                {
                    "minimum_ipv4_prefix_length": 24,
                    "minimum_ipv6_prefix_length": 48,
                },
                batching["grouping"],
            )
            self.assertTrue(backup_path.is_file())

    def test_top_level_only_preserves_operator_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "snapshot.json"
            example_path = root / "snapshot.example.json"
            config_path.write_text(
                json.dumps({"database": "/custom/state.sqlite3"}),
                encoding="utf-8",
            )
            example_path.write_text(
                json.dumps(
                    {
                        "database": "/default/state.sqlite3",
                        "collector_config": "/etc/argent-sentinel/collector.json",
                        "report_batch_state_file": "/var/lib/argent-sentinel/collector/report-batch-state.json",
                    }
                ),
                encoding="utf-8",
            )
            self.run_migrator(
                "--config",
                str(config_path),
                "--example",
                str(example_path),
                "--top-level-only",
            )
            migrated = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual("/custom/state.sqlite3", migrated["database"])
            self.assertEqual(
                "/etc/argent-sentinel/collector.json",
                migrated["collector_config"],
            )
            self.assertEqual(
                "/var/lib/argent-sentinel/collector/report-batch-state.json",
                migrated["report_batch_state_file"],
            )

    def test_postinst_quiesces_collector_before_migration(self) -> None:
        text = POSTINST.read_text(encoding="utf-8")
        stop_timer = text.index(
            "systemctl stop argent-sentinel-collector.timer"
        )
        config_migrate = text.index(
            "/usr/sbin/argent-sentinel-config-migrate"
        )
        database_migrate = text.index(
            '/usr/bin/argent-sentinel --config "$CONFIG" migrate'
        )
        restart_timer = text.index(
            "systemctl restart argent-sentinel-collector.timer"
        )
        self.assertLess(stop_timer, config_migrate)
        self.assertLess(stop_timer, database_migrate)
        self.assertLess(database_migrate, restart_timer)
        self.assertIn('[ "$WAIT_SECONDS" -lt 30 ]', text)
        self.assertIn(
            "dashboard-snapshot.json.pre-v0511",
            text,
        )


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0511_revision2.py
