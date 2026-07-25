#!/usr/bin/env python3
# Argent Sentinel v0.4.6 release regression tests.

from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402


class V045Test(unittest.TestCase):
    def make_collector(self) -> collector.Collector:
        instance = object.__new__(collector.Collector)
        instance.config = {
            "web_policy": {
                "window_seconds": 600,
                "suspicious_threshold": 3,
                "distinct_targets": 1,
            }
        }
        return instance

    @staticmethod
    def row(epoch: int, path: str, category: str, status: int) -> dict:
        return {
            "occurred_epoch": epoch,
            "request_path": path,
            "metadata_json": json.dumps(
                {
                    "probe_category": category,
                    "http_status": status,
                }
            ),
        }

    def test_threshold_crossing_keeps_later_events(self) -> None:
        instance = self.make_collector()
        rows = [
            self.row(1000, "/wp-content/plugins/file-manager/a.php",
                     "wp-content-php-probe", 444),
            self.row(1000, "/.env", "sensitive-file-probe", 444),
            self.row(1386, "/.env", "sensitive-file-probe", 444),
            self.row(1387, "/wp-content/plugins/hellopress/b.php",
                     "wp-content-php-probe", 444),
            self.row(1387, "/wp-config.php.bak",
                     "sensitive-file-probe", 403),
            self.row(1387, "/wp-includes/Requests/src/Proxy.php",
                     "wp-includes-php-probe", 444),
        ]

        candidates = instance.find_web_probe_candidates(rows)

        self.assertEqual(1, len(candidates))
        self.assertEqual(rows, candidates[0])
        self.assertEqual(6, len(candidates[0]))

    def test_unrelated_later_segment_is_not_included(self) -> None:
        instance = self.make_collector()
        first = [
            self.row(1000, "/.env", "sensitive-file-probe", 444),
            self.row(1001, "/wp-config.php.bak",
                     "sensitive-file-probe", 403),
            self.row(1002, "/wp-includes/a.php",
                     "wp-includes-php-probe", 444),
        ]
        later = [
            self.row(1703, "/wp-content/plugins/one.php",
                     "wp-content-php-probe", 444),
            self.row(1704, "/wp-content/plugins/two.php",
                     "wp-content-php-probe", 444),
        ]

        candidates = instance.find_web_probe_candidates(first + later)

        self.assertEqual([first], candidates)

    def test_release_versions_are_consistent(self) -> None:
        self.assertEqual("0.4.6", (ROOT / "VERSION").read_text().strip())
        for relative in (
            "src/collector.py",
            "src/agent.py",
            "src/server_api.py",
        ):
            source = (ROOT / relative).read_text()
            self.assertIn('APP_VERSION = "0.4.6"', source)

        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('if upstream != "0.4.6":', builder)
        self.assertIn('"test_v045.py"', builder)


if __name__ == "__main__":
    unittest.main()
