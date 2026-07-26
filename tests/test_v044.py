#!/usr/bin/env python3
# Argent Sentinel v0.5.0.3 release regression tests.

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class V044Test(unittest.TestCase):
    def test_release_versions_and_banner_layout(self) -> None:
        self.assertEqual("0.5.0.3", (ROOT / "VERSION").read_text().strip())

        for relative in (
            "src/collector.py",
            "src/agent.py",
            "src/server_api.py",
        ):
            source = (ROOT / relative).read_text()
            self.assertIn('APP_VERSION = "0.5.0.3"', source)

        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('if upstream != "0.5.0.3":', builder)
        self.assertIn('"test_v044.py"', builder)

        collector = (ROOT / "src/collector.py").read_text()
        self.assertIn('body: list[str] = []', collector)
        self.assertIn(
            'body.extend(["*** TEST MODE ***", ""])',
            collector,
        )
        self.assertIn('body.extend(["Hello,", ""])', collector)


if __name__ == "__main__":
    unittest.main()
