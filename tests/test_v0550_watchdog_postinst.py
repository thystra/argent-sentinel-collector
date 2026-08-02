#!/usr/bin/env python3
# tests/test_v0550_watchdog_postinst.py
#
# Regression coverage for the 0.5.5.0 watchdog configuration migration.
# EOF

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
POSTINST = ROOT / "packaging" / "deb" / "server.postinst"


class WatchdogPostinstMigrationTests(unittest.TestCase):
    def test_watchdog_migration_is_top_level_only(self) -> None:
        text = POSTINST.read_text(encoding="utf-8")

        expression = re.compile(
            r"""
            /usr/sbin/argent-sentinel-config-migrate
            [\s\\]+--config[ \t]+"\$WATCHDOG_CONFIG"
            [\s\\]+--example[ \t]+"\$WATCHDOG_EXAMPLE"
            [\s\\]+--backup[ \t]+"\$BACKUP/watchdog\.json\.pre-v0550"
            [\s\\]+--top-level-only
            """,
            re.VERBOSE,
        )

        self.assertRegex(
            text,
            expression,
            "watchdog.json must use top-level-only migration so the "
            "collector-specific report_batching migration is not applied "
            "to the watchdog schema",
        )

    def test_watchdog_migration_precedes_legacy_archive_invocation(
        self,
    ) -> None:
        text = POSTINST.read_text(encoding="utf-8")

        migration = text.index('--config "$WATCHDOG_CONFIG"')
        invocation = re.search(
            r"(?m)^[ \t]+archive_legacy_unbound_watchdog[ \t]*$",
            text[migration:],
        )

        self.assertIsNotNone(
            invocation,
            "legacy Unbound archive invocation was not found after the "
            "watchdog migration",
        )
        assert invocation is not None

        archive = migration + invocation.start()
        self.assertLess(
            migration,
            archive,
            "watchdog configuration must be migrated before legacy assets "
            "are archived",
        )


if __name__ == "__main__":
    unittest.main()
