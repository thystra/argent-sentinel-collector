#!/usr/bin/env python3
from __future__ import annotations

import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "onboard-wordpress-site.sh"


class WordPressOnboardingHelperTest(unittest.TestCase):
    def bash(self, body: str) -> subprocess.CompletedProcess[str]:
        command = f"source {shlex.quote(str(SCRIPT))}\n{body}"
        return subprocess.run(
            ["bash", "-c", command],
            check=True,
            text=True,
            capture_output=True,
        )

    def test_open_basedir_parent_or_exact_path_is_allowed(self) -> None:
        drop = "/var/lib/argent-sentinel/drop/wordpress/example/incoming"
        self.bash(
            "open_basedir_contains "
            + shlex.quote("/srv:/tmp:/var/lib/argent-sentinel/drop/wordpress")
            + " "
            + shlex.quote(drop)
        )
        self.bash(
            "open_basedir_contains "
            + shlex.quote("/srv:/tmp:" + drop)
            + " "
            + shlex.quote(drop)
        )

    def test_open_basedir_missing_path_is_rejected(self) -> None:
        result = subprocess.run(
            [
                "bash",
                "-c",
                f"source {shlex.quote(str(SCRIPT))}; "
                "open_basedir_contains /srv:/tmp "
                "/var/lib/argent-sentinel/drop/wordpress/example/incoming",
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(0, result.returncode)

    def test_pool_discovery_and_atomic_append(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pool = root / "etc/php/8.5/fpm/pool.d/example.conf"
            pool.parent.mkdir(parents=True)
            pool.write_text(
                "[example]\n"
                "user = example\n"
                "group = example\n"
                "php_admin_value[open_basedir] = /srv/example:/tmp\n",
                encoding="utf-8",
            )
            backup = root / "backups"
            drop = "/var/lib/argent-sentinel/drop/wordpress/example/incoming"

            discovered = self.bash(
                "find_php_fpm_pools example " + shlex.quote(str(root / "etc/php"))
            ).stdout.strip()
            self.assertEqual(str(pool), discovered)

            self.bash(
                "append_pool_open_basedir "
                + shlex.quote(str(pool))
                + " "
                + shlex.quote(drop)
                + " "
                + shlex.quote(str(backup))
            )
            updated = pool.read_text(encoding="utf-8")
            self.assertIn("/srv/example:/tmp:" + drop, updated)
            self.assertEqual(1, updated.count(drop))
            self.assertTrue(any(backup.rglob("*.bak")))

            self.bash(
                "append_pool_open_basedir "
                + shlex.quote(str(pool))
                + " "
                + shlex.quote(drop)
                + " "
                + shlex.quote(str(backup))
            )
            self.assertEqual(1, pool.read_text(encoding="utf-8").count(drop))

    def test_help_documents_prompt_append_warn_and_ignore(self) -> None:
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            check=True,
            text=True,
            capture_output=True,
        )
        for mode in ("prompt", "append", "warn", "ignore"):
            self.assertIn(mode, result.stdout)
        self.assertIn("--restart-php-fpm", result.stdout)

    def test_missing_option_value_returns_usage_error_not_shell_failure(self) -> None:
        result = subprocess.run(
            ["bash", str(SCRIPT), "--wordpress-path"],
            text=True,
            capture_output=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("--wordpress-path requires a value", result.stderr)


if __name__ == "__main__":
    unittest.main()
