#!/usr/bin/env python3
from __future__ import annotations

import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "onboard-wordpress-site.sh"


class MissingOpenBasedirPolicyTest(unittest.TestCase):
    def bash(
        self,
        body: str,
        *,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = f"source {shlex.quote(str(SCRIPT))}\n{body}"
        return subprocess.run(
            ["bash", "-c", command],
            check=check,
            text=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
        )

    def test_noninteractive_default_stops_on_unrestricted_pool(self) -> None:
        result = self.bash(
            "handle_missing_pool_open_basedir "
            "/etc/php/8.5/fpm/pool.d/example.conf "
            "/var/lib/argent-sentinel/drop/wordpress/example/incoming "
            "prompt stop"
        )
        self.assertEqual(4, result.returncode)
        self.assertIn("SECURITY WARNING", result.stderr)
        self.assertIn("Onboarding stopped", result.stderr)

    def test_explicit_continue_allows_unrestricted_pool(self) -> None:
        result = self.bash(
            "handle_missing_pool_open_basedir "
            "/etc/php/8.5/fpm/pool.d/example.conf "
            "/var/lib/argent-sentinel/drop/wordpress/example/incoming "
            "prompt continue"
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("--no-open-basedir-action continue", result.stderr)

    def test_ignore_mode_allows_unrestricted_pool(self) -> None:
        result = self.bash(
            "handle_missing_pool_open_basedir "
            "/etc/php/8.5/fpm/pool.d/example.conf "
            "/var/lib/argent-sentinel/drop/wordpress/example/incoming "
            "ignore stop"
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("--open-basedir-mode ignore", result.stderr)

    def test_inspection_stops_before_configuration_for_unrestricted_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "etc/php"
            pool = root / "8.5/fpm/pool.d/example.conf"
            pool.parent.mkdir(parents=True)
            pool.write_text(
                "[example]\n"
                "user = example\n"
                "group = example\n",
                encoding="utf-8",
            )
            result = self.bash(
                "export ARGENT_SENTINEL_PHP_ETC_ROOT="
                + shlex.quote(str(root))
                + "\ninspect_open_basedir example "
                "/var/lib/argent-sentinel/drop/wordpress/example/incoming "
                "prompt stop"
            )
            self.assertEqual(4, result.returncode)
            self.assertIn(str(pool), result.stderr)

    def test_inspection_accepts_explicit_continue_for_unrestricted_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "etc/php"
            pool = root / "8.5/fpm/pool.d/example.conf"
            pool.parent.mkdir(parents=True)
            pool.write_text(
                "[example]\n"
                "user = example\n"
                "group = example\n",
                encoding="utf-8",
            )
            result = self.bash(
                "export ARGENT_SENTINEL_PHP_ETC_ROOT="
                + shlex.quote(str(root))
                + "\ninspect_open_basedir example "
                "/var/lib/argent-sentinel/drop/wordpress/example/incoming "
                "prompt continue"
            )
            self.assertEqual(0, result.returncode)
            self.assertIn(
                "--no-open-basedir-action continue",
                result.stderr,
            )

    def test_help_documents_security_policy_and_override(self) -> None:
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            check=True,
            text=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
        )
        self.assertIn("security-hardening failure", result.stdout)
        self.assertIn("--no-open-basedir-action continue", result.stdout)


if __name__ == "__main__":
    unittest.main()
