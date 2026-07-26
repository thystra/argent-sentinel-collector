#!/usr/bin/env python3
from __future__ import annotations

import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "onboard-wordpress-site.sh"


class WordPressOnboardingRestartTest(unittest.TestCase):
    def bash(
        self,
        body: str,
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = f"source {shlex.quote(str(SCRIPT))}\n{body}"
        return subprocess.run(
            ["bash", "-c", command],
            check=check,
            text=True,
            capture_output=True,
        )

    def test_services_are_deduplicated_by_php_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "etc/php"
            for version, name in (
                ("8.5", "one.conf"),
                ("8.5", "two.conf"),
                ("8.4", "legacy.conf"),
            ):
                pool = root / version / "fpm/pool.d" / name
                pool.parent.mkdir(parents=True, exist_ok=True)
                pool.write_text(
                    "[site]\nuser = example\n",
                    encoding="utf-8",
                )

            result = self.bash(
                "php_fpm_services_for_user example "
                + shlex.quote(str(root))
            )
            self.assertEqual(
                {"php8.4-fpm", "php8.5-fpm"},
                set(result.stdout.splitlines()),
            )
            self.assertEqual(2, len(result.stdout.splitlines()))

    def test_restart_runs_once_and_verifies_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pool = root / "etc/php/8.5/fpm/pool.d/example.conf"
            pool.parent.mkdir(parents=True)
            pool.write_text(
                "[example]\nuser = example\n",
                encoding="utf-8",
            )
            log = root / "systemctl.log"
            result = self.bash(
                "systemctl() { printf '%s\\n' \"$*\" >> "
                + shlex.quote(str(log))
                + "; }\n"
                + "export ARGENT_SENTINEL_PHP_ETC_ROOT="
                + shlex.quote(str(root / "etc/php"))
                + "\nrestart_php_fpm_for_user example"
            )
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                ["restart php8.5-fpm", "is-active --quiet php8.5-fpm"],
                calls,
            )
            self.assertIn(
                "Restarted and verified php8.5-fpm.",
                result.stdout,
            )

    def test_help_documents_default_restart_and_opt_out(self) -> None:
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn("restarted automatically at the end", result.stdout)
        self.assertIn("--no-restart-php-fpm", result.stdout)
        self.assertIn("--restart-php-fpm", result.stdout)

    def test_no_matching_pool_warns_without_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.bash(
                "export ARGENT_SENTINEL_PHP_ETC_ROOT="
                + shlex.quote(str(Path(temporary) / "etc/php"))
                + "\nrestart_php_fpm_for_user nobody",
            )
            self.assertIn(
                "No matching PHP-FPM service could be identified",
                result.stderr,
            )


if __name__ == "__main__":
    unittest.main()
