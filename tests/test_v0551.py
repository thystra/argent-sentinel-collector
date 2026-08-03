#!/usr/bin/env python3
# /home/alan/src/argent-sentinel-collector/tests/test_v0551.py
"""Regression coverage for PHP-FPM target discovery in Argent Sentinel 0.5.5.1."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from watchdogs import php_fpm  # noqa: E402


class V0551Test(unittest.TestCase):
    def test_release_version_and_auto_package_default(self) -> None:
        self.assertEqual("0.5.5.1", (ROOT / "VERSION").read_text().strip())
        value = json.loads(
            (ROOT / "config/watchdog.d/20-php_fpm.json").read_text()
        )
        self.assertEqual("auto", value["service"])
        self.assertNotIn("php_fpm_command", value)
        self.assertNotIn("log_file", value)
        self.assertNotIn("process_name", value)
        self.assertNotIn("expected_event_mechanism", value)

    def test_auto_discovery_prefers_highest_active_service(self) -> None:
        active = {
            "returncode": 0,
            "timed_out": False,
            "stdout": (
                "php8.4-fpm.service loaded active running PHP 8.4 FPM\n"
                "php8.3-fpm.service loaded active running PHP 8.3 FPM\n"
            ),
            "stderr": "",
        }
        installed = {
            "returncode": 0,
            "timed_out": False,
            "stdout": (
                "php8.5-fpm.service disabled enabled\n"
                "php8.4-fpm.service enabled enabled\n"
                "php8.3-fpm.service enabled enabled\n"
            ),
            "stderr": "",
        }
        with mock.patch.object(
            php_fpm,
            "run_command",
            side_effect=[active, installed],
        ):
            target = php_fpm._resolve_target({"service": "auto"})
        self.assertEqual("php8.4-fpm.service", target["service"])
        self.assertEqual("8.4", target["version"])
        self.assertEqual("/usr/sbin/php-fpm8.4", target["command"])
        self.assertEqual("/var/log/php8.4-fpm.log", target["log_file"])
        self.assertEqual("php-fpm8.4", target["process_name"])
        self.assertEqual("auto-active", target["source"])
        self.assertEqual(
            ["php8.4-fpm.service", "php8.3-fpm.service"],
            target["active_services"],
        )

    def test_explicit_target_overrides_are_preserved(self) -> None:
        config = {
            "service": "custom-fpm.service",
            "php_fpm_command": "/opt/php/bin/php-fpm",
            "log_file": "/srv/log/custom-fpm.log",
            "process_name": "custom-fpm",
        }
        with mock.patch.object(php_fpm, "run_command") as command:
            target = php_fpm._resolve_target(config)
        command.assert_not_called()
        self.assertEqual("custom-fpm.service", target["service"])
        self.assertEqual("/opt/php/bin/php-fpm", target["command"])
        self.assertEqual("/srv/log/custom-fpm.log", target["log_file"])
        self.assertEqual("custom-fpm", target["process_name"])
        self.assertEqual("explicit", target["source"])

    def test_zombies_are_scoped_to_selected_master_and_process(self) -> None:
        result = {
            "returncode": 0,
            "timed_out": False,
            "stdout": (
                "100 Z php-fpm8.4\n"
                "100 Zs php-fpm8.4\n"
                "100 S php-fpm8.4\n"
                "200 Z php-fpm8.4\n"
                "100 Z php-fpm8.5\n"
                "100 Z unrelated\n"
            ),
            "stderr": "",
        }
        with mock.patch.object(php_fpm, "run_command", return_value=result):
            self.assertEqual(2, php_fpm._zombies(100, "php-fpm8.4"))

    def test_target_change_rebases_log_even_when_pid_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php8.4-fpm.log"
            log.write_text(
                "[old target] child exited with code 0 after 0.10 seconds from start\n"
            )
            config = {
                "service": "php8.4-fpm.service",
                "php_fpm_command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "mode": "observe",
                "interval_seconds": 60,
                "probes": [],
            }
            previous = {
                "metrics": {"main_pid": 222},
                "runtime": {
                    "log_cursor": {
                        "inode": log.stat().st_ino,
                        "offset": 0,
                    },
                    "target": {
                        "id": (
                            "php8.5-fpm.service|/usr/sbin/php-fpm8.5|"
                            "/var/log/php8.5-fpm.log|php-fpm8.5"
                        )
                    },
                },
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 222,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                return_value=(
                    "epoll",
                    {"returncode": 0, "timed_out": False},
                ),
            ):
                result = php_fpm.check({}, config, previous)
        self.assertEqual("healthy", result["status"])
        self.assertTrue(result["details"]["target_changed"])
        self.assertFalse(result["details"]["master_changed"])
        self.assertTrue(result["details"]["log_cursor_rebased"])
        self.assertEqual(0, result["metrics"]["rapid_exits"])

    def test_event_mechanism_check_is_skipped_when_expectation_is_absent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text("")
            config = {
                "service": "php8.4-fpm.service",
                "php_fpm_command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "mode": "observe",
                "interval_seconds": 60,
                "probes": [],
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 333,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                side_effect=AssertionError("optional mechanism check must be skipped"),
            ) as detector:
                result = php_fpm.check({}, config, {})
        detector.assert_not_called()
        self.assertEqual("healthy", result["status"])
        self.assertEqual("not_checked", result["details"]["event_mechanism"])
        self.assertEqual("any", result["details"]["expected_event_mechanism"])
        self.assertFalse(result["details"]["mechanism_check_enforced"])
        self.assertTrue(result["details"]["mechanism_check_skipped"])
        self.assertTrue(result["details"]["mechanism_command_ok"])
        self.assertFalse(result["notify_admin"])

    def test_event_mechanism_check_is_skipped_for_explicit_any(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text("")
            config = {
                "service": "php8.4-fpm.service",
                "php_fpm_command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "expected_event_mechanism": "any",
                "mode": "observe",
                "interval_seconds": 60,
                "probes": [],
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 333,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                side_effect=AssertionError(
                    "sandbox-incompatible detector must not run for any"
                ),
            ) as detector:
                result = php_fpm.check({}, config, {})
        detector.assert_not_called()
        self.assertEqual("healthy", result["status"])
        self.assertEqual("not_checked", result["details"]["event_mechanism"])
        self.assertFalse(result["notify_admin"])

    def test_explicit_event_mechanism_mismatch_remains_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text("")
            config = {
                "service": "php8.4-fpm.service",
                "php_fpm_command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "expected_event_mechanism": "poll",
                "mode": "observe",
                "interval_seconds": 60,
                "probes": [],
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 333,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                return_value=(
                    "epoll",
                    {"returncode": 0, "timed_out": False},
                ),
            ):
                result = php_fpm.check({}, config, {})
        self.assertEqual("warning", result["status"])
        self.assertIn("expected poll", result["summary"])

    def test_explicit_event_mechanism_unknown_remains_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text("")
            config = {
                "service": "php8.4-fpm.service",
                "php_fpm_command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "expected_event_mechanism": "poll",
                "mode": "observe",
                "interval_seconds": 60,
                "probes": [],
            }
            stderr = "x" * 1200 + "Read-only file system"
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 333,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                return_value=(
                    "unknown",
                    {
                        "returncode": 78,
                        "timed_out": False,
                        "stdout": "",
                        "stderr": stderr,
                    },
                ),
            ):
                result = php_fpm.check({}, config, {})
        self.assertEqual("warning", result["status"])
        self.assertIn("Unable to determine", result["summary"])
        self.assertTrue(result["details"]["mechanism_check_enforced"])
        self.assertFalse(result["details"]["mechanism_check_skipped"])
        self.assertFalse(result["details"]["mechanism_command_ok"])
        self.assertEqual(78, result["details"]["mechanism_command_returncode"])
        self.assertFalse(result["details"]["mechanism_command_timed_out"])
        tail = result["details"]["mechanism_command_stderr_tail"]
        self.assertLessEqual(len(tail), 1000)
        self.assertTrue(tail.endswith("Read-only file system"))
        self.assertTrue(result["notify_admin"])

    def test_explicit_event_mechanism_match_is_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text("")
            config = {
                "service": "php8.4-fpm.service",
                "php_fpm_command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "expected_event_mechanism": "epoll",
                "mode": "observe",
                "interval_seconds": 60,
                "probes": [],
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 333,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                return_value=(
                    "epoll",
                    {
                        "returncode": 0,
                        "timed_out": False,
                        "stdout": "",
                        "stderr": "",
                    },
                ),
            ):
                result = php_fpm.check({}, config, {})
        self.assertEqual("healthy", result["status"])
        self.assertEqual("epoll", result["details"]["event_mechanism"])
        self.assertTrue(result["details"]["mechanism_check_enforced"])
        self.assertFalse(result["details"]["mechanism_check_skipped"])
        self.assertTrue(result["details"]["mechanism_command_ok"])
        self.assertFalse(result["notify_admin"])

    def test_multiple_active_services_are_visible_and_warn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text("")
            target = {
                "service": "php8.4-fpm.service",
                "version": "8.4",
                "command": "/usr/sbin/php-fpm8.4",
                "log_file": str(log),
                "process_name": "php-fpm8.4",
                "id": "target",
                "source": "auto-active",
                "active_services": [
                    "php8.4-fpm.service",
                    "php8.3-fpm.service",
                ],
                "errors": [],
            }
            with mock.patch.object(
                php_fpm,
                "_resolve_target",
                return_value=target,
            ), mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 333,
                    "MemoryCurrent": 1024,
                    "TasksCurrent": 10,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                return_value=(
                    "epoll",
                    {"returncode": 0, "timed_out": False},
                ),
            ):
                result = php_fpm.check(
                    {},
                    {
                        "mode": "observe",
                        "interval_seconds": 60,
                        "probes": [],
                    },
                    {},
                )
        self.assertEqual("warning", result["status"])
        self.assertIn("Multiple active PHP-FPM services", result["summary"])


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0551.py
