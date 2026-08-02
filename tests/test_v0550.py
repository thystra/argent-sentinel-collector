#!/usr/bin/env python3
# /home/alan/src/argent-sentinel-collector/tests/test_v0550.py
"""Regression coverage for Argent Sentinel 0.5.5.0 watchdog framework."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import dashboard  # noqa: E402
import dashboard_snapshot  # noqa: E402
import watchdog  # noqa: E402
import watchdog_runtime  # noqa: E402
from watchdogs import php_fpm, unbound  # noqa: E402


class V0550Test(unittest.TestCase):
    def test_release_version(self) -> None:
        self.assertEqual("0.5.5.0", (ROOT / "VERSION").read_text().strip())
        self.assertEqual("0.5.5.0", watchdog.APP_VERSION)
        self.assertEqual("0.5.5.0", dashboard.APP_VERSION)
        self.assertEqual("0.5.5.0", dashboard_snapshot.APP_VERSION)

    def test_packaged_watchdog_assets_exist(self) -> None:
        required = (
            "src/watchdog.py",
            "src/watchdog_runtime.py",
            "src/watchdogs/__init__.py",
            "src/watchdogs/unbound.py",
            "src/watchdogs/php_fpm.py",
            "config/watchdog.json.example",
            "config/watchdog.d/10-unbound.json",
            "config/watchdog.d/20-php_fpm.json",
            "packaging/bin/argent-sentinel-watchdog",
            "packaging/systemd/argent-sentinel-watchdog.service",
            "packaging/systemd/argent-sentinel-watchdog.timer",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_package_watchdogs_are_disabled_until_locally_enabled(self) -> None:
        for relative in (
            "config/watchdog.d/10-unbound.json",
            "config/watchdog.d/20-php_fpm.json",
        ):
            value = json.loads((ROOT / relative).read_text())
            self.assertFalse(value["enabled"], relative)
            self.assertGreaterEqual(value["timeout_seconds"], 10)

    def test_definitions_merge_package_defaults_and_local_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            local = root / "local"
            package.mkdir()
            local.mkdir()
            (package / "10-test.json").write_text(
                json.dumps(
                    {
                        "id": "unbound",
                        "module": "unbound",
                        "enabled": False,
                        "mode": "remediate",
                        "interval_seconds": 300,
                        "timeout_seconds": 180,
                        "dig_timeout_seconds": 5,
                    }
                )
            )
            (local / "90-test.json").write_text(
                json.dumps({"id": "unbound", "enabled": True})
            )
            definitions = watchdog.load_watchdogs(
                {
                    "package_config_dir": str(package),
                    "config_dir": str(local),
                }
            )
        self.assertTrue(definitions["unbound"]["enabled"])
        self.assertEqual("unbound", definitions["unbound"]["module"])
        self.assertEqual(300, definitions["unbound"]["interval_seconds"])

    def test_invalid_notification_address_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "watchdog.json"
            value = dict(watchdog.DEFAULTS)
            value["notifications"] = {
                "enabled": True,
                "mail_command": "/usr/bin/mail",
                "hostname": "",
                "admin_recipients": ["not an address"],
                "emergency_recipients": [],
            }
            config.write_text(json.dumps(value))
            with self.assertRaises(watchdog.WatchdogError):
                watchdog.load_config(config)

    def test_bounded_command_reports_timeout(self) -> None:
        result = watchdog_runtime.run_command(
            ["/bin/sh", "-c", "sleep 5"],
            timeout=0.05,
        )
        self.assertTrue(result["timed_out"])
        self.assertNotEqual(0, result["returncode"])

    def test_php_log_cursor_ignores_history_then_counts_new_churn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text(
                "[old] child exited with code 0 after 0.01 seconds from start\n"
                "[old] epoll: unable to remove fd 1\n"
            )
            counts, cursor = php_fpm._read_log_delta(log, {})
            self.assertEqual({"code0": 0, "short": 0, "epoll": 0}, counts)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(
                    "[new] child exited with code 0 after 0.02 seconds from start\n"
                    "[new] child exited with code 0 after 12.00 seconds from start\n"
                    "[new] epoll: unable to remove fd 2\n"
                )
            counts, updated = php_fpm._read_log_delta(
                log,
                {"runtime": {"log_cursor": cursor}},
            )
        self.assertEqual({"code0": 2, "short": 1, "epoll": 1}, counts)
        self.assertGreater(updated["offset"], cursor["offset"])

    def test_php_log_rotation_restarts_at_beginning_for_same_master(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text(
                "[rotated] child exited with code 0 after 0.10 seconds from start\n"
                "[rotated] epoll: unable to remove fd 7\n"
            )
            expected_inode = log.stat().st_ino
            counts, cursor = php_fpm._read_log_delta(
                log,
                {
                    "metrics": {"main_pid": 123},
                    "runtime": {
                        "log_cursor": {
                            "inode": expected_inode + 1,
                            "offset": 99999,
                        }
                    },
                },
            )
        self.assertEqual({"code0": 1, "short": 1, "epoll": 1}, counts)
        self.assertEqual(expected_inode, cursor["inode"])

    def test_php_master_change_rebases_old_shutdown_churn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text(
                "[old master] child exited with code 0 after 0.10 seconds from start\n"
                "[old master] epoll: unable to remove fd 9\n"
            )
            config = json.loads(
                (ROOT / "config/watchdog.d/20-php_fpm.json").read_text()
            )
            config.update(
                {
                    "enabled": True,
                    "log_file": str(log),
                    "probes": [],
                }
            )
            previous = {
                "metrics": {"main_pid": 111},
                "runtime": {
                    "log_cursor": {
                        "inode": log.stat().st_ino,
                        "offset": 0,
                    }
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
                    "TasksCurrent": 12,
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
                return_value=("poll", {"returncode": 0, "timed_out": False}),
            ):
                result = php_fpm.check({}, config, previous)
            expected_offset = log.stat().st_size
        self.assertEqual("healthy", result["status"])
        self.assertEqual(0, result["metrics"]["code0_exits"])
        self.assertEqual(0, result["metrics"]["rapid_exits"])
        self.assertEqual(0, result["metrics"]["epoll_remove_failures"])
        self.assertEqual(111, result["details"]["previous_main_pid"])
        self.assertEqual(222, result["details"]["current_main_pid"])
        self.assertTrue(result["details"]["master_changed"])
        self.assertTrue(result["details"]["log_cursor_rebased"])
        self.assertTrue(result["public_details"]["master_changed"])
        self.assertEqual(expected_offset, result["runtime"]["log_cursor"]["offset"])

    def test_php_master_change_still_reports_current_zombies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text(
                "[old master] child exited with code 0 after 0.10 seconds from start\n"
            )
            config = json.loads(
                (ROOT / "config/watchdog.d/20-php_fpm.json").read_text()
            )
            config.update(
                {
                    "enabled": True,
                    "log_file": str(log),
                    "probes": [],
                }
            )
            previous = {
                "metrics": {"main_pid": 111},
                "runtime": {
                    "log_cursor": {
                        "inode": log.stat().st_ino,
                        "offset": 0,
                    }
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
                    "TasksCurrent": 12,
                },
            ), mock.patch.object(
                php_fpm,
                "_zombies",
                return_value=2,
            ), mock.patch.object(
                php_fpm,
                "_maximum_socket_queue",
                return_value=0,
            ), mock.patch.object(
                php_fpm,
                "_event_mechanism",
                return_value=("poll", {"returncode": 0, "timed_out": False}),
            ):
                result = php_fpm.check({}, config, previous)
        self.assertEqual("critical", result["status"])
        self.assertIn("2 zombie process(es)", result["summary"])
        self.assertEqual(0, result["metrics"]["rapid_exits"])
        self.assertTrue(result["details"]["master_changed"])
        self.assertTrue(result["details"]["log_cursor_rebased"])

    def test_php_same_master_after_rebase_detects_appended_fault(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            log.write_text(
                "[old master] child exited with code 0 after 0.10 seconds from start\n"
            )
            config = json.loads(
                (ROOT / "config/watchdog.d/20-php_fpm.json").read_text()
            )
            config.update(
                {
                    "enabled": True,
                    "log_file": str(log),
                    "probes": [],
                    "critical_rapid_exits": 1,
                }
            )
            previous = {
                "metrics": {"main_pid": 111},
                "runtime": {
                    "log_cursor": {
                        "inode": log.stat().st_ino,
                        "offset": 0,
                    }
                },
            }
            properties = {
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": 222,
                "MemoryCurrent": 1024,
                "TasksCurrent": 12,
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value=properties,
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
                return_value=("poll", {"returncode": 0, "timed_out": False}),
            ):
                rebased = php_fpm.check({}, config, previous)
                with log.open("a", encoding="utf-8") as handle:
                    handle.write(
                        "[new master] child exited with code 0 after 0.20 seconds from start\n"
                        "[new master] epoll: unable to remove fd 10\n"
                    )
                result = php_fpm.check({}, config, rebased)
        self.assertEqual("critical", result["status"])
        self.assertFalse(result["details"]["master_changed"])
        self.assertFalse(result["details"]["log_cursor_rebased"])
        self.assertEqual(1, result["metrics"]["code0_exits"])
        self.assertEqual(1, result["metrics"]["rapid_exits"])
        self.assertEqual(1, result["metrics"]["epoll_remove_failures"])

    def test_php_zero_current_pid_does_not_rebase_or_hide_faults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "php.log"
            prefix = "[before] ordinary line\n"
            log.write_text(
                prefix
                + "[current] child exited with code 0 after 0.10 seconds from start\n"
                + "[current] epoll: unable to remove fd 11\n"
            )
            config = json.loads(
                (ROOT / "config/watchdog.d/20-php_fpm.json").read_text()
            )
            config.update(
                {
                    "enabled": True,
                    "log_file": str(log),
                    "probes": [],
                    "critical_rapid_exits": 1,
                }
            )
            previous = {
                "metrics": {"main_pid": 111},
                "runtime": {
                    "log_cursor": {
                        "inode": log.stat().st_ino,
                        "offset": len(prefix.encode()),
                    }
                },
            }
            with mock.patch.object(
                php_fpm,
                "_systemd_properties",
                return_value={
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "MainPID": 0,
                    "MemoryCurrent": 0,
                    "TasksCurrent": 0,
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
                return_value=("poll", {"returncode": 0, "timed_out": False}),
            ):
                result = php_fpm.check({}, config, previous)
        self.assertEqual("critical", result["status"])
        self.assertIn("master process is not active", result["summary"])
        self.assertFalse(result["details"]["master_changed"])
        self.assertFalse(result["details"]["log_cursor_rebased"])
        self.assertEqual(1, result["metrics"]["rapid_exits"])
        self.assertEqual(1, result["metrics"]["epoll_remove_failures"])

    def test_php_watchdog_healthy_result_is_observe_only(self) -> None:
        config = json.loads(
            (ROOT / "config/watchdog.d/20-php_fpm.json").read_text()
        )
        config["enabled"] = True
        config["probes"] = [{"name": "site"}]
        with mock.patch.object(
            php_fpm,
            "_systemd_properties",
            return_value={
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": 123,
                "MemoryCurrent": 1024,
                "TasksCurrent": 12,
            },
        ), mock.patch.object(php_fpm, "_zombies", return_value=0), mock.patch.object(
            php_fpm, "_maximum_socket_queue", return_value=0
        ), mock.patch.object(
            php_fpm,
            "_event_mechanism",
            return_value=("poll", {"returncode": 0, "timed_out": False}),
        ), mock.patch.object(
            php_fpm,
            "_read_log_delta",
            return_value=(
                {"code0": 0, "short": 0, "epoll": 0},
                {"inode": 1, "offset": 2},
            ),
        ), mock.patch.object(
            php_fpm,
            "_probe",
            return_value={
                "name": "site",
                "code": "200",
                "allowed": True,
                "time_seconds": 0.1,
                "stderr": "private diagnostic",
            },
        ):
            result = php_fpm.check({}, config, {})
        self.assertEqual("healthy", result["status"])
        self.assertEqual(0, result["metrics"]["rapid_exits"])
        self.assertEqual("observe", config["mode"])
        self.assertNotIn("stderr", result["public_details"]["probes"][0])

    def test_unbound_recovery_notifies_admin_but_not_emergency(self) -> None:
        config = json.loads(
            (ROOT / "config/watchdog.d/10-unbound.json").read_text()
        )
        config["enabled"] = True
        failed = {
            "returncode": 1,
            "timed_out": False,
            "duration_ms": 1,
            "stderr": "failed",
        }
        healthy = {
            "returncode": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stderr": "",
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            unbound,
            "_probe",
            side_effect=[failed, healthy],
        ), mock.patch.object(
            unbound,
            "_prepare_incident",
            return_value=(
                Path(temporary) / "incident-work",
                Path(temporary) / "incident.tar.gz",
            ),
        ), mock.patch.object(
            unbound,
            "_finish_incident",
        ) as finish, mock.patch.object(
            unbound,
            "run_command",
            return_value=healthy,
        ), mock.patch.object(unbound.time, "sleep"):
            result = unbound.check(
                {"incident_dir": temporary, "hostname": "test"},
                config,
                {},
            )
        self.assertEqual("healthy", result["status"])
        self.assertEqual("automatic-recovery", result["event"])
        self.assertTrue(result["notify_admin"])
        self.assertFalse(result["notify_emergency"])
        finish.assert_called_once()

    def test_recipient_categories_are_deduplicated(self) -> None:
        config = {
            "notifications": {
                "enabled": True,
                "hostname": "test.example",
                "admin_recipients": ["admin@example.com"],
                "emergency_recipients": [
                    "admin@example.com",
                    "phone@example.com",
                ],
            }
        }
        previous = {"status": "healthy"}
        state = {
            "id": "php_fpm",
            "display_name": "PHP-FPM",
            "status": "critical",
            "severity": "critical",
            "summary": "failed",
            "checked_at": "2026-08-01T16:00:00Z",
            "mode": "observe",
            "consecutive_failures": 1,
            "metrics": {},
            "details": {},
            "notify_admin": True,
            "notify_emergency": True,
        }
        calls: list[tuple[list[str], bool]] = []

        def fake_mail(config, recipients, subject, body, *, individual):
            del config, subject, body
            calls.append((recipients, individual))
            return []

        with mock.patch.object(watchdog, "_mail", side_effect=fake_mail):
            watchdog.send_state_notifications(config, previous, state)
        self.assertEqual(
            [(["admin@example.com"], False), (["phone@example.com"], True)],
            calls,
        )

    def test_notification_threshold_delays_first_php_alert(self) -> None:
        config = {
            "notifications": {
                "enabled": True,
                "hostname": "test.example",
                "admin_recipients": ["admin@example.com"],
                "emergency_recipients": [],
            }
        }
        state = {
            "id": "php_fpm",
            "display_name": "PHP-FPM",
            "status": "critical",
            "severity": "critical",
            "summary": "failed",
            "checked_at": "2026-08-01T16:00:00Z",
            "mode": "observe",
            "consecutive_failures": 1,
            "notification_failure_threshold": 2,
            "metrics": {},
            "details": {},
            "notify_admin": True,
            "notify_emergency": True,
        }
        with mock.patch.object(watchdog, "_mail") as mail:
            watchdog.send_state_notifications(
                config,
                {"status": "healthy", "consecutive_failures": 0},
                state,
            )
        mail.assert_not_called()

    def test_dashboard_snapshot_is_sanitized_and_marks_stale_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            status = Path(temporary) / "status"
            status.mkdir()
            (status / "php_fpm.json").write_text(
                json.dumps(
                    {
                        "id": "php_fpm",
                        "display_name": "PHP-FPM 8.5",
                        "enabled": True,
                        "mode": "observe",
                        "interval_seconds": 60,
                        "status": "healthy",
                        "summary": "all good",
                        "checked_at": "2026-08-01T16:00:00Z",
                        "checked_epoch": 100,
                        "metrics": {"zombies": 0},
                        "details": {"secret": "do not publish"},
                        "public_details": {"event_mechanism": "poll"},
                        "notification_deliveries": {
                            "emergency": [
                                {
                                    "recipients": ["phone@example.com"],
                                    "success": True,
                                }
                            ]
                        },
                        "history": [
                            {
                                "checked_at": "2026-08-01T16:00:00Z",
                                "status": "healthy",
                                "severity": "info",
                                "summary": "all good",
                                "event": "",
                            }
                        ],
                    }
                )
            )
            with mock.patch.object(
                dashboard_snapshot,
                "utc_now",
                return_value=dt.datetime.fromtimestamp(1000, tz=dt.timezone.utc),
            ):
                values = dashboard_snapshot.load_watchdog_statuses(Path(temporary))
        self.assertEqual(1, len(values))
        self.assertEqual("error", values[0]["status"])
        self.assertTrue(values[0]["stale"])
        self.assertEqual({"event_mechanism": "poll"}, values[0]["details"])
        self.assertNotIn("secret", json.dumps(values[0]))
        self.assertNotIn("phone@example.com", json.dumps(values[0]))
        self.assertEqual(1, values[0]["notification_delivery"]["emergency"]["successful"])
        rendered = dashboard.render_watchdogs({"watchdogs": values})
        self.assertIn("PHP-FPM 8.5", rendered)
        self.assertIn("Watchdog state is stale", rendered)
        page = dashboard.page(
            "Watchdogs",
            rendered,
            {"generated_at": "2026-08-01T16:00:00Z"},
            dashboard.DEFAULTS,
        ).decode()
        self.assertIn('href="/watchdogs"', page)

    def test_packaging_migrates_only_compatible_legacy_unbound_watchdog(self) -> None:
        postinst = (ROOT / "packaging/deb/server.postinst").read_text()
        self.assertIn("detect_legacy_unbound_watchdog", postinst)
        self.assertIn("archive_legacy_unbound_watchdog", postinst)
        self.assertIn("LEGACY_UNBOUND_COMPATIBLE", postinst)
        self.assertIn("LEGACY_UNBOUND_EMAIL", postinst)
        self.assertIn("LEGACY_UNBOUND_OVERRIDE", postinst)
        self.assertIn("argent-sentinel-watchdog.timer", postinst)
        self.assertIn("OnUnitActiveSec[[:space:]]*=[[:space:]]*5min", postinst)
        self.assertIn("unbound-watchdog\\.sh[[:space:]]*$", postinst)
        service = (
            ROOT / "packaging/systemd/argent-sentinel-watchdog.service"
        ).read_text()
        self.assertIn("User=root", service)
        self.assertIn("TimeoutStartSec=10min", service)
        self.assertIn("ReadWritePaths=/var/lib/argent-sentinel/watchdogs", service)


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0550.py
