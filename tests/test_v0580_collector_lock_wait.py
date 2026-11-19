#!/usr/bin/env python3
# tests/test_v0580_collector_lock_wait.py
"""Bounded wait for the shared collector lock (fix for nidhoggur ExecStartPre
migrate failures).

Production evidence (2026-11-17..19, nidhoggur): every one of 562 failed
argent-sentinel-collector / -report-batch starts happened while another
holder of /run/argent-sentinel/collector.lock was active; 538 of the 548
collector failures overlapped argent-sentinel-dashboard-snapshot, which holds
LOCK_SH for ~10-15 s every minute. ``migrate`` used LOCK_EX|LOCK_NB and exited
1 immediately, failing the unit before ExecStart. These tests reproduce that
overlap with a real second process and prove the bounded wait.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402

HOLDER = r"""
import fcntl, sys, time
mode = fcntl.LOCK_SH if sys.argv[2] == "sh" else fcntl.LOCK_EX
with open(sys.argv[1], "a+b") as handle:
    fcntl.flock(handle.fileno(), mode)
    print("held", flush=True)
    time.sleep(float(sys.argv[3]))
"""


class LockHolder:
    """A separate process holding the lock, like the dashboard snapshot."""

    def __init__(self, path: Path, mode: str, seconds: float) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", HOLDER, str(path), mode, str(seconds)],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline().strip()
        if line != "held":
            raise RuntimeError(f"lock holder failed to start: {line!r}")

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=10)


class ProcessLockWaitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.lock = self.root / "run" / "collector.lock"
        self.lock.parent.mkdir()
        self.lock.touch()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_zero_wait_keeps_fail_fast_behaviour(self) -> None:
        holder = LockHolder(self.lock, "sh", 5)
        try:
            started = time.monotonic()
            with self.assertRaises(collector.CollectorError) as caught:
                with collector.process_lock(self.lock):
                    pass
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual(str(caught.exception), collector.LOCK_BUSY_MESSAGE)
        finally:
            holder.stop()

    def test_waits_for_shared_reader_then_acquires(self) -> None:
        holder = LockHolder(self.lock, "sh", 1.0)
        try:
            started = time.monotonic()
            with collector.process_lock(self.lock, wait_seconds=10):
                elapsed = time.monotonic() - started
                # Prove we really own it: a non-blocking SH attempt must fail.
                with self.lock.open("a+b") as probe:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertGreaterEqual(elapsed, 0.5)
            self.assertLess(elapsed, 8.0)
        finally:
            holder.stop()

    def test_bounded_wait_still_reports_stuck_holder(self) -> None:
        holder = LockHolder(self.lock, "ex", 10)
        try:
            started = time.monotonic()
            with self.assertRaises(collector.CollectorError) as caught:
                with collector.process_lock(self.lock, wait_seconds=0.6):
                    pass
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 0.5)
            self.assertLess(elapsed, 3.0)
            self.assertEqual(str(caught.exception), collector.LOCK_BUSY_MESSAGE)
        finally:
            holder.stop()

    def test_lock_wait_seconds_validation(self) -> None:
        self.assertEqual(collector.lock_wait_seconds({"lock_wait_seconds": 45}), 45.0)
        self.assertEqual(collector.lock_wait_seconds({}), 0.0)
        for bad in (-1, 601, "45", True, None):
            with self.assertRaises(collector.CollectorError):
                collector.lock_wait_seconds({"lock_wait_seconds": bad})
        self.assertEqual(collector.DEFAULTS["lock_wait_seconds"], 45)


class MainCommandLockTests(unittest.TestCase):
    """Drive the real CLI entry point the systemd units use."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.lock = self.root / "run" / "collector.lock"
        self.lock.parent.mkdir()
        self.lock.touch()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_config(self, wait: float) -> Path:
        config = {
            "state_db": str(self.root / "state" / "state.sqlite3"),
            "lock_file": str(self.lock),
            "lock_wait_seconds": wait,
        }
        path = self.root / "collector.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def test_migrate_succeeds_while_snapshot_holds_shared_lock(self) -> None:
        config = self.write_config(10)
        holder = LockHolder(self.lock, "sh", 1.0)
        try:
            rc = collector.main(["--config", str(config), "migrate"])
        finally:
            holder.stop()
        self.assertEqual(rc, 0)
        self.assertTrue((self.root / "state" / "state.sqlite3").exists())

    def test_migrate_fail_fast_reproduces_production_failure(self) -> None:
        config = self.write_config(0)
        holder = LockHolder(self.lock, "sh", 5)
        try:
            rc = collector.main(["--config", str(config), "migrate"])
        finally:
            holder.stop()
        # This is the exact pre-fix behaviour seen as
        # "Control process exited, code=exited, status=1/FAILURE".
        self.assertEqual(rc, 1)

    def test_invalid_lock_wait_is_a_config_error(self) -> None:
        config = self.write_config(-5)
        self.assertEqual(collector.main(["--config", str(config), "validate-config"]), 1)


class ExampleAndUnitTests(unittest.TestCase):
    def test_example_config_documents_the_default(self) -> None:
        example = json.loads(
            (ROOT / "config/collector.json.example").read_text(encoding="utf-8")
        )
        self.assertEqual(example["lock_wait_seconds"], collector.DEFAULTS["lock_wait_seconds"])

    def test_units_keep_sandbox_and_schedule(self) -> None:
        # The fix is in the lock acquisition only: no sandbox relaxation and
        # no timer change to mask overlaps.
        unit = (ROOT / "packaging/systemd/argent-sentinel-collector.service").read_text()
        for directive in (
            "ProtectSystem=strict",
            "ProtectHome=true",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ExecStartPre=/usr/bin/argent-sentinel --config /etc/argent-sentinel/collector.json migrate",
        ):
            self.assertIn(directive, unit)
        timer = (ROOT / "packaging/systemd/argent-sentinel-collector.timer").read_text()
        self.assertIn("OnUnitActiveSec=1min", timer)

    def test_every_collector_lock_taker_uses_the_bounded_wait(self) -> None:
        for name in ("src/collector.py", "src/report_batcher.py"):
            text = (ROOT / name).read_text(encoding="utf-8")
            for line in text.splitlines():
                if "with process_lock(" in line:
                    self.assertIn("lock_wait_seconds(config)", line, f"{name}: {line.strip()}")


if __name__ == "__main__":
    unittest.main()

# EOF: tests/test_v0580_collector_lock_wait.py
