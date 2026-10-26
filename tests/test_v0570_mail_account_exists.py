#!/usr/bin/env python3
# tests/test_v0570_mail_account_exists.py
"""Mail account-existence classification, Postfix mail.log tail, and the
known-account vs account-probe policy split (0.5.7.0).

All fixtures are synthetic: example.org mailboxes, documentation addresses,
and fabricated journal/syslog lines. No real mailbox name belongs here.
"""

from __future__ import annotations

import base64
import datetime as dt
import email
from email import policy as email_policy
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import collector  # noqa: E402
import dashboard  # noqa: E402
import dashboard_snapshot  # noqa: E402
import review_digest  # noqa: E402

SECRET = b"e" * 32
NODE = "nidhoggur"
SITE = f"mail-{NODE}"
PORTS = {"smtp": 25, "submission": 587, "smtps": 465}
ALICE = "alice@example.org"
BOB = "bob@example.org"
PRIVATE_WORDS = ("account_exists", "failure_reason", "unknown_user", "bad_password",
                 "account_lookup", "nonexistent")
_counter = 0


def dovecot_line(account: str, source_ip: str, session: str | None = None) -> str:
    tail = f", session=<{session}>" if session else ""
    return (
        "imap-login: Disconnected (auth failed, 1 attempts in 2 secs): "
        f"user=<{account}>, method=PLAIN, rip={source_ip}, lip=203.0.113.25, TLS{tail}"
    )


def postfix_line(account: str | None, source_ip: str) -> str:
    user = f", sasl_username={account}" if account else ""
    return f"warning: unknown[{source_ip}]: SASL LOGIN authentication failed: UGFzc3dvcmQ6{user}"


def jrow(message: str, identifier: str = "dovecot", offset_seconds: int = 60) -> dict:
    global _counter
    _counter += 1
    return {
        "MESSAGE": message,
        "SYSLOG_IDENTIFIER": identifier,
        "__REALTIME_TIMESTAMP": str(int((time.time() - offset_seconds) * 1_000_000)),
        "__CURSOR": f"s=v0570;i={_counter};u={uuid.uuid4()}",
    }


class FakeResolver:
    """Stand-in for MailAccountResolver: a fixed name -> existence map."""

    def __init__(self, known: dict[str, bool | None]) -> None:
        self.known = {key.casefold(): value for key, value in known.items()}
        self.calls: list[str] = []

    def lookup(self, username):
        self.calls.append(username)
        value = self.known.get(str(username).casefold())
        return value, ("doveadm" if value is not None else None)

    def save(self) -> None:
        pass


def parse(item, resolver=None, hints=None):
    return agent.parse_mail_row(
        item, node_id=NODE, secret=SECRET, destination_ip="203.0.113.10",
        postfix_service_ports=PORTS, resolver=resolver, hints=hints,
    )


# ---------------------------------------------------------------------------
# Ingest classification
# ---------------------------------------------------------------------------

class ClassificationTest(unittest.TestCase):
    def test_existing_mailbox_is_known_bad_password(self) -> None:
        event = parse(jrow(dovecot_line(ALICE, "198.51.100.7")), FakeResolver({ALICE: True}))
        assert event is not None
        metadata = event["metadata"]
        self.assertIs(True, metadata["account_exists"])
        self.assertEqual("bad_password", metadata["failure_reason"])
        self.assertEqual("known", metadata["account_class"])
        self.assertEqual("doveadm", metadata["account_lookup"])
        self.assertNotIn(ALICE, json.dumps(event))

    def test_nonexistent_mailbox_is_invalid_unknown_user(self) -> None:
        event = parse(jrow(dovecot_line("ghost@example.org", "198.51.100.8")),
                      FakeResolver({"ghost@example.org": False}))
        assert event is not None
        self.assertIs(False, event["metadata"]["account_exists"])
        self.assertEqual("unknown_user", event["metadata"]["failure_reason"])
        self.assertEqual("invalid", event["metadata"]["account_class"])
        self.assertIn("account_key", event)  # still tokenised for probe counting

    def test_unresolved_keeps_pre_0570_class(self) -> None:
        for resolver in (None, FakeResolver({})):
            event = parse(jrow(dovecot_line(ALICE, "198.51.100.7")), resolver)
            assert event is not None
            self.assertIsNone(event["metadata"]["account_exists"])
            self.assertEqual("unknown", event["metadata"]["failure_reason"])
            self.assertEqual("submitted", event["metadata"]["account_class"])
            self.assertIsNone(event["metadata"]["account_lookup"])

    def test_postfix_sasl_is_classified_too(self) -> None:
        resolver = FakeResolver({ALICE: True, "ghost": False})
        known = parse(jrow(postfix_line(ALICE, "198.51.100.23"), "postfix/submission/smtpd"), resolver)
        ghost = parse(jrow(postfix_line("ghost", "198.51.100.24"), "postfix/smtpd"), resolver)
        anonymous = parse(jrow(postfix_line(None, "198.51.100.25"), "postfix/smtpd"), resolver)
        assert known and ghost and anonymous
        self.assertEqual(("known", True), (known["metadata"]["account_class"], known["metadata"]["account_exists"]))
        self.assertEqual(("invalid", False), (ghost["metadata"]["account_class"], ghost["metadata"]["account_exists"]))
        self.assertEqual("unresolved", anonymous["metadata"]["account_class"])
        self.assertIsNone(anonymous["metadata"]["account_exists"])
        self.assertEqual([ALICE, "ghost"], resolver.calls)  # no lookup without a name

    def test_empty_dovecot_user_is_not_looked_up(self) -> None:
        resolver = FakeResolver({})
        event = parse(jrow(dovecot_line("", "198.51.100.9")), resolver)
        assert event is not None
        self.assertEqual("empty", event["metadata"]["account_class"])
        self.assertEqual([], resolver.calls)

    def test_auth_verbose_session_and_account_ip_fallback(self) -> None:
        hints = agent.MailAuthVerboseHints()
        hints.add_row(jrow("auth: passwd-file(ghost@example.org,198.51.100.7,<S1>): unknown user"))
        hints.add_row(jrow("auth-worker(42): pam(alice@example.org,198.51.100.8,<S2>): "
                           "pam_authenticate() failed: Authentication failure (password mismatch?)"))
        hints.add_row(jrow("auth: sql(bob@example.org,198.51.100.9): Password mismatch"))
        by_session = parse(jrow(dovecot_line("ghost@example.org", "198.51.100.7", "S1")), None, hints)
        mismatch = parse(jrow(dovecot_line(ALICE, "198.51.100.8", "S2")), None, hints)
        smtp = parse(jrow(postfix_line(BOB, "198.51.100.9"), "postfix/smtpd"), None, hints)
        other_ip = parse(jrow(postfix_line(BOB, "198.51.100.99"), "postfix/smtpd"), None, hints)
        assert by_session and mismatch and smtp and other_ip
        self.assertEqual((False, "unknown_user", "auth_verbose"), (
            by_session["metadata"]["account_exists"], by_session["metadata"]["failure_reason"],
            by_session["metadata"]["account_lookup"]))
        self.assertEqual("bad_password", mismatch["metadata"]["failure_reason"])
        self.assertIs(True, smtp["metadata"]["account_exists"])
        self.assertIsNone(other_ip["metadata"]["account_exists"])

    def test_lookup_wins_over_hint(self) -> None:
        hints = agent.MailAuthVerboseHints()
        hints.add_row(jrow("auth: passwd-file(alice@example.org,198.51.100.7,<S>): unknown user"))
        event = parse(jrow(dovecot_line(ALICE, "198.51.100.7", "S")), FakeResolver({ALICE: True}), hints)
        assert event is not None
        self.assertEqual("doveadm", event["metadata"]["account_lookup"])

    def test_auth_detail_lines_never_become_events(self) -> None:
        for line in (
            "auth: passwd-file(ghost@example.org,198.51.100.7,<S1>): unknown user",
            "auth: sql(bob@example.org,198.51.100.9): Password mismatch",
        ):
            self.assertIsNone(parse(jrow(line)))


# ---------------------------------------------------------------------------
# Resolver backends, cache TTL, and DoS bounds
# ---------------------------------------------------------------------------

class ResolverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = agent.deep_merge(agent.DEFAULTS["mail"]["account_lookup"], {
            "cache_file": str(self.root / "cache.json"),
            "doveadm_path": "/usr/bin/doveadm",
        })

    def tearDown(self) -> None:
        self.temp.cleanup()

    def resolver(self, now: float, **overrides) -> agent.MailAccountResolver:
        return agent.MailAccountResolver(agent.deep_merge(self.settings, overrides), SECRET, NODE, now=now)

    @staticmethod
    def doveadm(codes: dict[str, int]):
        calls: list[list[str]] = []

        def run(command, **kwargs):
            calls.append(list(command))
            return subprocess.CompletedProcess(command, codes.get(command[-1], 75), stdout="", stderr="")
        return run, calls

    def test_doveadm_exit_codes(self) -> None:
        run, calls = self.doveadm({ALICE: 0, "ghost": agent.DOVEADM_EX_NOUSER})
        resolver = self.resolver(1000.0)
        with mock.patch.object(agent.subprocess, "run", side_effect=run):
            self.assertEqual((True, "doveadm"), resolver.lookup(ALICE))
            self.assertEqual((False, "doveadm"), resolver.lookup("ghost"))
            self.assertEqual((None, None), resolver.lookup("tempfail"))
        self.assertEqual(["/usr/bin/doveadm", "user", ALICE], calls[0])
        self.assertTrue(all("shell" not in str(call) for call in calls))

    def test_unsafe_names_are_never_looked_up(self) -> None:
        run, calls = self.doveadm({})
        resolver = self.resolver(1000.0)
        with mock.patch.object(agent.subprocess, "run", side_effect=run):
            for name in ("*", "a*", "us?r", "-A", "--help", "a b", "x\tUSER", "x\ny", "%u", "a" * 300):
                self.assertEqual((None, None), resolver.lookup(name))
        self.assertEqual([], calls)

    def test_ttl_cache_hits_then_expires(self) -> None:
        run, calls = self.doveadm({ALICE: 0, "ghost": agent.DOVEADM_EX_NOUSER})
        with mock.patch.object(agent.subprocess, "run", side_effect=run):
            first = self.resolver(1000.0, positive_ttl_seconds=600, negative_ttl_seconds=300)
            first.lookup(ALICE)
            first.lookup("ghost")
            self.assertEqual((True, "cache"), first.lookup(ALICE))
            first.save()
            self.assertEqual(2, len(calls))
            # New agent run within TTL: answered from the persisted cache.
            second = self.resolver(1200.0)
            self.assertEqual((True, "cache"), second.lookup(ALICE))
            self.assertEqual((False, "cache"), second.lookup("ghost"))
            self.assertEqual(2, len(calls))
            # Negative TTL (300 s) elapsed, positive (600 s) not yet.
            third = self.resolver(1350.0)
            self.assertEqual((True, "cache"), third.lookup(ALICE))
            self.assertEqual((False, "doveadm"), third.lookup("ghost"))
            self.assertEqual(3, len(calls))
            fourth = self.resolver(1700.0)
            self.assertEqual((True, "doveadm"), fourth.lookup(ALICE))
            self.assertEqual(4, len(calls))

    def test_errors_are_cached_briefly_as_null(self) -> None:
        run, calls = self.doveadm({})
        with mock.patch.object(agent.subprocess, "run", side_effect=run):
            resolver = self.resolver(1000.0, error_ttl_seconds=60)
            self.assertEqual((None, None), resolver.lookup(ALICE))
            self.assertEqual((None, None), resolver.lookup(ALICE))
            self.assertEqual(1, len(calls))
            resolver.save()
            later = self.resolver(1061.0)
            later.lookup(ALICE)
            self.assertEqual(2, len(calls))

    def test_cache_file_is_private_and_has_no_plaintext(self) -> None:
        run, _ = self.doveadm({ALICE: 0})
        with mock.patch.object(agent.subprocess, "run", side_effect=run):
            resolver = self.resolver(1000.0)
            resolver.lookup(ALICE)
            resolver.save()
        path = self.root / "cache.json"
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        text = path.read_text()
        self.assertNotIn("alice", text.lower())
        exported = agent.privacy_token(SECRET, NODE, ALICE, agent.MAIL_PRIVACY_DOMAIN)
        self.assertNotIn(exported, text)  # cache keys use a separate HMAC domain
        self.assertIn(agent.privacy_token(SECRET, NODE, ALICE, "mail-lookup"), text)

    def test_per_run_lookup_budget_and_cache_bound(self) -> None:
        run, calls = self.doveadm({f"u{index}": 0 for index in range(50)})
        with mock.patch.object(agent.subprocess, "run", side_effect=run):
            resolver = self.resolver(1000.0, max_lookups_per_run=5, max_cache_entries=3)
            results = [resolver.lookup(f"u{index}")[0] for index in range(10)]
            resolver.save()
        self.assertEqual([True] * 5 + [None] * 5, results)
        self.assertEqual(5, len(calls))
        entries = json.loads((self.root / "cache.json").read_text())["entries"]
        self.assertEqual(3, len(entries))

    def test_missing_backend_stops_for_the_run_without_caching(self) -> None:
        with mock.patch.object(agent.subprocess, "run", side_effect=FileNotFoundError("doveadm")) as run:
            resolver = self.resolver(1000.0)
            self.assertEqual((None, None), resolver.lookup(ALICE))
            self.assertEqual((None, None), resolver.lookup(BOB))
            resolver.save()
        self.assertEqual(1, run.call_count)
        self.assertFalse((self.root / "cache.json").exists())

    def test_timeout_is_null(self) -> None:
        with mock.patch.object(agent.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("doveadm", 2)):
            self.assertEqual((None, None), self.resolver(1000.0).lookup(ALICE))

    def test_disabled_or_none_backend_never_runs(self) -> None:
        with mock.patch.object(agent.subprocess, "run") as run:
            self.assertEqual((None, None), self.resolver(1000.0, enabled=False).lookup(ALICE))
            self.assertEqual((None, None), self.resolver(1000.0, backend="none").lookup(ALICE))
        run.assert_not_called()

    def test_auth_userdb_socket_protocol(self) -> None:
        path = str(self.root / "auth-userdb")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(4)
        received: list[str] = []

        def serve() -> None:
            for _ in range(2):
                connection, _ = server.accept()
                with connection:
                    connection.sendall(b"VERSION\t1\t1\nSPID\t1\n")
                    data = b""
                    while b"USER\t1\t" not in data or not data.endswith(b"\n"):
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    received.append(data.decode())
                    user = data.decode().split("USER\t1\t", 1)[1].split("\t", 1)[0]
                    reply = f"USER\t1\t{user}\tuid=1000\n" if user == ALICE else "NOTFOUND\t1\n"
                    connection.sendall(reply.encode())

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            resolver = self.resolver(1000.0, backend="auth-userdb", auth_userdb_socket=path)
            self.assertEqual((True, "auth-userdb"), resolver.lookup(ALICE))
            self.assertEqual((False, "auth-userdb"), resolver.lookup("ghost"))
        finally:
            thread.join(5)
            server.close()
        self.assertIn("service=argent-sentinel", received[0])

    def test_config_validation(self) -> None:
        base = agent.deep_merge(agent.DEFAULTS, {"node": {"id": NODE}})
        agent.validate_config(base)
        for override in (
            {"account_lookup": {"backend": "ldap"}},
            {"account_lookup": {"enabled": "yes"}},
            {"account_lookup": {"positive_ttl_seconds": -1}},
            {"account_lookup": {"timeout_seconds": 0}},
            {"account_lookup": {"doveadm_path": "doveadm"}},
            {"log_files": [{"path": "relative.log"}]},
            {"log_files": [{"path": "/var/log/mail.log", "components": ["exim"]}]},
            {"log_files": "/var/log/mail.log"},
            {"max_log_bytes_per_run": 10},
        ):
            with self.subTest(override=override), self.assertRaises(agent.AgentError):
                agent.validate_config(agent.deep_merge(base, {"mail": override}))

    def test_defaults_cover_postfix_file_and_example_matches(self) -> None:
        mail = agent.DEFAULTS["mail"]
        self.assertEqual([{"path": "/var/log/mail.log", "components": ["postfix"]}], mail["log_files"])
        self.assertTrue(mail["account_lookup"]["enabled"])
        self.assertEqual("doveadm", mail["account_lookup"]["backend"])
        example = json.loads((ROOT / "config/agent.json.example").read_text())
        self.assertEqual(mail, example["mail"])


# ---------------------------------------------------------------------------
# mail.log file tail with a durable cursor
# ---------------------------------------------------------------------------

def bsd_stamp(moment: dt.datetime) -> str:
    local = moment.astimezone()
    return f"{local.strftime('%b')} {local.day:2d} {local.strftime('%H:%M:%S')}"


class MailLogTailTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "mail.log"
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def line(self, account: str | None, source_ip: str, *, minutes_ago: int = 1,
             ident: str = "postfix/submission/smtpd", iso: bool = False) -> str:
        moment = self.now - dt.timedelta(minutes=minutes_ago)
        stamp = moment.astimezone().isoformat(timespec="microseconds") if iso else bsd_stamp(moment)
        return f"{stamp} nidhoggur {ident}[4242]: {postfix_line(account, source_ip)}\n"

    def read(self, state, **kwargs):
        options = {"components": ["postfix"], "max_bytes": 1 << 20, "initial_lookback_minutes": 5,
                   "now": self.now}
        options.update(kwargs)
        return agent.read_mail_log_file(self.log, state, **options)

    def test_syslog_formats_parse(self) -> None:
        bsd = agent.syslog_line_row(self.line(ALICE, "198.51.100.1").rstrip("\n"), "c1", self.now)
        iso = agent.syslog_line_row(self.line(ALICE, "198.51.100.1", iso=True).rstrip("\n"), "c2", self.now)
        assert bsd and iso
        for row in (bsd, iso):
            self.assertEqual("postfix/submission/smtpd", row["SYSLOG_IDENTIFIER"])
            occurred = int(row["__REALTIME_TIMESTAMP"]) / 1_000_000
            self.assertAlmostEqual((self.now - dt.timedelta(minutes=1)).timestamp(), occurred, delta=1)
        self.assertIsNone(agent.syslog_line_row("garbage", "c3", self.now))

    def test_year_rollover(self) -> None:
        january = dt.datetime(2027, 1, 1, 0, 5, tzinfo=dt.timezone.utc)
        december = dt.datetime(2026, 12, 31, 23, 50, tzinfo=dt.timezone.utc)
        line = f"{bsd_stamp(december)} host postfix/smtpd[1]: x"
        row = agent.syslog_line_row(line, "c", january)
        assert row is not None
        occurred = dt.datetime.fromtimestamp(int(row["__REALTIME_TIMESTAMP"]) / 1e6, dt.timezone.utc)
        self.assertEqual(december, occurred)

    def test_first_run_lookback_then_cursor_continues(self) -> None:
        self.log.write_text(
            self.line("old@example.org", "198.51.100.1", minutes_ago=90)
            + self.line(ALICE, "198.51.100.2", minutes_ago=2)
            + "Oct  1 00:00:00 nidhoggur postfix/smtpd[1]: connect from unknown[198.51.100.3]\n"
        )
        rows, state = self.read(None)
        self.assertEqual(1, len(rows))
        self.assertIn("198.51.100.2", rows[0]["MESSAGE"])
        self.assertEqual(self.log.stat().st_size, state["offset"])
        rows, state2 = self.read(state)
        self.assertEqual([], rows)
        with self.log.open("a") as handle:
            handle.write(self.line(BOB, "198.51.100.4"))
        rows, state3 = self.read(state2)
        self.assertEqual(1, len(rows))
        self.assertIn("198.51.100.4", rows[0]["MESSAGE"])
        self.assertGreater(state3["offset"], state2["offset"])

    def test_partial_line_waits_for_newline(self) -> None:
        self.log.write_text(self.line(ALICE, "198.51.100.5"))
        _, state = self.read(None)
        full = self.line(BOB, "198.51.100.6")
        with self.log.open("a") as handle:
            handle.write(full[:20])
        rows, state2 = self.read(state)
        self.assertEqual([], rows)
        self.assertEqual(state["offset"], state2["offset"])
        with self.log.open("a") as handle:
            handle.write(full[20:])
        rows, _ = self.read(state2)
        self.assertEqual(1, len(rows))

    def test_rename_rotation_finishes_old_file(self) -> None:
        self.log.write_text(self.line(ALICE, "198.51.100.7"))
        _, state = self.read(None)
        with self.log.open("a") as handle:
            handle.write(self.line(ALICE, "198.51.100.8"))  # written before rotation
        os.rename(self.log, self.root / "mail.log.1")
        self.log.write_text(self.line(BOB, "198.51.100.9"))
        rows, state2 = self.read(state)
        self.assertEqual(["198.51.100.8", "198.51.100.9"],
                         [row["MESSAGE"].split("[")[1].split("]")[0] for row in rows])
        self.assertEqual(self.log.stat().st_ino, state2["ino"])

    def test_copytruncate_restarts_at_zero(self) -> None:
        self.log.write_text(self.line(ALICE, "198.51.100.10") * 3)
        _, state = self.read(None)
        self.log.write_text(self.line(BOB, "198.51.100.11"))  # same inode, shorter
        rows, _ = self.read(state)
        self.assertEqual(1, len(rows))
        self.assertIn("198.51.100.11", rows[0]["MESSAGE"])

    def test_byte_budget_resumes_next_run(self) -> None:
        self.log.write_text("")
        _, state = self.read(None)
        lines = [self.line(f"u{index}@example.org", f"198.51.100.{20 + index}") for index in range(6)]
        with self.log.open("a") as handle:
            handle.writelines(lines)
        budget = len(lines[0]) * 2 + 10
        seen: list[dict] = []
        for _ in range(10):
            rows, state = self.read(state, max_bytes=budget)
            seen.extend(rows)
            if state["offset"] >= self.log.stat().st_size:
                break
        self.assertEqual(6, len(seen))
        self.assertEqual(6, len({row["__CURSOR"] for row in seen}))

    def test_only_configured_components_are_read(self) -> None:
        dovecot = f"{bsd_stamp(self.now)} nidhoggur dovecot[7]: {dovecot_line(ALICE, '198.51.100.30')}\n"
        self.log.write_text(dovecot + self.line(BOB, "198.51.100.31"))
        rows, _ = self.read(None)
        self.assertEqual(["postfix/submission/smtpd"], [row["SYSLOG_IDENTIFIER"] for row in rows])
        rows, _ = self.read(None, components=["postfix", "dovecot"])
        self.assertEqual(2, len(rows))

    def test_missing_file_keeps_cursor(self) -> None:
        rows, state = self.read({"dev": 1, "ino": 2, "offset": 3})
        self.assertEqual([], rows)
        self.assertEqual({"dev": 1, "ino": 2, "offset": 3}, state)

    def test_event_identity_is_stable_per_file_offset(self) -> None:
        self.log.write_text(self.line(ALICE, "198.51.100.40"))
        first, _ = self.read(None)
        again, _ = self.read(None)
        self.assertEqual(first[0]["__CURSOR"], again[0]["__CURSOR"])
        self.assertEqual(parse(first[0])["event_uuid"], parse(again[0])["event_uuid"])


class CollectMailTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "privacy.key").write_bytes(SECRET)
        self.log = self.root / "mail.log"
        self.config = agent.deep_merge(agent.DEFAULTS, {
            "node": {"id": NODE, "fqdn": "nidhoggur.example"},
            "pending_dir": str(self.root / "pending"),
            "mail": {
                "enabled": True,
                "privacy_key_file": str(self.root / "privacy.key"),
                "cursor_file": str(self.root / "mail.cursor"),
                "log_cursor_file": str(self.root / "mail-log.cursor"),
                "log_files": [{"path": str(self.log), "components": ["postfix"]}],
                "account_lookup": {"enabled": False},
            },
        })
        agent.validate_config(self.config)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def journal(self, *rows: dict) -> subprocess.CompletedProcess:
        lines = [json.dumps(item) for item in rows] + ["-- cursor: s=final"]
        return subprocess.CompletedProcess([], 0, stdout="\n".join(lines) + "\n", stderr="")

    def batches(self) -> list[dict]:
        result = []
        for path in sorted((self.root / "pending").glob("*.json")):
            envelope = json.loads(path.read_text())
            result.append(json.loads(base64.b64decode(envelope["payload_b64"])
                                     if "payload_b64" in envelope else envelope["payload"]))
        return result

    def test_postfix_from_file_and_journal_postfix_not_double_counted(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        self.log.write_text(
            f"{bsd_stamp(now)} nidhoggur postfix/submission/smtpd[9]: {postfix_line(ALICE, '198.51.100.50')}\n"
        )
        completed = self.journal(
            jrow(dovecot_line(BOB, "198.51.100.51")),
            jrow(postfix_line(ALICE, "198.51.100.50"), "postfix/submission/smtpd"),
        )
        with mock.patch.object(agent.subprocess, "run", return_value=completed):
            total = agent.collect_mail(self.config)
        self.assertEqual(2, total)  # dovecot from journal + postfix once (file)
        cursor = json.loads((self.root / "mail-log.cursor").read_text())
        self.assertEqual(self.log.stat().st_size, cursor["files"][str(self.log)]["offset"])
        self.assertEqual("s=final\n", (self.root / "mail.cursor").read_text())
        with mock.patch.object(agent.subprocess, "run", return_value=self.journal()):
            self.assertEqual(0, agent.collect_mail(self.config))

    def test_journal_postfix_kept_when_file_absent(self) -> None:
        completed = self.journal(jrow(postfix_line(ALICE, "198.51.100.52"), "postfix/smtpd"))
        with mock.patch.object(agent.subprocess, "run", return_value=completed):
            self.assertEqual(1, agent.collect_mail(self.config))

    def test_cursor_not_advanced_when_staging_fails(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        self.log.write_text(
            f"{bsd_stamp(now)} nidhoggur postfix/smtpd[9]: {postfix_line(ALICE, '198.51.100.53')}\n"
        )
        with mock.patch.object(agent.subprocess, "run", return_value=self.journal()), \
                mock.patch.object(agent, "save_envelope", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                agent.collect_mail(self.config)
        self.assertFalse((self.root / "mail-log.cursor").exists())


# ---------------------------------------------------------------------------
# Collector policy split + dashboard + privacy
# ---------------------------------------------------------------------------

class CscliRecorder:
    def __init__(self) -> None:
        self.decisions: list[list[str]] = []

    def __call__(self, command, **kwargs):
        if command[1:3] == ["allowlists", "check"]:
            return subprocess.CompletedProcess(command, 1, stdout="not allowlisted", stderr="")
        if command[1:3] == ["decisions", "add"]:
            self.decisions.append(list(command))
            return subprocess.CompletedProcess(command, 0, stdout="Decision successfully added", stderr="")
        raise AssertionError(f"unexpected subprocess call: {command}")


class PolicySplitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "agent-privacy.key"
        self.key.write_bytes(SECRET)
        self.incoming = self.root / "drop" / "remote" / NODE / "events" / "incoming"
        self.incoming.mkdir(parents=True)
        self.agent_config = agent.deep_merge(agent.DEFAULTS, {
            "node": {"id": NODE, "fqdn": "nidhoggur.example"},
            "mail": {"privacy_key_file": str(self.key), "max_events_per_batch": 500},
        })
        self.instances: list[collector.Collector] = []
        existing = {f"ghost{index}@example.org": False for index in range(20)}
        existing.update({ALICE: True, BOB: True})
        self.resolver = FakeResolver(existing)

    def tearDown(self) -> None:
        for instance in self.instances:
            instance.close()
        self.temp.cleanup()

    def config(self, **mail_policy) -> dict:
        policy = {"enabled": True, "crowdsec_enforcement": True, "privacy_key_file": str(self.key)}
        policy.update(mail_policy)
        config = collector.deep_merge(collector.DEFAULTS, {
            "state_db": str(self.root / "state.sqlite3"),
            "lock_file": str(self.root / "collector.lock"),
            "incoming_globs": [str(self.root / "drop/remote/*/events/incoming/*.json")],
            "processing_dir": str(self.root / "processing"),
            "archive_dir": str(self.root / "archive"),
            "rejected_dir": str(self.root / "rejected"),
            "node": {"id": NODE},
            "crowdsec": {"enabled": True, "cscli_path": "/usr/bin/cscli"},
            "enrichment": {"enabled": False},
            "abuse_reporting": {"enabled": False},
            "mail_account_policy": policy,
        })
        collector.validate_config(config)
        return config

    def deliver(self, rows: list[dict], resolver=None) -> None:
        for batch in agent.build_mail_batches(self.agent_config, rows, resolver=resolver or self.resolver):
            (self.incoming / f"{uuid.uuid4()}-mail.json").write_text(json.dumps(batch))

    def run_collector(self, config: dict):
        instance = collector.Collector(config)
        self.instances.append(instance)
        recorder = CscliRecorder()
        with mock.patch.object(collector.subprocess, "run", side_effect=recorder):
            instance.run()
        return instance, recorder

    @staticmethod
    def incidents(instance) -> list[sqlite3.Row]:
        return instance.db.conn.execute("SELECT * FROM incidents ORDER BY rule_id, source_ip").fetchall()

    def probe_rows(self, source_ip: str, accounts: int, offset: int = 3000) -> list[dict]:
        return [jrow(dovecot_line(f"ghost{index}@example.org", source_ip), offset_seconds=offset + index * 60)
                for index in range(accounts)]

    def known_rows(self, account: str, ips: list[str], per_ip: int) -> list[dict]:
        return [jrow(dovecot_line(account, ip), offset_seconds=60000 - n * 3000 - k * 600)
                for n, ip in enumerate(ips) for k in range(per_ip)]

    def test_defaults_and_example(self) -> None:
        defaults = collector.DEFAULTS["mail_account_policy"]
        self.assertTrue(defaults["probe_enabled"])
        self.assertFalse(defaults["probe_crowdsec_enforcement"])
        self.assertFalse(defaults["probe_abuse_reporting_enabled"])
        self.assertEqual((86400, 5, 5, 3, "72h"), (
            defaults["probe_window_seconds"], defaults["probe_distinct_accounts"],
            defaults["probe_failure_threshold"], defaults["probe_review_distinct_accounts"],
            defaults["probe_ban_duration"]))
        example = json.loads((ROOT / "config/collector.json.example").read_text())
        self.assertEqual(defaults, example["mail_account_policy"])

    def test_validation(self) -> None:
        for override in ({"probe_crowdsec_enforcement": "false"}, {"probe_distinct_accounts": 1},
                         {"probe_ban_duration": "forever"}, {"probe_window_seconds": 0}):
            with self.subTest(override=override), self.assertRaises(collector.CollectorError):
                self.config(**override)

    def test_known_account_slow_burn_still_enforces(self) -> None:
        ips = [f"45.155.205.{10 + index}" for index in range(5)]
        self.deliver(self.known_rows(ALICE, ips, 2))
        instance, recorder = self.run_collector(self.config())
        incidents = self.incidents(instance)
        self.assertEqual({"mail-account-slow-burn"}, {row["rule_id"] for row in incidents})
        self.assertEqual(5, len(recorder.decisions))
        campaign = instance.db.mail_campaigns()[0]
        self.assertEqual(("known", "Valid mailbox attack", "enforcing"),
                         (campaign["campaign_kind"], campaign["campaign_label"], campaign["status"]))

    def test_unknown_existence_keeps_current_behaviour(self) -> None:
        ips = [f"45.155.205.{10 + index}" for index in range(5)]
        self.deliver(self.known_rows("carol@example.org", ips, 2), resolver=FakeResolver({}))
        instance, recorder = self.run_collector(self.config())
        self.assertEqual(5, len(self.incidents(instance)))
        self.assertEqual("unresolved", instance.db.mail_campaigns()[0]["campaign_kind"])

    def test_nonexistent_accounts_never_feed_account_campaigns(self) -> None:
        # Ten IPs each try the same nonexistent mailbox twice: under 0.5.6.x
        # this was an account slow-burn; now it is per-IP probe evidence only.
        ips = [f"45.155.205.{10 + index}" for index in range(10)]
        self.deliver([jrow(dovecot_line("ghost0@example.org", ip), offset_seconds=1000 + n)
                      for n, ip in enumerate(ips) for _ in range(2)])
        instance, recorder = self.run_collector(self.config())
        self.assertEqual([], self.incidents(instance))  # 1 distinct account < probe threshold
        self.assertEqual([], recorder.decisions)
        self.assertEqual([], [c for c in instance.db.mail_campaigns() if c["campaign_kind"] in {"known", "unresolved"}])

    def test_probe_rule_is_per_source_ip_and_dry_run_by_default(self) -> None:
        self.deliver(self.probe_rows("198.51.100.66", 6) + self.probe_rows("198.51.100.67", 2))
        instance, recorder = self.run_collector(self.config())  # crowdsec_enforcement on
        incidents = self.incidents(instance)
        self.assertEqual([("mail-account-probe", "198.51.100.66")],
                         [(row["rule_id"], row["source_ip"]) for row in incidents])
        self.assertEqual("dry-run", incidents[0]["decision_status"])
        self.assertIn("probe_crowdsec_enforcement is false", incidents[0]["decision_detail"])
        self.assertEqual("suppressed", incidents[0]["report_status"])
        self.assertEqual([], recorder.decisions)
        campaign = instance.db.mail_campaigns()[0]
        self.assertEqual(("probe", "Account probing", 6, "198.51.100.66"), (
            campaign["campaign_kind"], campaign["campaign_label"],
            campaign["distinct_accounts"], campaign["source_ip"]))

    def test_probe_enforcement_gate_and_duration(self) -> None:
        self.deliver(self.probe_rows("45.155.205.68", 5))
        instance, recorder = self.run_collector(self.config(probe_crowdsec_enforcement=True,
                                                            crowdsec_enforcement=False))
        self.assertEqual(1, len(recorder.decisions))
        command = recorder.decisions[0]
        self.assertEqual("45.155.205.68", command[command.index("--ip") + 1])
        self.assertEqual("72h", command[command.index("--duration") + 1])
        self.assertTrue(command[command.index("--reason") + 1].endswith("/mail-account-probe"))
        joined = " ".join(command).lower()
        for word in PRIVATE_WORDS:
            self.assertNotIn(word, joined)

    def test_probe_disabled(self) -> None:
        self.deliver(self.probe_rows("198.51.100.69", 8))
        instance, _ = self.run_collector(self.config(probe_enabled=False))
        self.assertEqual([], self.incidents(instance))

    def test_mixed_kind_and_known_first_ordering(self) -> None:
        rows = self.probe_rows("198.51.100.70", 5) + [jrow(dovecot_line(BOB, "198.51.100.70"))]
        rows += self.known_rows(ALICE, [f"45.155.205.{10 + index}" for index in range(5)], 2)
        self.deliver(rows)
        instance, _ = self.run_collector(self.config())
        kinds = [item["campaign_kind"] for item in instance.db.mail_campaigns()]
        self.assertEqual("known", kinds[0])
        self.assertIn("mixed", kinds)
        mixed = next(item for item in instance.db.mail_campaigns() if item["campaign_kind"] == "mixed")
        self.assertEqual(1, mixed["known_failures"])
        self.assertEqual(5, mixed["probe_failures"])

    def test_schema_migration_adds_columns(self) -> None:
        path = self.root / "old.sqlite3"
        connection = sqlite3.connect(path)
        connection.execute("""CREATE TABLE mail_account_campaigns (
            site_id TEXT NOT NULL, account_key TEXT NOT NULL, campaign_id TEXT NOT NULL UNIQUE,
            protected INTEGER NOT NULL DEFAULT 0, protected_label TEXT, status TEXT NOT NULL,
            failures INTEGER NOT NULL, distinct_source_ips INTEGER NOT NULL,
            enforced_source_ips INTEGER NOT NULL DEFAULT 0, failure_threshold INTEGER NOT NULL,
            distinct_ip_threshold INTEGER NOT NULL, window_seconds INTEGER NOT NULL,
            first_seen_epoch INTEGER NOT NULL, last_seen_epoch INTEGER NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, protocols TEXT,
            sample_source_ips_json TEXT NOT NULL DEFAULT '[]',
            prefix_proposals_json TEXT NOT NULL DEFAULT '[]',
            asn_summary_json TEXT NOT NULL DEFAULT '[]',
            automatic_block INTEGER NOT NULL DEFAULT 0, review_status TEXT NOT NULL DEFAULT 'open',
            updated_at TEXT NOT NULL, PRIMARY KEY (site_id, account_key))""")
        connection.commit()
        connection.close()
        db = collector.StateDB(path)
        try:
            columns = {row[1] for row in db.conn.execute("PRAGMA table_info(mail_account_campaigns)")}
        finally:
            db.close()
        self.assertTrue({"campaign_kind", "source_ip", "distinct_accounts",
                         "known_failures", "probe_failures"} <= columns)

    def snapshot(self, config: dict) -> dict:
        config_path = self.root / "collector.json"
        config_path.write_text(json.dumps(config))
        snapshot_config = dashboard_snapshot.deep_merge(dashboard_snapshot.DEFAULTS, {
            "state_db": config["state_db"],
            "collector_config": str(config_path),
            "report_batch_state_file": str(self.root / "batch.json"),
            "lock_file": str(self.root / "snapshot.lock"),
            "traffic_sites_config": str(self.root / "sites.json"),
            "awstats_root": str(self.root / "awstats"),
            "watchdog_state_dir": str(self.root / "watchdogs"),
        })
        return dashboard_snapshot.build_snapshot(snapshot_config)

    def test_dashboard_mail_page_and_overview(self) -> None:
        rows = self.probe_rows("198.51.100.71", 5)
        rows += self.known_rows(ALICE, [f"45.155.205.{10 + index}" for index in range(5)], 2)
        rows.append(jrow(dovecot_line("carol@example.org", "198.51.100.72")))
        self.deliver(rows, resolver=FakeResolver({**self.resolver.known, "carol@example.org": None}))
        config = self.config()
        self.run_collector(config)
        snapshot = self.snapshot(config)
        overview = snapshot["overview"]
        self.assertEqual((16, 10, 5, 1), (
            overview["mail_auth_failures"], overview["mail_auth_failures_known"],
            overview["mail_auth_failures_nonexistent"], overview["mail_auth_failures_unresolved"]))
        self.assertEqual(1, overview["mail_known_account_campaigns"])
        self.assertEqual(1, overview["mail_probe_campaigns"])
        self.assertEqual("known", snapshot["mail_account_campaigns"][0]["campaign_kind"])
        recent = {(item["account_exists"], item["failure_reason"]) for item in snapshot["recent_mail_auth_failures"]}
        self.assertEqual({(True, "bad_password"), (False, "unknown_user"), (None, "unknown")}, recent)
        grouped = next(item for item in snapshot["mail_auth_failures"] if item["source_ip"] == "198.51.100.71")
        self.assertEqual((5, 0, 5), (grouped["nonexistent_failures"], grouped["known_failures"],
                                     grouped["nonexistent_accounts"]))
        page = dashboard.render_mail(snapshot)
        for text in ("Valid mailbox attack", "Account probing", "<th>Exists</th>", "<th>Reason</th>",
                     "unknown_user", "bad_password", "Nonexistent account (unknown user)",
                     "Probe CrowdSec enforcement"):
            self.assertIn(text, page)
        self.assertLess(page.index("Valid mailbox attack</td>"), page.index("Account probing</td>"))
        overview_html = dashboard.render_overview(snapshot)
        self.assertIn("Valid mailbox failures", overview_html)
        self.assertIn("Nonexistent-account probes", overview_html)
        text = json.dumps(snapshot, default=str).lower() + page.lower()
        for name in (ALICE, "ghost0@example.org", "carol@example.org"):
            self.assertNotIn(name, text)

    def test_digest_leads_with_known_attacks_and_is_aggregate(self) -> None:
        rows = self.probe_rows("198.51.100.73", 5)
        rows += self.known_rows(ALICE, [f"45.155.205.{10 + index}" for index in range(5)], 2)
        self.deliver(rows)
        config = self.config()
        self.run_collector(config)
        connection = sqlite3.connect(config["state_db"])
        connection.row_factory = sqlite3.Row
        now = int(time.time())
        digest = review_digest.render_digest(
            {"daily_review": {"max_rows": 20, "max_network_rows": 20}}, connection, now - 86400, now + 60,
        )
        connection.close()
        summary = digest.index("Mail attacks (valid mailbox attacks first")
        self.assertLess(summary, digest.index("HTTP 429 pressure"))
        self.assertIn("Valid mailbox attack: 1 campaign(s), 10 failure(s)", digest)
        self.assertIn("Account probing: 1 campaign(s), 5 failure(s)", digest)
        self.assertLess(digest.index("Kind: Valid mailbox attack"), digest.index("Kind: Account probing"))
        lowered = digest.lower()
        for word in ("account_exists", "failure_reason", "unknown_user", "bad_password", "alice", "ghost"):
            self.assertNotIn(word, lowered)

    def test_abuse_report_and_xarf_exclude_existence(self) -> None:
        self.deliver(self.probe_rows("45.155.205.90", 6))
        config = self.config()
        instance, _ = self.run_collector(config)
        incident = instance.db.conn.execute(
            "SELECT * FROM incidents WHERE rule_id = 'mail-account-probe'").fetchone()
        self.assertIsNotNone(incident)
        # Stored evidence does carry the classification (local DB / dashboard).
        evidence = instance.db.incident_evidence(str(incident["incident_uuid"]))
        self.assertIn("account_exists", str(evidence[0]["metadata_json"]))
        self.assertNotIn("account_exists", instance._report_metadata(evidence[0]))
        instance.config["abuse_reporting"].update({
            "enabled": True, "test_mode": True, "from": "sentinel@example.net",
            "recipient_override": "abuse-test@example.net", "resolve_target_dns": False,
            "resolve_source_rdns": False,
        })
        enrichment = {"network_cidr": "45.155.205.0/24", "network_name": "test", "asn": 64500,
                      "asn_holder": "EXAMPLE-AS", "abuse_emails": [], "network_class": "hosting"}
        payloads: list[bytes] = []

        def fake_run(command, **kwargs):
            if "input" in kwargs:
                payloads.append(kwargs["input"])
                return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
            return CscliRecorder()(command, **kwargs)

        with mock.patch.object(collector.subprocess, "run", side_effect=fake_run):
            status, _, _ = instance.send_abuse_report(incident, enrichment, ["abuse-test@example.net"])
        self.assertEqual("sent", status)
        message = email.message_from_string(payloads[-1].decode("utf-8", "replace"), policy=email_policy.default)
        decoded = []
        for part in message.walk():
            if part.is_multipart():
                continue
            content = part.get_content()
            decoded.append(content if isinstance(content, str) else content.decode("utf-8", "replace"))
        text = "\n".join(decoded).lower()
        self.assertIn("login_attack", text)
        # ("unknown" legitimately appears as dst="unknown", so match whole classes.)
        for word in PRIVATE_WORDS + ("ghost", '"invalid"', '"known"', "account_class"):
            with self.subTest(word=word):
                self.assertNotIn(word, text)

    def test_server_responses_untouched_by_design(self) -> None:
        # The agent only reads logs and queries userdb; it never writes Dovecot
        # or Postfix configuration and never enables auth_verbose_passwords.
        source = (ROOT / "src" / "agent.py").read_text()
        self.assertNotIn("auth_verbose_passwords =", source)
        self.assertNotIn("auth_failure_delay =", source)
        self.assertNotIn("doveadm reload", source)
        self.assertNotIn("postconf -e", source)


class VersionTest(unittest.TestCase):
    def test_release_version(self) -> None:
        self.assertEqual("0.5.7.0", (ROOT / "VERSION").read_text().strip())
        for module in (agent, collector, dashboard, dashboard_snapshot, review_digest):
            self.assertEqual("0.5.7.0", module.APP_VERSION)


if __name__ == "__main__":
    unittest.main()
# EOF tests/test_v0570_mail_account_exists.py
