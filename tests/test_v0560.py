#!/usr/bin/env python3
"""Regression coverage for observe-only mail authentication ingest in 0.5.6.0.

Sample journal rows below reproduce common Dovecot 2.2/2.3/2.4 login-process
and Postfix smtpd SASL failure formats.  Account names in fixtures must never
appear in exported events.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import collector  # noqa: E402
import server_api  # noqa: E402

SECRET = b"k" * 32
NODE = "nidhoggur"
PORTS = {"smtp": 25, "submission": 587, "smtps": 465}

_counter = 0


def row(message, identifier="dovecot", cursor=None):
    global _counter
    _counter += 1
    return {
        "MESSAGE": message,
        "SYSLOG_IDENTIFIER": identifier,
        "__REALTIME_TIMESTAMP": "1792990000000000",
        "__CURSOR": cursor or f"s=mailtest;i={_counter}",
    }


def parse(item, destination_ip="203.0.113.10"):
    return agent.parse_mail_row(
        item,
        node_id=NODE,
        secret=SECRET,
        destination_ip=destination_ip,
        postfix_service_ports=PORTS,
    )


DOVECOT_FAILURES = [
    # Dovecot 2.2 disconnect summary.
    (
        "imap-login: Disconnected (auth failed, 3 attempts in 12 secs): "
        "user=<alice@example.org>, method=PLAIN, rip=198.51.100.7, "
        "lip=203.0.113.25, TLS, session=<AbCdEf123>",
        "imap", 3, "alice@example.org",
    ),
    # Dovecot 2.3 disconnect with reason.
    (
        "imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): "
        "user=<bob@example.org>, method=LOGIN, rip=198.51.100.8, lip=203.0.113.25, "
        "TLS, session=<XyZ>",
        "imap", 1, "bob@example.org",
    ),
    # Aborted login form.
    (
        "pop3-login: Aborted login (auth failed, 1 attempts in 6 secs): "
        "user=<admin>, method=PLAIN, rip=198.51.100.9, lip=203.0.113.25, session=<q>",
        "pop3", 1, "admin",
    ),
    # Dovecot 2.3.x/2.4 "Login aborted" with reason code and ports.
    (
        "imap-login: Login aborted: Connection closed (auth failed, 2 attempts in 4 secs) "
        "(auth_failed): user=<carol@example.org>, method=PLAIN, rip=198.51.100.10, "
        "lip=203.0.113.25, rport=51234, lport=993, TLS, session=<s>",
        "imap", 2, "carol@example.org",
    ),
    # stderr-to-journal style with level prefix, submission login process.
    (
        "submission-login: Info: Disconnected: Connection closed "
        "(auth failed, 1 attempts in 3 secs): user=<dave@example.org>, "
        "method=PLAIN, rip=198.51.100.11, lip=203.0.113.25, TLS",
        "submission", 1, "dave@example.org",
    ),
]

POSTFIX_FAILURES = [
    (
        "warning: unknown[198.51.100.23]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
        "postfix/smtpd", "smtp", 25, "LOGIN", "password", None,
    ),
    (
        "warning: host.example.net[198.51.100.24]: SASL PLAIN authentication failed: "
        "UGFzc3dvcmQ6, sasl_username=Alice@Example.org",
        "postfix/submission/smtpd", "submission", 587, "PLAIN", "password",
        "Alice@Example.org",
    ),
    (
        "warning: unknown[2001:db8::23]: SASL LOGIN authentication failed: "
        "authentication failure",
        "postfix/smtps/smtpd", "smtps", 465, "LOGIN", "other", None,
    ),
    (
        "warning: unknown[198.51.100.25]: SASL PLAIN authentication failed: ",
        "postfix-out/submission/smtpd", "submission", 587, "PLAIN", "none", None,
    ),
]

IGNORED = [
    ("imap-login: Disconnected (no auth attempts in 0 secs): user=<>, rip=198.51.100.7, lip=203.0.113.25", "dovecot"),
    ("imap-login: Login: user=<alice@example.org>, method=PLAIN, rip=198.51.100.7, lip=203.0.113.25, mpid=1, TLS", "dovecot"),
    ("auth-worker(1234): pam(alice@example.org,198.51.100.7,<s>): pam_authenticate() failed: Authentication failure (password mismatch?)", "dovecot"),
    ("auth: passwd-file(eve@example.org,198.51.100.7,<s>): unknown user", "dovecot"),
    ("imap-login: Disconnected (tried to use disallowed plaintext auth): user=<>, rip=198.51.100.7", "dovecot"),
    ("lost connection after AUTH from unknown[198.51.100.23]", "postfix/smtpd"),
    ("disconnect from unknown[198.51.100.23] ehlo=1 auth=0/1 quit=1 commands=2/3", "postfix/smtpd"),
    ("warning: unknown[198.51.100.23]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "postfix/qmgr"),
    ("imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<x>, method=PLAIN, rip=not-an-ip", "dovecot"),
]


class MailParserTest(unittest.TestCase):
    def test_dovecot_failures(self) -> None:
        for message, protocol, attempts, username in DOVECOT_FAILURES:
            with self.subTest(message=message):
                event = parse(row(message))
                self.assertIsNotNone(event)
                assert event is not None
                self.assertEqual("mail_auth_failed", event["event_type"])
                self.assertEqual("denied", event["outcome"])
                self.assertEqual(protocol.upper(), event["application_protocol"])
                self.assertEqual("TCP", event["transport_protocol"])
                self.assertEqual("dovecot", event["metadata"]["mail_component"])
                self.assertEqual(protocol, event["metadata"]["protocol"])
                self.assertEqual(attempts, event["metadata"]["attempts"])
                self.assertEqual("submitted", event["metadata"]["account_class"])
                self.assertEqual("203.0.113.25", event["destination_ip"])
                self.assertEqual(
                    agent.privacy_token(SECRET, NODE, username, "mail"),
                    event["account_key"],
                )
                self.assertNotIn(username.casefold(), json.dumps(event).casefold())

    def test_dovecot_ports_and_tls_when_logged(self) -> None:
        event = parse(row(DOVECOT_FAILURES[3][0]))
        assert event is not None
        self.assertEqual(51234, event["source_port"])
        self.assertEqual(993, event["destination_port"])
        self.assertTrue(event["metadata"]["tls"])
        no_tls = parse(row(DOVECOT_FAILURES[2][0]))
        assert no_tls is not None
        self.assertIsNone(no_tls["destination_port"])
        self.assertFalse(no_tls["metadata"]["tls"])

    def test_dovecot_empty_user_and_mapped_ipv4(self) -> None:
        event = parse(row(
            "imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<>, "
            "method=PLAIN, rip=::ffff:198.51.100.40, session=<z>"
        ))
        assert event is not None
        self.assertEqual("198.51.100.40", event["source_ip"])
        self.assertEqual("empty", event["metadata"]["account_class"])
        self.assertNotIn("account_key", event)
        # No lip= logged: fall back to the configured destination address.
        self.assertEqual("203.0.113.10", event["destination_ip"])

    def test_postfix_sasl_failures(self) -> None:
        for message, ident, service, port, mech, stage, username in POSTFIX_FAILURES:
            with self.subTest(message=message):
                event = parse(row(message, ident))
                self.assertIsNotNone(event)
                assert event is not None
                self.assertEqual("mail_auth_failed", event["event_type"])
                self.assertEqual("SMTP", event["application_protocol"])
                self.assertEqual("postfix", event["metadata"]["mail_component"])
                self.assertEqual(service, event["metadata"]["postfix_service"])
                self.assertEqual(mech, event["metadata"]["auth_mechanism"])
                self.assertEqual(stage, event["metadata"]["sasl_stage"])
                self.assertEqual(port, event["destination_port"])
                self.assertEqual("203.0.113.10", event["destination_ip"])
                self.assertIsNone(event["source_port"])
                if username:
                    self.assertEqual("submitted", event["metadata"]["account_class"])
                    self.assertNotIn(username.casefold(), json.dumps(event).casefold())
                else:
                    self.assertEqual("unresolved", event["metadata"]["account_class"])
                    self.assertNotIn("account_key", event)
                self.assertNotIn("UGFzc3dvcmQ6", json.dumps(event))
        ipv6 = parse(row(POSTFIX_FAILURES[2][0], POSTFIX_FAILURES[2][1]))
        assert ipv6 is not None
        self.assertEqual("2001:db8::23", ipv6["source_ip"])

    def test_ignored_lines(self) -> None:
        for message, ident in IGNORED:
            with self.subTest(message=message):
                self.assertIsNone(parse(row(message, ident)))

    def test_same_mailbox_shares_token_across_imap_and_smtp(self) -> None:
        imap = parse(row(DOVECOT_FAILURES[0][0]))
        smtp = parse(row(POSTFIX_FAILURES[1][0], POSTFIX_FAILURES[1][1]))
        assert imap is not None and smtp is not None
        self.assertEqual(imap["account_key"], smtp["account_key"])
        # Mail tokens are domain-separated from OpenSSH tokens.
        self.assertNotEqual(
            agent.privacy_token(SECRET, NODE, "alice@example.org"),
            imap["account_key"],
        )
        # Existing sshd tokens are unchanged by the domain parameter.
        self.assertEqual(
            agent.privacy_token(SECRET, NODE, "root"),
            agent.privacy_token(SECRET, NODE, "root", "sshd"),
        )

    def test_event_uuid_is_stable_per_cursor(self) -> None:
        first = parse(row(DOVECOT_FAILURES[0][0], cursor="s=fixed"))
        second = parse(row(DOVECOT_FAILURES[0][0], cursor="s=fixed"))
        assert first is not None and second is not None
        self.assertEqual(first["event_uuid"], second["event_uuid"])

    def test_byte_array_message(self) -> None:
        message = DOVECOT_FAILURES[0][0].encode()
        item = row("")
        item["MESSAGE"] = list(message)
        self.assertIsNotNone(parse(item))


class MailAgentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        key = self.root / "privacy.key"
        key.write_bytes(SECRET)
        self.config = agent.deep_merge(agent.DEFAULTS, {
            "node": {"id": NODE, "fqdn": "nidhoggur.example"},
            "pending_dir": str(self.root / "pending"),
            "mail": {
                "enabled": True,
                "privacy_key_file": str(key),
                "cursor_file": str(self.root / "mail.cursor"),
                "destination_ip": "203.0.113.10",
                "max_events_per_batch": 2,
            },
        })
        agent.validate_config(self.config)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_defaults_are_disabled_and_examples_match(self) -> None:
        self.assertFalse(agent.DEFAULTS["mail"]["enabled"])
        example = json.loads((ROOT / "config/agent.json.example").read_text())
        self.assertEqual(agent.DEFAULTS["mail"], example["mail"])
        node = json.loads((ROOT / "config/node.json.example").read_text())
        self.assertIn("mail", node["services"])

    def test_validation_rejects_bad_units(self) -> None:
        for units in ([], "dovecot.service", ["dovecot.service; rm -rf /"]):
            config = agent.deep_merge(self.config, {"mail": {"units": units}})
            with self.assertRaises(agent.AgentError):
                agent.validate_config(config)
        config = agent.deep_merge(self.config, {"mail": {"destination_ip": "bogus"}})
        with self.assertRaises(agent.AgentError):
            agent.validate_config(config)

    def test_batches_are_bounded_and_tagged(self) -> None:
        rows = [row(item[0]) for item in DOVECOT_FAILURES]
        rows.append(row("unrelated line"))
        batches = agent.build_mail_batches(self.config, rows)
        self.assertEqual(3, len(batches))
        self.assertEqual([2, 2, 1], [len(batch["events"]) for batch in batches])
        for batch in batches:
            self.assertEqual("mail", batch["source"]["service"])
            self.assertEqual(f"mail-{NODE}", batch["source"]["site_id"])
            self.assertEqual("mail://nidhoggur.example/", batch["source"]["site_url"])
            text = json.dumps(batch)
            for _, _, _, username in DOVECOT_FAILURES:
                self.assertNotIn(username, text)

    def test_missing_privacy_key_fails_closed(self) -> None:
        config = agent.deep_merge(self.config, {"mail": {"privacy_key_file": str(self.root / "absent")}})
        with self.assertRaises(agent.AgentError):
            agent.build_mail_batches(config, [row(DOVECOT_FAILURES[0][0])])

    def test_collect_mail_reads_units_and_advances_cursor(self) -> None:
        lines = [json.dumps(row(DOVECOT_FAILURES[0][0])),
                 json.dumps(row(POSTFIX_FAILURES[0][0], POSTFIX_FAILURES[0][1])),
                 "-- cursor: s=final"]
        completed = subprocess.CompletedProcess([], 0, stdout="\n".join(lines) + "\n", stderr="")
        with mock.patch.object(agent.subprocess, "run", return_value=completed) as run:
            total = agent.collect_mail(self.config)
        self.assertEqual(2, total)
        command = run.call_args.args[0]
        self.assertEqual(
            ["-u", "dovecot.service", "-u", "postfix@-.service"],
            command[4:8],
        )
        self.assertIn("--since=-5min", command)
        self.assertEqual("s=final\n", (self.root / "mail.cursor").read_text())
        self.assertEqual(1, len(list((self.root / "pending").glob("*.json"))))
        with mock.patch.object(agent.subprocess, "run", return_value=completed) as run:
            agent.collect_mail(self.config)
        self.assertIn("--after-cursor=s=final", run.call_args.args[0])

    def test_collect_mail_disabled_does_not_call_journalctl(self) -> None:
        config = agent.deep_merge(self.config, {"mail": {"enabled": False}})
        with mock.patch.object(agent.subprocess, "run") as run:
            self.assertEqual(0, agent.collect_mail(config))
        run.assert_not_called()


class MailCentralTest(unittest.TestCase):
    def batch(self) -> dict:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        key = Path(temp.name) / "k"
        key.write_bytes(SECRET)
        config = agent.deep_merge(agent.DEFAULTS, {
            "node": {"id": NODE, "fqdn": "nidhoggur.example"},
            "mail": {"privacy_key_file": str(key)},
        })
        # Many failures from one IP against several accounts: would trip
        # WordPress/OpenSSH rules if those applied, but mail is observe-only.
        rows = []
        for index in range(30):
            rows.append(row(
                "imap-login: Disconnected (auth failed, 1 attempts in 2 secs): "
                f"user=<u{index % 5}@example.org>, method=PLAIN, rip=198.51.100.77, "
                "lip=203.0.113.25, TLS"
            ))
        return agent.build_mail_batches(config, rows)[0]

    def test_server_api_accepts_authorized_mail(self) -> None:
        payload = json.dumps(self.batch()).encode()
        service, site_id = server_api.validate_event_batch(
            payload, {"node_id": NODE, "services": ["sshd", "mail"]}
        )
        self.assertEqual(("mail", f"mail-{NODE}"), (service, site_id))
        with self.assertRaises(server_api.APIError) as raised:
            server_api.validate_event_batch(payload, {"node_id": NODE, "services": ["sshd"]})
        self.assertEqual(403, raised.exception.status)

    def test_collector_imports_without_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = root / "drop" / "remote" / NODE / "events" / "incoming"
            incoming.mkdir(parents=True)
            config = collector.deep_merge(collector.DEFAULTS, {
                "state_db": str(root / "state.sqlite3"),
                "lock_file": str(root / "collector.lock"),
                "incoming_globs": [str(root / "drop/remote/*/events/incoming/*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "crowdsec": {"enabled": False},
                "enrichment": {"enabled": False},
                "abuse_reporting": {"enabled": False},
            })
            batch = self.batch()
            (incoming / f"{uuid.uuid4()}-mail.json").write_text(json.dumps(batch))
            instance = collector.Collector(config)
            try:
                self.assertEqual(1, instance.run())
                rows = instance.db.conn.execute(
                    "SELECT service, event_type, site_id, account_key, application_protocol "
                    "FROM events"
                ).fetchall()
                self.assertEqual(len(batch["events"]), len(rows))
                self.assertEqual({("mail", "mail_auth_failed", f"mail-{NODE}", "IMAP")},
                                 {(r[0], r[1], r[2], r[4]) for r in rows})
                self.assertEqual(5, len({r[3] for r in rows}))
                for value in {r[3] for r in rows}:
                    self.assertRegex(value, rf"^mail-{NODE}:account:[0-9a-f]{{64}}$")
                incidents = instance.db.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                self.assertEqual(0, incidents)
                self.assertEqual([], list(Path(config["rejected_dir"]).rglob("*.json")))
            finally:
                instance.close()

    def test_normalize_batch_allowlist(self) -> None:
        self.assertIn("mail", collector.BATCH_SERVICES)
        batch = self.batch()
        batch["source"]["service"] = "dovecot"
        with self.assertRaises(collector.CollectorError):
            collector.normalize_batch(batch)


class MailReleaseTest(unittest.TestCase):
    def test_release_version(self) -> None:
        self.assertEqual("0.5.6.1", (ROOT / "VERSION").read_text().strip())
        self.assertEqual("0.5.6.1", agent.APP_VERSION)
        self.assertIn('"test_v0560.py"', (ROOT / "packaging/build_debs.py").read_text())


if __name__ == "__main__":
    unittest.main()
