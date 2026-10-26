#!/usr/bin/env python3
# tests/test_v0560_mail_slowburn.py
"""Account-keyed mail slow-burn policy (0.5.6.0, PR2).

All fixtures are synthetic: example.org mailboxes and fabricated journal rows.
No real mailbox name belongs in this repository.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
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

SECRET = b"s" * 32
NODE = "nidhoggur"
SITE = f"mail-{NODE}"
ALICE = "alice@example.org"
CAROL = "carol@example.org"
_counter = 0


def journal_row(account: str, source_ip: str, offset_seconds: int, protocol: str = "imap") -> dict:
    global _counter
    _counter += 1
    micros = int((time.time() - offset_seconds) * 1_000_000)
    return {
        "MESSAGE": (
            f"{protocol}-login: Disconnected (auth failed, 1 attempts in 2 secs): "
            f"user=<{account}>, method=PLAIN, rip={source_ip}, lip=203.0.113.25, TLS"
        ),
        "SYSLOG_IDENTIFIER": "dovecot",
        "__REALTIME_TIMESTAMP": str(micros),
        "__CURSOR": f"s=slowburn;i={_counter};u={uuid.uuid4()}",
    }


def sources(prefix: str, count: int, start: int = 10) -> list[str]:
    return [f"{prefix}.{start + index}" for index in range(count)]


class CscliRecorder:
    """Stand-in for cscli: nothing allowlisted, every decision accepted."""

    def __init__(self) -> None:
        self.decisions: list[list[str]] = []

    def __call__(self, command, **kwargs):
        if command[1:3] == ["allowlists", "check"]:
            return subprocess.CompletedProcess(command, 1, stdout="not allowlisted", stderr="")
        if command[1:3] == ["decisions", "add"]:
            self.decisions.append(list(command))
            return subprocess.CompletedProcess(command, 0, stdout="Decision successfully added", stderr="")
        raise AssertionError(f"unexpected subprocess call: {command}")


class MailSlowBurnTest(unittest.TestCase):
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

    def tearDown(self) -> None:
        for instance in self.instances:
            instance.close()
        self.temp.cleanup()

    # -- helpers -----------------------------------------------------------
    def config(self, **mail_policy) -> dict:
        policy = {"enabled": True, "privacy_key_file": str(self.key)}
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

    def deliver(self, rows: list[dict]) -> None:
        for batch in agent.build_mail_batches(self.agent_config, rows):
            (self.incoming / f"{uuid.uuid4()}-mail.json").write_text(json.dumps(batch))

    def campaign_rows(self, account: str, ips: list[str], per_ip: int) -> list[dict]:
        rows = []
        for ip_index, source_ip in enumerate(ips):
            for attempt in range(per_ip):
                # Spread across ~20 hours: slow-burn, far below fail2ban rates.
                rows.append(journal_row(account, source_ip, 72000 - ip_index * 3000 - attempt * 600))
        return rows

    def run_collector(self, config: dict) -> tuple[collector.Collector, CscliRecorder]:
        instance = collector.Collector(config)
        self.instances.append(instance)
        recorder = CscliRecorder()
        with mock.patch.object(collector.subprocess, "run", side_effect=recorder):
            instance.run()
        return instance, recorder

    @staticmethod
    def incidents(instance: collector.Collector) -> list[sqlite3.Row]:
        return instance.db.conn.execute(
            "SELECT * FROM incidents ORDER BY source_ip"
        ).fetchall()

    # -- HMAC domain -------------------------------------------------------
    def test_collector_token_matches_agent_mail_domain(self) -> None:
        for account in (ALICE, "Alice@Example.ORG", "postmaster"):
            self.assertEqual(
                agent.privacy_token(SECRET, NODE, account, agent.MAIL_PRIVACY_DOMAIN),
                collector.mail_privacy_token(SECRET, NODE, account),
            )
        self.assertNotEqual(
            agent.privacy_token(SECRET, NODE, ALICE, "sshd"),
            collector.mail_privacy_token(SECRET, NODE, ALICE),
        )

    # -- thresholds --------------------------------------------------------
    def test_defaults_are_conservative_and_disabled(self) -> None:
        defaults = collector.DEFAULTS["mail_account_policy"]
        self.assertFalse(defaults["enabled"])
        self.assertFalse(defaults["abuse_reporting_enabled"])
        self.assertEqual(
            (86400, 10, 5, 2, 6, 3, "168h"),
            (
                defaults["window_seconds"], defaults["failure_threshold"],
                defaults["distinct_source_ips"], defaults["min_failures_per_ip"],
                defaults["protected_failure_threshold"],
                defaults["protected_distinct_source_ips"], defaults["ban_duration"],
            ),
        )
        example = json.loads((ROOT / "config/collector.json.example").read_text())
        self.assertEqual(defaults, example["mail_account_policy"])

    def test_disabled_policy_creates_nothing(self) -> None:
        self.deliver(self.campaign_rows(ALICE, sources("45.155.205", 6), 3))
        instance, recorder = self.run_collector(self.config(enabled=False))
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)
        self.assertEqual(0, instance.db.conn.execute("SELECT COUNT(*) FROM mail_account_campaigns").fetchone()[0])

    def test_threshold_triggers_per_ip_crowdsec_decisions(self) -> None:
        ips = sources("45.155.205", 3) + sources("185.220.101", 2)
        self.deliver(self.campaign_rows(ALICE, ips, 2))  # 10 failures, 5 IPs
        instance, recorder = self.run_collector(self.config())
        incidents = self.incidents(instance)
        self.assertEqual(sorted(ips), [row["source_ip"] for row in incidents])
        for row in incidents:
            self.assertEqual("mail-account-slow-burn", row["rule_id"])
            self.assertEqual(SITE, row["site_id"])
            self.assertEqual(2, row["event_count"])
            self.assertEqual("applied", row["decision_status"])
            self.assertEqual("suppressed", row["report_status"])
        self.assertEqual(5, len(recorder.decisions))
        for command in recorder.decisions:
            self.assertIn("--ip", command)
            self.assertNotIn("--range", command)
            self.assertEqual("168h", command[command.index("--duration") + 1])
            self.assertTrue(command[command.index("--reason") + 1].endswith("/mail-account-slow-burn"))
        campaign = instance.db.mail_campaigns()[0]
        self.assertEqual(("enforcing", 10, 5, 5), (
            campaign["status"], campaign["failures"],
            campaign["distinct_source_ips"], campaign["enforced_source_ips"],
        ))

    def test_rerun_is_idempotent(self) -> None:
        self.deliver(self.campaign_rows(ALICE, sources("45.155.205", 5), 2))
        config = self.config()
        instance, first = self.run_collector(config)
        self.assertEqual(5, len(first.decisions))
        recorder = CscliRecorder()
        with mock.patch.object(collector.subprocess, "run", side_effect=recorder):
            instance.run()
        self.assertEqual([], recorder.decisions)
        self.assertEqual(5, len(self.incidents(instance)))

    def test_below_threshold_creates_no_decision(self) -> None:
        # 4 IPs x 2 = 8 failures: below N=10 and below M=5.
        self.deliver(self.campaign_rows(ALICE, sources("45.155.205", 4), 2))
        # 12 failures but only 4 distinct IPs: below M.
        self.deliver(self.campaign_rows(CAROL, sources("185.220.101", 4), 3))
        instance, recorder = self.run_collector(self.config())
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)
        statuses = {item["status"] for item in instance.db.mail_campaigns()}
        self.assertEqual({"review"}, statuses)

    def test_one_shot_sources_feed_review_not_bans(self) -> None:
        one_shot = sources("45.155.205", 8)
        repeat = sources("185.220.101", 2)
        rows = self.campaign_rows(ALICE, one_shot, 1) + self.campaign_rows(ALICE, repeat, 3)
        self.deliver(rows)
        instance, recorder = self.run_collector(self.config())
        self.assertEqual(sorted(repeat), [row["source_ip"] for row in self.incidents(instance)])
        self.assertEqual(2, len(recorder.decisions))
        campaign = instance.db.mail_campaigns()[0]
        self.assertEqual(("enforcing", 14, 10, 2), (
            campaign["status"], campaign["failures"],
            campaign["distinct_source_ips"], campaign["enforced_source_ips"],
        ))

    def test_trusted_sources_are_ignored(self) -> None:
        self.deliver(self.campaign_rows(ALICE, sources("192.168.1", 6), 3))
        instance, recorder = self.run_collector(self.config())
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)

    def test_failures_spread_over_accounts_do_not_aggregate(self) -> None:
        rows = []
        for index, source_ip in enumerate(sources("45.155.205", 6)):
            rows += self.campaign_rows(f"user{index}@example.org", [source_ip], 3)
        self.deliver(rows)
        instance, recorder = self.run_collector(self.config())
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)

    # -- prefix / ASN review-only -------------------------------------------
    def test_prefix_and_asn_proposals_are_review_only(self) -> None:
        ips = ["45.155.205.10", "45.155.205.11", "45.155.205.40", "2a0e:1234::10"]
        self.deliver(self.campaign_rows(ALICE, ips, 1))
        config = self.config()
        instance = collector.Collector(config)
        self.instances.append(instance)
        with instance.db.conn:
            instance.db.conn.execute(
                """INSERT INTO enrichment_cache (source_ip, fetched_epoch, expires_epoch, asn,
                   asn_holder, abuse_emails_json, raw_json) VALUES (?, 0, 9999999999, 64500,
                   'EXAMPLE-AS', '[]', '{}')""",
                ("45.155.205.10",),
            )
        recorder = CscliRecorder()
        with mock.patch.object(collector.subprocess, "run", side_effect=recorder):
            instance.run()
        self.assertEqual([], recorder.decisions)
        self.assertEqual([], self.incidents(instance))
        campaign = instance.db.mail_campaigns()[0]
        self.assertEqual("review", campaign["status"])
        self.assertFalse(campaign["automatic_block"])
        self.assertEqual(
            [{"bounded_cidr": "45.155.205.0/24", "proposal_cidr": "45.155.205.0/26",
              "source_ips": 3, "failures": 3, "review_only": True}],
            campaign["prefix_proposals"],
        )
        self.assertEqual(
            [{"asn": 64500, "asn_holder": "EXAMPLE-AS", "source_ips": 1, "review_only": True}],
            campaign["asn_summary"],
        )
        self.assertEqual(0, instance.db.conn.execute(
            "SELECT COUNT(*) FROM network_cases WHERE decision_status IS NOT NULL"
        ).fetchone()[0])

    def test_enforcement_never_issues_range_decisions(self) -> None:
        self.deliver(self.campaign_rows(ALICE, sources("45.155.205", 12), 2))
        _, recorder = self.run_collector(self.config())
        self.assertEqual(12, len(recorder.decisions))
        self.assertTrue(all("--range" not in command for command in recorder.decisions))

    # -- protected accounts ------------------------------------------------
    def protected_rows(self) -> list[dict]:
        # 3 IPs x 2 = 6 failures: below the unlisted N/M, at the protected N/M.
        return self.campaign_rows(CAROL, sources("45.155.205", 3), 2)

    def test_unlisted_account_below_threshold(self) -> None:
        self.deliver(self.protected_rows())
        instance, recorder = self.run_collector(self.config())
        self.assertEqual([], recorder.decisions)

    def test_protected_token_list_lowers_threshold(self) -> None:
        token = collector.mail_privacy_token(SECRET, NODE, CAROL)
        for entry in (f"{SITE}:account:{token}", token, {"token": token, "label": "owner-primary"}):
            with self.subTest(entry=str(entry)[:20]):
                for name in ("state.sqlite3",):
                    with contextlib.suppress(FileNotFoundError):
                        (self.root / name).unlink()
                self.deliver(self.protected_rows())
                instance, recorder = self.run_collector(self.config(protected_account_tokens=[entry]))
                incidents = self.incidents(instance)
                self.assertEqual(3, len(incidents))
                self.assertEqual({"mail-protected-account-slow-burn"}, {row["rule_id"] for row in incidents})
                self.assertEqual(3, len(recorder.decisions))
                campaign = instance.db.mail_campaigns()[0]
                self.assertTrue(campaign["protected"])
                self.assertEqual("enforcing", campaign["status"])
                instance.close()
                self.instances.remove(instance)

    def test_protected_account_is_always_surfaced(self) -> None:
        token = collector.mail_privacy_token(SECRET, NODE, CAROL)
        self.deliver(self.campaign_rows(CAROL, ["45.155.205.10"], 2))
        instance, recorder = self.run_collector(self.config(
            protected_account_tokens=[{"token": token, "label": "owner-primary"}]
        ))
        self.assertEqual([], recorder.decisions)
        campaign = instance.db.mail_campaigns()[0]
        self.assertEqual(("review", True, "owner-primary"), (
            campaign["status"], campaign["protected"], campaign["protected_label"],
        ))

    def test_protected_accounts_file_uses_ingest_hmac(self) -> None:
        accounts = self.root / "protected-mailboxes"
        accounts.write_text(f"# operator list\n{CAROL.upper()} owner-primary\n\n")
        os.chmod(accounts, 0o600)
        self.deliver(self.protected_rows())
        instance, recorder = self.run_collector(self.config(protected_accounts_file=str(accounts)))
        self.assertEqual(3, len(recorder.decisions))
        self.assertEqual({"owner-primary"}, set(instance.protected_mail_accounts().values()))
        self.assertTrue(all(CAROL not in key.lower() for key in instance.protected_mail_accounts()))

    def test_world_readable_protected_file_is_ignored(self) -> None:
        accounts = self.root / "protected-mailboxes"
        accounts.write_text(f"{CAROL}\n")
        os.chmod(accounts, 0o644)
        self.deliver(self.protected_rows())
        with self.assertLogs("argent-sentinel", level="ERROR"):
            instance, recorder = self.run_collector(self.config(protected_accounts_file=str(accounts)))
        self.assertEqual({}, instance.protected_mail_accounts())
        self.assertEqual([], recorder.decisions)

    def test_config_rejects_plaintext_addresses(self) -> None:
        for entries in ([ALICE], [{"token": "a" * 64, "label": ALICE}], ["not-a-token"]):
            with self.subTest(entries=entries):
                with self.assertRaises(collector.CollectorError):
                    self.config(protected_account_tokens=entries)
        with self.assertRaises(collector.CollectorError):
            self.config(distinct_source_ips=1)

    def test_mail_account_token_cli(self) -> None:
        config_path = self.root / "collector.json"
        config_path.write_text(json.dumps({
            "state_db": str(self.root / "cli.sqlite3"),
            "node": {"id": NODE},
            "mail_account_policy": {"privacy_key_file": str(self.key)},
        }))
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(f"# comment\n{CAROL}\n")), \
                contextlib.redirect_stdout(stdout):
            self.assertEqual(0, collector.main(["--config", str(config_path), "mail-account-token"]))
        expected = f"{SITE}:account:{agent.privacy_token(SECRET, NODE, CAROL, 'mail')}\n"
        self.assertEqual(expected, stdout.getvalue())
        self.assertNotIn(CAROL, stdout.getvalue())

    # -- privacy of exports ------------------------------------------------
    def test_exports_contain_no_raw_addresses_or_tokens(self) -> None:
        token = collector.mail_privacy_token(SECRET, NODE, CAROL)
        rows = self.campaign_rows(ALICE, sources("45.155.205", 5), 2) + self.protected_rows()
        self.deliver(rows)
        config = self.config(protected_account_tokens=[{"token": token, "label": "owner-primary"}])
        instance, _ = self.run_collector(config)
        tokens = {
            row[0].rpartition(":account:")[2]
            for row in instance.db.conn.execute("SELECT DISTINCT account_key FROM events")
        }
        self.assertEqual(2, len(tokens))

        exports: dict[str, str] = {}
        exports["status"] = json.dumps(collector.status_output(instance), default=str)

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
        snapshot = dashboard_snapshot.build_snapshot(snapshot_config)
        self.assertEqual(2, len(snapshot["mail_account_campaigns"]))
        exports["snapshot"] = json.dumps(snapshot, default=str)
        exports["dashboard"] = dashboard.render_incidents(snapshot)
        self.assertIn("Mail account slow-burn campaigns", exports["dashboard"])
        self.assertIn("owner-primary", exports["dashboard"])

        connection = sqlite3.connect(config["state_db"])
        connection.row_factory = sqlite3.Row
        now = int(time.time())
        exports["digest"] = review_digest.render_digest(
            {"daily_review": {"max_rows": 20, "max_network_rows": 20}}, connection, now - 86400, now + 60,
        )
        connection.close()
        self.assertIn("Mail account slow-burn campaigns", exports["digest"])
        self.assertIn("review-only", exports["digest"])

        incident = instance.db.conn.execute(
            "SELECT * FROM incidents WHERE rule_id = 'mail-protected-account-slow-burn' LIMIT 1"
        ).fetchone()
        instance.config["abuse_reporting"].update({
            "enabled": True, "test_mode": True, "from": "sentinel@example.net",
            "recipient_override": "abuse-test@example.net", "resolve_target_dns": False,
            "resolve_source_rdns": False,
        })
        enrichment = {"network_cidr": "45.155.205.0/24", "network_name": "test", "asn": 64500,
                      "asn_holder": "EXAMPLE-AS", "abuse_emails": [], "network_class": "hosting"}
        mail_payloads: list[bytes] = []

        def fake_run(command, **kwargs):
            if "input" in kwargs:
                mail_payloads.append(kwargs["input"])
                return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
            return CscliRecorder()(command, **kwargs)

        with mock.patch.object(collector.subprocess, "run", side_effect=fake_run):
            status, _, _ = instance.send_abuse_report(incident, enrichment, ["abuse-test@example.net"])
        self.assertEqual("sent", status)
        payload = mail_payloads[-1].decode("utf-8", "replace")
        exports["report"] = payload
        self.assertIn("mail", payload.lower())
        import base64
        import email
        from email import policy as email_policy
        message = email.message_from_string(payload, policy=email_policy.default)
        xarf = None
        for part in message.walk():
            if part.get_filename() and part.get_filename().endswith(".json"):
                xarf = json.loads(part.get_content() if isinstance(part.get_content(), str)
                                  else part.get_content().decode())
        self.assertIsNotNone(xarf)
        assert xarf is not None
        self.assertEqual("login_attack", xarf["type"])
        self.assertIn("service:mail", xarf["tags"])
        exports["xarf"] = json.dumps(xarf)
        decoded = "\n".join(
            part.get_content() if isinstance(part.get_content(), str) else base64.b64encode(part.get_content()).decode()
            for part in message.walk() if not part.is_multipart()
        )
        exports["report_decoded"] = decoded

        for name, text in exports.items():
            lowered = text.lower()
            with self.subTest(export=name):
                for address in (ALICE, CAROL, "alice", "carol"):
                    self.assertNotIn(address, lowered)
                for value in tokens:
                    self.assertNotIn(value, lowered)


if __name__ == "__main__":
    unittest.main()
# EOF tests/test_v0560_mail_slowburn.py
