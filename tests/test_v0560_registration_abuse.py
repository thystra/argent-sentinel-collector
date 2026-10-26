#!/usr/bin/env python3
# tests/test_v0560_registration_abuse.py
"""Access Guard ``registration_abuse`` collector policy (0.5.6.0, PR4).

All fixtures are synthetic: example.test sites, fabricated Access Guard
metadata, and public-looking source addresses (the decision path refuses
non-global addresses, so enforcement tests cannot use TEST-NET ranges). The collector must stay site
agnostic, so site IDs here are arbitrary and appear in no allowlist.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402

SIGNATURE = "a" * 64


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


def registration_event(
    source_ip: str,
    minutes_ago: int,
    *,
    score: float = 7.5,
    confidence: str = "high",
    outcome: str = "denied",
    signature: str = SIGNATURE,
    rule_ids: list[str] | None = None,
) -> dict:
    occurred = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
    return {
        "event_uuid": str(uuid.uuid4()),
        "occurred_at": occurred.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "recorded_at": occurred.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "registration_abuse",
        "severity": "warning" if outcome == "denied" else "notice",
        "outcome": outcome,
        "source_ip": source_ip,
        "user_agent": "Mozilla/5.0 (synthetic)",
        "request": {"method": "POST", "path": "/wp-login.php"},
        "metadata": {
            "producer": "argentwolf-access-guard",
            "producer_schema": "argentwolf.access_guard.abuse.v1",
            "score": score,
            "confidence": confidence,
            "rule_ids": rule_ids or ["AWAG_FORM_LT_2S"],
            "policy_action": "reject" if outcome == "denied" else "allow",
            "fingerprint_signature": signature,
            "handoff": "argentwolf_access_guard_sentinel_external_event_v1",
        },
    }


class RegistrationAbuseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.instances: list[collector.Collector] = []

    def tearDown(self) -> None:
        for instance in self.instances:
            instance.close()
        self.temp.cleanup()

    # -- helpers -----------------------------------------------------------
    def config(self, crowdsec: bool = True, site_mismatch: str = "warn", **policy_overrides) -> dict:
        policy = {"enabled": True}
        policy.update(policy_overrides)
        config = collector.deep_merge(collector.DEFAULTS, {
            "state_db": str(self.root / "state.sqlite3"),
            "lock_file": str(self.root / "collector.lock"),
            "incoming_globs": [str(self.root / "drop/wordpress/*/incoming/*.json")],
            "processing_dir": str(self.root / "processing"),
            "archive_dir": str(self.root / "archive"),
            "rejected_dir": str(self.root / "rejected"),
            "crowdsec": {"enabled": crowdsec, "cscli_path": "/usr/bin/cscli"},
            "enrichment": {"enabled": False},
            "abuse_reporting": {"enabled": False},
            "persistent_wordpress_policy": {"enabled": False},
            "registration_abuse_policy": policy,
            "wordpress_drop": {"site_mismatch": site_mismatch},
        })
        collector.validate_config(config)
        return config

    def deliver(self, site_id: str, events: list[dict], directory: str | None = None) -> None:
        incoming = self.root / "drop" / "wordpress" / (directory or site_id) / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        batch = {
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": {
                "host": "example-host",
                "site_id": site_id,
                "site_url": f"https://{site_id}.example.test/",
                "service": "wordpress",
                "plugin_version": "0.2.6",
            },
            "events": events,
        }
        (incoming / f"{uuid.uuid4()}.json").write_text(json.dumps(batch))

    def run_collector(self, config: dict) -> tuple[collector.Collector, CscliRecorder]:
        instance = collector.Collector(config)
        self.instances.append(instance)
        recorder = CscliRecorder()
        with mock.patch.object(collector.subprocess, "run", side_effect=recorder):
            instance.run()
        return instance, recorder

    @staticmethod
    def incidents(instance: collector.Collector) -> list[sqlite3.Row]:
        return instance.db.conn.execute("SELECT * FROM incidents ORDER BY source_ip, rule_id").fetchall()

    # -- defaults ----------------------------------------------------------
    def test_defaults_are_disabled_and_match_example(self) -> None:
        defaults = collector.DEFAULTS["registration_abuse_policy"]
        self.assertFalse(defaults["enabled"])
        self.assertFalse(defaults["crowdsec_enforcement"])
        self.assertFalse(defaults["abuse_reporting_enabled"])
        self.assertEqual(
            (86400, 6.0, ["high", "medium"], 3, 2, 9.0, 2, "168h"),
            (
                defaults["window_seconds"], defaults["min_score"],
                defaults["accepted_confidences"], defaults["event_threshold"],
                defaults["cross_site_distinct_sites"], defaults["high_confidence_score"],
                defaults["high_confidence_event_threshold"], defaults["ban_duration"],
            ),
        )
        example = json.loads((ROOT / "config/collector.json.example").read_text())
        self.assertEqual(defaults, example["registration_abuse_policy"])
        self.assertEqual(collector.DEFAULTS["wordpress_drop"], example["wordpress_drop"])
        self.assertEqual("warn", example["wordpress_drop"]["site_mismatch"])
        self.assertIn("/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json", collector.DEFAULTS["incoming_globs"])
        self.assertIn("wordpress", collector.BATCH_SERVICES)

    def test_disabled_policy_stores_events_but_creates_nothing(self) -> None:
        self.deliver("site-one", [registration_event("45.155.205.10", m, score=9.5) for m in (10, 20, 30)])
        instance, recorder = self.run_collector(self.config(enabled=False))
        stored = instance.db.conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'registration_abuse'"
        ).fetchone()[0]
        self.assertEqual(3, stored)
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)
        self.assertEqual([], instance.registration_abuse_campaigns())

    # -- operator gate -----------------------------------------------------
    def test_enabled_policy_is_dry_run_until_operator_enables_enforcement(self) -> None:
        self.deliver("any-site-name", [registration_event("45.155.205.10", m) for m in (10, 20, 30)])
        instance, recorder = self.run_collector(self.config())
        [incident] = self.incidents(instance)
        self.assertEqual("wordpress-registration-abuse", incident["rule_id"])
        self.assertIsNone(incident["site_id"])
        self.assertEqual(3, incident["event_count"])
        self.assertEqual("dry-run", incident["decision_status"])
        self.assertIn("crowdsec_enforcement", incident["decision_detail"])
        self.assertEqual("suppressed", incident["report_status"])
        self.assertEqual([], recorder.decisions)

        # Operator flips the per-policy gate: the same incident is now enforced.
        instance.close()
        self.instances.remove(instance)
        instance, recorder = self.run_collector(self.config(crowdsec_enforcement=True))
        [incident] = self.incidents(instance)
        self.assertEqual("applied", incident["decision_status"])
        [command] = recorder.decisions
        self.assertEqual("45.155.205.10", command[command.index("--ip") + 1])
        self.assertNotIn("--range", command)
        self.assertEqual("168h", command[command.index("--duration") + 1])
        self.assertTrue(command[command.index("--reason") + 1].endswith("/wordpress-registration-abuse"))

    def test_global_crowdsec_guard_still_wins(self) -> None:
        self.deliver("site-one", [registration_event("45.155.205.10", m) for m in (10, 20, 30)])
        instance, recorder = self.run_collector(self.config(crowdsec=False, crowdsec_enforcement=True))
        [incident] = self.incidents(instance)
        self.assertEqual("dry-run", incident["decision_status"])
        self.assertEqual("CrowdSec enforcement disabled in configuration", incident["decision_detail"])
        self.assertEqual([], recorder.decisions)

    # -- rules -------------------------------------------------------------
    def test_high_confidence_rule(self) -> None:
        self.deliver("site-one", [registration_event("45.155.205.20", m, score=9.5) for m in (10, 20)])
        instance, recorder = self.run_collector(self.config(crowdsec_enforcement=True, ban_duration="72h"))
        [incident] = self.incidents(instance)
        self.assertEqual("wordpress-registration-abuse-high-confidence", incident["rule_id"])
        [command] = recorder.decisions
        self.assertEqual("72h", command[command.index("--duration") + 1])

    def test_cross_site_rule_is_site_agnostic(self) -> None:
        self.deliver("alpha-example", [registration_event("45.155.205.30", 10)])
        self.deliver("beta-example", [registration_event("45.155.205.30", 20)])
        instance, _ = self.run_collector(self.config())
        [incident] = self.incidents(instance)
        self.assertEqual("wordpress-registration-abuse", incident["rule_id"])
        self.assertEqual(2, incident["site_count"])
        self.assertIsNone(incident["site_id"])

    def test_below_threshold_low_score_low_confidence_and_observed_do_not_qualify(self) -> None:
        self.deliver("site-one", [
            registration_event("45.155.205.40", 10),
            registration_event("45.155.205.40", 20),  # 2 < event_threshold 3
            registration_event("45.155.205.41", 10, score=4.0),
            registration_event("45.155.205.41", 20, score=4.0),
            registration_event("45.155.205.41", 30, score=4.0),
            registration_event("45.155.205.42", 10, confidence="low"),
            registration_event("45.155.205.42", 20, confidence="low"),
            registration_event("45.155.205.42", 30, confidence="low"),
            registration_event("45.155.205.43", 10, score=9.9, outcome="observed"),
            registration_event("45.155.205.43", 20, score=9.9, outcome="observed"),
            registration_event("45.155.205.43", 30, score=9.9, outcome="observed"),
        ])
        instance, recorder = self.run_collector(self.config(crowdsec_enforcement=True))
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)

    def test_events_outside_window_are_ignored(self) -> None:
        self.deliver("site-one", [registration_event("45.155.205.50", m) for m in (3000, 3010, 3020)])
        instance, _ = self.run_collector(self.config())
        self.assertEqual([], self.incidents(instance))

    def test_trusted_source_is_never_an_incident(self) -> None:
        self.deliver("site-one", [registration_event("192.168.1.10", m, score=9.5) for m in (10, 20, 30)])
        instance, recorder = self.run_collector(self.config(crowdsec_enforcement=True))
        self.assertEqual([], self.incidents(instance))
        self.assertEqual([], recorder.decisions)

    def test_existing_wordpress_login_policy_unchanged(self) -> None:
        config = self.config()
        self.assertTrue(collector.DEFAULTS["persistent_wordpress_policy"]["enabled"])
        self.assertTrue(set(collector.REGISTRATION_RULES).isdisjoint({
            "wordpress-credential-spray",
            "wordpress-single-account-bruteforce",
            "wordpress-persistent-credential-spray",
            "wordpress-persistent-single-account-bruteforce",
        }))
        self.assertEqual(collector.DEFAULTS["policy"], config["policy"])

    # -- review-only campaigns ---------------------------------------------
    def test_fingerprint_campaign_is_review_only(self) -> None:
        events = [registration_event(f"203.0.113.{10 + index}", 10 + index, score=6.5, confidence="medium")
                  for index in range(4)]
        self.deliver("site-one", events)
        instance, recorder = self.run_collector(self.config(crowdsec_enforcement=True))
        self.assertEqual([], self.incidents(instance))  # one event per IP: below per-IP thresholds
        self.assertEqual([], recorder.decisions)
        [campaign] = instance.registration_abuse_campaigns()
        self.assertEqual(SIGNATURE, campaign["fingerprint_signature"])
        self.assertEqual(4, campaign["distinct_source_ips"])
        self.assertTrue(campaign["review_only"])
        self.assertEqual("review", campaign["status"])
        self.assertEqual(["site-one"], campaign["sites"])
        [proposal] = campaign["prefix_proposals"]
        self.assertTrue(proposal["review_only"])
        self.assertEqual("203.0.113.0/24", proposal["bounded_cidr"])
        status = collector.status_output(instance)
        self.assertEqual(1, len(status["registration_abuse_campaigns"]))
        self.assertFalse(status["registration_abuse_policy"]["crowdsec_enforcement"] is None)

    # -- drop path identity ------------------------------------------------
    def test_site_mismatch_warns_and_imports_by_default(self) -> None:
        self.deliver("batch-site", [registration_event("45.155.205.60", 10)], directory="other-dir")
        with self.assertLogs("argent-sentinel", level="WARNING") as logs:
            instance, _ = self.run_collector(self.config())
        self.assertTrue(any("does not match its drop directory" in line for line in logs.output))
        site = instance.db.conn.execute("SELECT site_id FROM events").fetchone()[0]
        self.assertEqual("batch-site", site)

    def test_site_mismatch_can_reject(self) -> None:
        self.deliver("batch-site", [registration_event("45.155.205.61", 10)], directory="other-dir")
        instance, _ = self.run_collector(self.config(site_mismatch="reject"))
        self.assertEqual(0, instance.db.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        rejected = list((self.root / "rejected").rglob("*.error.txt"))
        self.assertEqual(1, len(rejected))

    def test_wordpress_drop_site_parser(self) -> None:
        self.assertEqual(
            "any-site",
            collector.wordpress_drop_site(Path("/var/lib/argent-sentinel/drop/wordpress/any-site/incoming/x.json")),
        )
        self.assertIsNone(collector.wordpress_drop_site(Path("/var/lib/argent-sentinel/drop/remote/n/events/incoming/x.json")))

    # -- validation --------------------------------------------------------
    def test_validation_rejects_unsafe_settings(self) -> None:
        for overrides in (
            {"cross_site_distinct_sites": 1},
            {"accepted_confidences": []},
            {"accepted_confidences": ["certain"]},
            {"high_confidence_score": 5.0},
            {"min_score": 101},
            {"ban_duration": "forever"},
            {"crowdsec_enforcement": "yes"},
            {"event_threshold": 0},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(collector.CollectorError):
                self.config(**overrides)
        with self.assertRaises(collector.CollectorError):
            self.config(site_mismatch="ignore")

    def test_metadata_parser_is_defensive(self) -> None:
        evidence = collector.registration_evidence('{"score": "NaN", "confidence": "EXTREME", "rule_ids": "x"}')
        self.assertEqual((0.0, "low", [], ""), (
            evidence["score"], evidence["confidence"], evidence["rule_ids"], evidence["fingerprint_signature"],
        ))
        self.assertEqual(0.0, collector.registration_evidence("not json")["score"])


if __name__ == "__main__":
    unittest.main()
# EOF tests/test_v0560_registration_abuse.py
