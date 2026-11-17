#!/usr/bin/env python3
# tests/test_v0580_ban_sync.py
"""Cross-node ban sync (0.5.8.0): protection filter, loop prevention,
idempotent apply with a mocked cscli, the delta cursor, the expiry cap, the
decisions transport kind, the authenticated GET, the collector merge, the
watchdog and the dashboard section.

All addresses are documentation or synthetic examples except where a global
address is required by the safety filter; those use well-known public
resolver ranges that never belong to the operator.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import ipaddress
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import ban_sync  # noqa: E402
import collector  # noqa: E402
import dashboard  # noqa: E402
import dashboard_snapshot  # noqa: E402
import server_api  # noqa: E402
from watchdogs import ban_sync_lag  # noqa: E402

NOW = 1_800_000_000
HOSTILE_A = "1.1.1.1"
HOSTILE_B = "8.8.8.8"
HOSTILE_C = "9.9.9.9"
HOSTILE_RANGE = "1.0.0.0/24"
HOME_V6 = "2606:4700:4700::/64"  # stands in for a protected home /64


def epoch_text(epoch: int) -> str:
    return ban_sync.epoch_text(epoch)


def candidate(node: str, value: str, *, scope: str = "Ip", until: int | None = NOW + 3600,
              origin: str = "crowdsec", reason: str = "crowdsecurity/ssh-bf", channel: str = "agent",
              started: int | None = None, first_seen: int = NOW) -> dict:
    return {
        "node_id": node, "channel": channel, "source": "crowdsec", "source_id": value,
        "scope": scope, "value": value, "origin": origin, "scenario": reason, "reason": reason,
        "started_epoch": started, "until_epoch": until, "first_seen_epoch": first_seen,
    }


class FakeCrowdSec:
    """Minimal cscli stand-in: list (optionally by --ip/--range), add,
    delete --id and allowlists check."""

    def __init__(self, allowlisted: set[str] | None = None) -> None:
        self.decisions: list[dict] = []
        self.calls: list[list[str]] = []
        self.next_id = 100
        self.allowlisted = allowlisted or set()

    def add_foreign(self, value: str, scenario: str, origin: str = "crowdsec", scope: str = "Ip",
                    duration: str = "3h59m0s") -> None:
        self.next_id += 1
        self.decisions.append({"id": self.next_id, "value": value, "scope": scope, "scenario": scenario,
                               "origin": origin, "type": "ban", "duration": duration, "simulated": False})

    def mutating_calls(self) -> list[list[str]]:
        return [call for call in self.calls if call[1:3] in (["decisions", "add"], ["decisions", "delete"])]

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[1:3] == ["allowlists", "check"]:
            if args[3] in self.allowlisted:
                return subprocess.CompletedProcess(args, 0, f"{args[3]} is allowlisted by home\n", "")
            return subprocess.CompletedProcess(args, 0, f"{args[3]} is not allowlisted\n", "")
        if args[1:3] == ["decisions", "list"]:
            selected = self.decisions
            if "--ip" in args:
                selected = [d for d in selected if d["value"] == args[args.index("--ip") + 1]]
            if "--range" in args:
                selected = [d for d in selected if d["value"] == args[args.index("--range") + 1]]
            alerts = [{"start_at": epoch_text(NOW - 60), "decisions": [d]} for d in selected]
            return subprocess.CompletedProcess(args, 0, json.dumps(alerts) if alerts else "null", "")
        if args[1:3] == ["decisions", "add"]:
            scope = "Ip" if "--ip" in args else "Range"
            value = args[args.index("--ip" if scope == "Ip" else "--range") + 1]
            self.next_id += 1
            self.decisions.append({
                "id": self.next_id, "value": value, "scope": scope,
                "scenario": args[args.index("--reason") + 1], "origin": "cscli", "type": "ban",
                "duration": args[args.index("--duration") + 1], "simulated": False,
            })
            return subprocess.CompletedProcess(args, 0, "Decision successfully added\n", "")
        if args[1:3] == ["decisions", "delete"]:
            identifier = int(args[args.index("--id") + 1])
            self.decisions = [d for d in self.decisions if d["id"] != identifier]
            return subprocess.CompletedProcess(args, 0, "1 decision(s) deleted\n", "")
        if args[:2] == ["ip", "-j"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        return subprocess.CompletedProcess(args, 2, "", f"unexpected {args}")


class StoreOpener:
    """urlopen stand-in that serves BanSyncStore.node_view for one node."""

    def __init__(self, store: ban_sync.BanSyncStore, node: str, clock: list[int]) -> None:
        self.store = store
        self.node = node
        self.clock = clock
        self.requests: list[int] = []
        self.tamper = None

    def __call__(self, request, timeout):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
        cursor = int(query["cursor"][0])
        self.requests.append(cursor)
        view = self.store.node_view(self.node, cursor, now_epoch=self.clock[0])
        if self.tamper is not None:
            view = self.tamper(view)
        self.store.record_pull(self.node, cursor, view["cursor"], view["reset"], 0, now_epoch=self.clock[0])
        return contextlib.closing(io.BytesIO(json.dumps(view).encode()))


def agent_config(root: Path, node: str = "hermod", **apply_overrides) -> dict:
    config = agent.deep_merge(agent.DEFAULTS, {
        "enabled": True,
        "node": {"id": node, "fqdn": f"{node}.example.org"},
        "ban_sync": {
            "enabled": True,
            "apply": {"state_file": str(root / "ban-sync-state.json"), **apply_overrides},
            "upstream": {"state_file": str(root / "upstream-state.json"),
                         "fail2ban_db": str(root / "fail2ban.sqlite3")},
        },
        "pending_dir": str(root / "pending"),
    })
    return config


class SharedHelpersTest(unittest.TestCase):
    def test_go_duration(self) -> None:
        self.assertEqual(719 * 3600 + 57 * 60 + 15, ban_sync.parse_go_duration("719h57m15s"))
        self.assertEqual(90, ban_sync.parse_go_duration("1m30.9s"))
        self.assertEqual(0, ban_sync.parse_go_duration("150ms"))
        self.assertIsNone(ban_sync.parse_go_duration("soon"))
        self.assertIsNone(ban_sync.parse_go_duration(""))

    def test_reason_prefixes(self) -> None:
        self.assertTrue(ban_sync.is_sentinel_reason("argent-sentinel/sshd-credential-spray"))
        self.assertTrue(ban_sync.is_sentinel_reason("argent-sentinel:nidhoggur:ssh"))
        self.assertFalse(ban_sync.is_sync_reason("argent-sentinel/sshd-credential-spray"))
        self.assertTrue(ban_sync.is_sync_reason("Argent-Sentinel:nidhoggur:ssh"))
        self.assertEqual(
            "argent-sentinel:nidhoggur:argent-sentinel/sshd-credential-spray",
            ban_sync.sync_reason("nidhoggur", "argent-sentinel/sshd-credential-spray"),
        )
        # Shell metacharacters never reach cscli arguments.
        self.assertEqual("bad-reason-rm--rf", ban_sync.sanitize_reason("bad reason; rm -rf"))

    def test_entry_id_is_stable_and_canonical(self) -> None:
        self.assertEqual(ban_sync.entry_id("Ip", "2001:db8::1"),
                         ban_sync.entry_id("Ip", ban_sync.normalize_value("Ip", "2001:0db8:0::1")))
        self.assertNotEqual(ban_sync.entry_id("Ip", HOSTILE_A), ban_sync.entry_id("Range", HOSTILE_A + "/32"))


class ProtectionFilterTest(unittest.TestCase):
    def protected(self) -> dict:
        return {
            "trusted_cidrs": ban_sync.parse_networks(["127.0.0.0/8", "192.168.0.0/16"]),
            "enforcement_protection.protected_cidrs": ban_sync.parse_networks([HOME_V6, "8.8.8.0/24"]),
            "node protection inventory": ban_sync.parse_networks(["2606:4700:4700::1111/128"]),
        }

    def test_filter_drops_protected_private_and_broad_targets(self) -> None:
        candidates = [
            candidate("hermod", HOSTILE_A),
            candidate("hermod", HOSTILE_B),                      # protected /24
            candidate("hermod", "2606:4700:4700::1111"),           # home /64 and node inventory
            candidate("hermod", "192.168.1.20"),                  # trusted and not global
            candidate("hermod", "10.1.2.3"),                      # not global
            candidate("hermod", "9.0.0.0/16", scope="Range"),     # broader than /24
            candidate("hermod", "8.8.8.0/24", scope="Range"),     # range overlapping protection
            candidate("hermod", HOSTILE_RANGE, scope="Range"),
        ]
        computed, removed, stats = ban_sync.compute_effective(candidates, self.protected(), now_epoch=NOW)
        values = sorted(entry["value"] for entry in computed.values())
        self.assertEqual([HOSTILE_RANGE, HOSTILE_A], values)
        self.assertEqual(3, stats["protected"])
        self.assertEqual(3, stats["unsafe"])
        self.assertIn("protected", removed[ban_sync.entry_id("Ip", HOSTILE_B)])
        self.assertIn("unsafe", removed[ban_sync.entry_id("Range", "9.0.0.0/16")])
        self.assertIn("protected", removed[ban_sync.entry_id("Range", "8.8.8.0/24")])

    def test_central_protection_reads_dynamic_state_and_fails_closed_when_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "effective.json"
            config = {
                "trusted_cidrs": ["127.0.0.0/8"],
                "enforcement_protection": {"protected_cidrs": [HOME_V6], "dynamic_state_file": str(state),
                                           "dynamic_state_max_age_seconds": 600},
                "ban_sync": {"protected_cidrs": ["134.199.206.240/32"]},
            }
            protected, problem = ban_sync.central_protection(config, now_epoch=NOW)
            self.assertIn("unavailable", problem)
            state.write_text(json.dumps({
                "schema_version": 1, "generated_epoch": NOW - 30,
                "dynamic_cidrs": ["2001:4860:4860::/64"],
                "nodes": [{"node_id": "hermod", "effective_cidrs": ["2001:4860:4860::8888/128"]}],
            }))
            protected, problem = ban_sync.central_protection(config, now_epoch=NOW)
            self.assertIsNone(problem)
            self.assertIsNotNone(ban_sync.protection_match("Ip", "2001:4860:4860::8844", protected))
            self.assertIsNotNone(ban_sync.protection_match("Ip", "134.199.206.240", protected))
            _, problem = ban_sync.central_protection(config, now_epoch=NOW + 601)
            self.assertEqual("dynamic protected state is stale", problem)

    def test_agent_side_protection_own_interface_inventory_and_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = agent_config(Path(temporary), local_allowlist=["9.9.9.0/24"])
            config["local_address_protection"]["manual_cidrs"] = []
            protected = ban_sync.local_protection_sets(
                config,
                interfaces=[ipaddress.ip_network("1.1.1.1/32")],
                inventory_cidrs=["2606:4700:4700::/64"],
            )
            mirror = {
                ban_sync.entry_id("Ip", value): {
                    "id": ban_sync.entry_id("Ip", value), "scope": "Ip", "value": value,
                    "until": epoch_text(NOW + 3600), "reason": "x", "origin_node": "nidhoggur",
                }
                for value in (HOSTILE_A, HOSTILE_B, HOSTILE_C, "2606:4700:4700::64")
            }
            plan = ban_sync.plan_changes(mirror, {}, protected, now_epoch=NOW, min_remaining_seconds=60,
                                         update_tolerance_seconds=300, node_id="hermod")
            self.assertEqual([HOSTILE_B], [entry["value"] for entry in plan["adds"]])
            reasons = {item["value"]: item["reason"] for item in plan["skipped"]}
            self.assertTrue(reasons[HOSTILE_A].startswith("own interface"))
            self.assertTrue(reasons[HOSTILE_C].startswith("ban_sync.apply.local_allowlist"))
            self.assertTrue(reasons["2606:4700:4700::64"].startswith("local_address_protection"))


class LoopPreventionTest(unittest.TestCase):
    def alerts(self) -> str:
        def alert(value, scenario, origin, scope="Ip", kind="ban", simulated=False):
            return {"start_at": epoch_text(NOW - 100), "scenario": scenario, "decisions": [{
                "id": abs(hash(value + scenario)) % 10000, "value": value, "scope": scope, "origin": origin,
                "scenario": scenario, "type": kind, "duration": "2h0m0s", "simulated": simulated}]}
        return json.dumps([
            alert(HOSTILE_A, "crowdsecurity/nginx-bf", "crowdsec"),
            alert(HOSTILE_B, "manual ban", "cscli"),
            alert(HOSTILE_C, "argent-sentinel/sshd-credential-spray", "cscli"),
            alert("4.4.4.4", "argent-sentinel:nidhoggur:sshd", "cscli"),
            alert("5.5.5.5", "update : +15000/-0 IPs", "CAPI"),
            alert("6.6.6.6", "firehol", "lists"),
            alert("7.7.7.7", "crowdsecurity/http-probing", "crowdsec", kind="captcha"),
            alert("2.2.2.2", "crowdsecurity/http-probing", "crowdsec", simulated=True),
            alert("AS1234", "x", "cscli", scope="AS"),
        ])

    def test_agent_never_reports_sentinel_reasons_or_capi(self) -> None:
        found, skipped = ban_sync.parse_cscli_decisions(self.alerts(), now_epoch=NOW)
        self.assertEqual([HOSTILE_A, HOSTILE_B], [item["value"] for item in found])
        self.assertEqual(2, skipped["loop"])
        self.assertEqual(2, skipped["origin"])
        self.assertEqual(1, skipped["type"])
        self.assertEqual(1, skipped["simulated"])
        self.assertEqual(1, skipped["scope"])
        self.assertEqual(epoch_text(NOW + 7200), found[0]["until"])

    def test_central_keeps_collector_decisions_but_not_synced_ones(self) -> None:
        found, skipped = ban_sync.parse_cscli_decisions(self.alerts(), now_epoch=NOW, skip_reason=ban_sync.is_sync_reason)
        self.assertIn(HOSTILE_C, [item["value"] for item in found])
        self.assertNotIn("4.4.4.4", [item["value"] for item in found])
        self.assertEqual(1, skipped["loop"])

    def test_merge_drops_sync_reasons_and_node_sentinel_reasons(self) -> None:
        candidates = [
            candidate("hermod", HOSTILE_A, reason="argent-sentinel:nidhoggur:sshd"),
            candidate("hermod", HOSTILE_B, reason="argent-sentinel/sshd-credential-spray"),
            candidate("nidhoggur", HOSTILE_C, reason="argent-sentinel/sshd-credential-spray", channel="central", origin="cscli"),
            candidate("nidhoggur", "4.4.4.4", reason="argent-sentinel:hermod:x", channel="central", origin="cscli"),
            candidate("hermod", "5.5.5.5", origin="CAPI"),
        ]
        computed, _, stats = ban_sync.compute_effective(candidates, {}, now_epoch=NOW)
        self.assertEqual([HOSTILE_C], [entry["value"] for entry in computed.values()])
        self.assertEqual(3, stats["loop"])
        self.assertEqual(1, stats["origin"])

    def test_agent_upstream_skips_its_own_synced_decisions(self) -> None:
        fake = FakeCrowdSec()
        fake.add_foreign(HOSTILE_A, "crowdsecurity/ssh-bf")
        fake.add_foreign(HOSTILE_B, "argent-sentinel:nidhoggur:sshd", origin="cscli")
        settings = ban_sync.AGENT_DEFAULTS | {"upstream": ban_sync.AGENT_DEFAULTS["upstream"] | {"fail2ban_enabled": False}}
        decisions, info = ban_sync.collect_upstream_decisions(settings, now_epoch=NOW, runner=fake)
        self.assertEqual([HOSTILE_A], [item["value"] for item in decisions])
        self.assertEqual(1, info["crowdsec"]["skipped"]["loop"])


class ExpiryCapTest(unittest.TestCase):
    def test_capped_until(self) -> None:
        week = 7 * 86400
        self.assertEqual(NOW + 3600, ban_sync.capped_until(NOW + 3600, started_epoch=NOW, first_seen_epoch=NOW, max_duration_seconds=week))
        self.assertEqual(NOW + week, ban_sync.capped_until(NOW + 30 * 86400, started_epoch=NOW, first_seen_epoch=NOW, max_duration_seconds=week))
        # Anchored on the decision's own start, not on when central saw it.
        self.assertEqual(NOW - 86400 + week, ban_sync.capped_until(NOW + 30 * 86400, started_epoch=NOW - 86400, first_seen_epoch=NOW, max_duration_seconds=week))
        # Permanent fail2ban ban takes the cap; cap disabled uses the 30-day ceiling.
        self.assertEqual(NOW + week, ban_sync.capped_until(None, started_epoch=None, first_seen_epoch=NOW, max_duration_seconds=week))
        self.assertEqual(NOW + 30 * 86400, ban_sync.capped_until(None, started_epoch=None, first_seen_epoch=NOW, max_duration_seconds=0))
        self.assertEqual(NOW + 90 * 86400, ban_sync.capped_until(NOW + 90 * 86400, started_epoch=NOW, first_seen_epoch=NOW, max_duration_seconds=0))

    def test_merge_applies_cap_and_drops_capped_out_entries(self) -> None:
        candidates = [
            candidate("nidhoggur", HOSTILE_A, until=NOW + 30 * 86400, started=NOW - 3600, channel="central", origin="cscli",
                      reason="argent-sentinel/sshd-credential-spray"),
            candidate("hermod", HOSTILE_B, until=NOW + 30 * 86400, started=NOW - 8 * 86400),
        ]
        computed, _, stats = ban_sync.compute_effective(candidates, {}, now_epoch=NOW)
        self.assertEqual(NOW - 3600 + 7 * 86400, computed[ban_sync.entry_id("Ip", HOSTILE_A)]["until_epoch"])
        self.assertNotIn(ban_sync.entry_id("Ip", HOSTILE_B), computed)
        self.assertEqual(1, stats["expired"])

    def test_latest_expiry_wins_across_nodes(self) -> None:
        candidates = [
            candidate("hermod", HOSTILE_A, until=NOW + 3600),
            candidate("nidhoggur", HOSTILE_A, until=NOW + 7200, channel="central", origin="cscli"),
        ]
        computed, _, _ = ban_sync.compute_effective(candidates, {}, now_epoch=NOW)
        entry = computed[ban_sync.entry_id("Ip", HOSTILE_A)]
        self.assertEqual(("nidhoggur", NOW + 7200), (entry["origin_node"], entry["until_epoch"]))


class DeltaCursorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ban_sync.BanSyncStore(Path(self.temporary.name) / "ban-sync.sqlite3")

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def publish(self, candidates, now=NOW, protected=None):
        computed, removed, _ = ban_sync.compute_effective(candidates, protected or {}, now_epoch=now)
        return self.store.reconcile(computed, removed, now_epoch=now, tombstone_retention_seconds=86400)

    def test_snapshot_then_delta_then_removal(self) -> None:
        self.publish([candidate("nidhoggur", HOSTILE_A, channel="central", origin="cscli"),
                      candidate("hermod", HOSTILE_B)])
        snapshot = self.store.node_view("hermod", 0, now_epoch=NOW)
        self.assertTrue(snapshot["reset"])
        self.assertEqual(2, snapshot["cursor"])
        # Hermod's own decision is withheld from hermod.
        self.assertEqual([HOSTILE_A], [entry["value"] for entry in snapshot["entries"]])
        self.assertEqual({"id", "scope", "value", "until", "reason", "origin_node"}, set(snapshot["entries"][0]))
        # No change: empty delta, same digest.
        again = self.store.node_view("hermod", snapshot["cursor"], now_epoch=NOW)
        self.assertFalse(again["reset"])
        self.assertEqual(([], []), (again["upserts"], again["removals"]))
        self.assertEqual(snapshot["snapshot_sha256"], again["snapshot_sha256"])
        # A new central decision and a revocation of HOSTILE_A.
        self.publish([candidate("nidhoggur", HOSTILE_C, channel="central", origin="cscli"),
                      candidate("hermod", HOSTILE_B)])
        delta = self.store.node_view("hermod", snapshot["cursor"], now_epoch=NOW)
        self.assertEqual([HOSTILE_C], [entry["value"] for entry in delta["upserts"]])
        self.assertEqual([ban_sync.entry_id("Ip", HOSTILE_A)], [item["id"] for item in delta["removals"]])
        self.assertEqual("revoked", delta["removals"][0]["reason"])
        mirror, ok = ban_sync.merge_view({"set_id": snapshot["set_id"], "mirror": {e["id"]: e for e in snapshot["entries"]}},
                                         ban_sync.validate_view(delta))
        self.assertTrue(ok)
        self.assertEqual([HOSTILE_C], [entry["value"] for entry in mirror.values()])

    def test_unchanged_reconcile_does_not_bump_cursor(self) -> None:
        candidates = [candidate("hermod", HOSTILE_A)]
        self.publish(candidates)
        head = self.store.head_seq()
        self.assertEqual({"added": 0, "updated": 0, "removed": 0}, self.publish(candidates, now=NOW + 30))
        self.assertEqual(head, self.store.head_seq())

    def test_protection_change_becomes_a_removal(self) -> None:
        self.publish([candidate("hermod", HOSTILE_A)])
        view = self.store.node_view("nidhoggur", 0, now_epoch=NOW)
        self.publish([candidate("hermod", HOSTILE_A)], protected={"home": ban_sync.parse_networks(["1.1.1.0/24"])})
        delta = self.store.node_view("nidhoggur", view["cursor"], now_epoch=NOW)
        self.assertTrue(delta["removals"][0]["reason"].startswith("protected: home"))

    def test_collected_tombstones_force_full_snapshot(self) -> None:
        self.publish([candidate("hermod", HOSTILE_A)])
        early = self.store.node_view("nidhoggur", 0, now_epoch=NOW)["cursor"]
        self.publish([], now=NOW + 10)                       # revoke -> tombstone
        self.publish([], now=NOW + 2 * 86400)                # GC beyond retention
        self.assertGreaterEqual(int(self.store.meta("min_cursor")), early + 1)
        view = self.store.node_view("nidhoggur", early, now_epoch=NOW + 2 * 86400)
        self.assertTrue(view["reset"])
        self.assertEqual([], view["entries"])

    def test_cursor_ahead_of_head_or_new_set_id_resets(self) -> None:
        self.publish([candidate("hermod", HOSTILE_A)])
        self.assertTrue(self.store.node_view("nidhoggur", 999, now_epoch=NOW)["reset"])
        view = ban_sync.validate_view(self.store.node_view("nidhoggur", 0, now_epoch=NOW))
        mirror, ok = ban_sync.merge_view({"set_id": "older-store", "mirror": {"stale": {"until": epoch_text(NOW + 99)}}}, view)
        self.assertTrue(ok)
        self.assertNotIn("stale", mirror)

    def test_digest_mismatch_is_detected(self) -> None:
        self.publish([candidate("hermod", HOSTILE_A)])
        view = ban_sync.validate_view(self.store.node_view("nidhoggur", 0, now_epoch=NOW))
        view["entries"][0]["until"] = epoch_text(NOW + 99999)
        _, ok = ban_sync.merge_view({}, view)
        self.assertFalse(ok)

    def test_validate_view_rejects_forged_identity(self) -> None:
        self.publish([candidate("hermod", HOSTILE_A)])
        view = self.store.node_view("nidhoggur", 0, now_epoch=NOW)
        view["entries"][0]["value"] = HOSTILE_B
        with self.assertRaises(ban_sync.BanSyncError):
            ban_sync.validate_view(view)

    def test_node_report_replacement_dedup_and_staleness(self) -> None:
        report = ban_sync.validate_decisions_report(ban_sync.build_decisions_report("hermod", [
            {"source": "crowdsec", "source_id": "1", "scope": "Ip", "value": HOSTILE_A, "origin": "crowdsec",
             "scenario": "crowdsecurity/ssh-bf", "reason": "crowdsecurity/ssh-bf", "until": epoch_text(NOW + 600)},
        ], now=dt.datetime.fromtimestamp(NOW, dt.timezone.utc)), "hermod")
        self.assertEqual("accepted", self.store.record_node_report(report, "a" * 64, now_epoch=NOW))
        self.assertEqual("duplicate", self.store.record_node_report(report, "a" * 64, now_epoch=NOW))
        with self.assertRaises(ban_sync.BanSyncError):
            self.store.record_node_report(report, "b" * 64, now_epoch=NOW)
        older = dict(report, report_uuid=str(uuid.uuid4()), generated_epoch=NOW - 100, decisions=[])
        self.assertEqual("stale", self.store.record_node_report(older, "c" * 64, now_epoch=NOW))
        self.assertEqual(1, len(self.store.candidate_decisions()))
        newer = dict(report, report_uuid=str(uuid.uuid4()), generated_epoch=NOW + 100, decisions=[])
        self.assertEqual("accepted", self.store.record_node_report(newer, "d" * 64, now_epoch=NOW))
        self.assertEqual([], self.store.candidate_decisions())


class AgentApplyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ban_sync.BanSyncStore(self.root / "ban-sync.sqlite3")
        self.clock = [NOW]
        self.opener = StoreOpener(self.store, "hermod", self.clock)
        self.fake = FakeCrowdSec()

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def publish(self, candidates):
        computed, removed, _ = ban_sync.compute_effective(candidates, {}, now_epoch=self.clock[0])
        self.store.reconcile(computed, removed, now_epoch=self.clock[0], tombstone_retention_seconds=86400)

    def sync(self, config, **kwargs):
        return ban_sync.run_agent_sync(
            config, force=True, runner=self.fake, opener=self.opener, now_epoch=self.clock[0],
            interfaces=[], inventory_cidrs=[], crowdsec_present=kwargs.pop("crowdsec_present", True), **kwargs,
        )

    def central(self, value, until=NOW + 7200):
        return candidate("nidhoggur", value, until=until, channel="central", origin="cscli",
                         reason="argent-sentinel/sshd-credential-spray")

    def test_dry_run_is_default_and_never_calls_cscli_mutations(self) -> None:
        self.publish([self.central(HOSTILE_A)])
        config = agent_config(self.root)
        self.assertTrue(config["ban_sync"]["apply"]["dry_run"])
        result = self.sync(config)
        self.assertEqual(("ok", "dry-run", 1), (result["status"], result["mode"], result["would_apply"]))
        self.assertEqual([], self.fake.mutating_calls())
        state = json.loads(Path(config["ban_sync"]["apply"]["state_file"]).read_text())
        self.assertEqual("argent-sentinel:nidhoggur:argent-sentinel/sshd-credential-spray",
                         state["would_apply"][0]["crowdsec_reason"])
        self.assertEqual({}, state["applied"])
        status = ban_sync.agent_status(config)
        self.assertEqual((1, 0, 0), (status["would_apply"], status["applied"], status["skipped_protection"]))
        self.assertIsNotNone(status["last_pull_at"])

    def test_crowdsec_absent_does_nothing(self) -> None:
        self.publish([self.central(HOSTILE_A)])
        result = self.sync(agent_config(self.root, dry_run=False), crowdsec_present=False)
        self.assertEqual("crowdsec-absent", result["mode"])
        self.assertEqual([], self.fake.mutating_calls())

    def test_apply_is_idempotent_and_removes_only_owned_decisions(self) -> None:
        self.publish([self.central(HOSTILE_A), self.central(HOSTILE_RANGE.replace("1.0.0.0", "1.0.0.0"))])
        self.publish([self.central(HOSTILE_A), candidate("nidhoggur", HOSTILE_RANGE, scope="Range", until=NOW + 7200,
                                                          channel="central", origin="cscli", reason="manual")])
        config = agent_config(self.root, dry_run=False)
        first = self.sync(config)
        self.assertEqual((2, 0, 0), (first["applied"], first["removed"], first["failed"]))
        adds = [call for call in self.fake.mutating_calls() if call[2] == "add"]
        self.assertIn(["/usr/bin/cscli", "decisions", "add", "--ip", HOSTILE_A, "--duration", "7200s",
                       "--reason", "argent-sentinel:nidhoggur:argent-sentinel/sshd-credential-spray",
                       "--type", "ban"], adds)
        self.assertTrue(any("--range" in call and HOSTILE_RANGE in call for call in adds))
        # Repeated pulls with no central change: no cscli mutation at all.
        before = len(self.fake.mutating_calls())
        self.clock[0] += 300
        second = self.sync(config)
        self.assertEqual((0, 0), (second["applied"], second["removed"]))
        self.assertEqual(before, len(self.fake.mutating_calls()))
        # A local CrowdSec ban and a collector ban on the same IP must survive revocation.
        self.fake.add_foreign(HOSTILE_A, "crowdsecurity/ssh-bf")
        self.fake.add_foreign(HOSTILE_A, "argent-sentinel/sshd-credential-spray", origin="cscli")
        self.publish([candidate("nidhoggur", HOSTILE_RANGE, scope="Range", until=NOW + 7200,
                                channel="central", origin="cscli", reason="manual")])
        self.clock[0] += 300
        third = self.sync(config)
        self.assertEqual((0, 1), (third["applied"], third["removed"]))
        remaining = [(d["value"], d["scenario"]) for d in self.fake.decisions if d["value"] == HOSTILE_A]
        self.assertEqual(sorted([(HOSTILE_A, "crowdsecurity/ssh-bf"), (HOSTILE_A, "argent-sentinel/sshd-credential-spray")]),
                         sorted(remaining))
        deletes = [call for call in self.fake.mutating_calls() if call[2] == "delete"]
        self.assertEqual(1, len(deletes))
        self.assertNotIn("--ip", deletes[0])  # delete by decision id only

    def test_expiry_extension_replaces_owned_decision(self) -> None:
        self.publish([self.central(HOSTILE_A, until=NOW + 3600)])
        config = agent_config(self.root, dry_run=False)
        self.sync(config)
        self.publish([self.central(HOSTILE_A, until=NOW + 4 * 3600)])
        self.clock[0] += 60
        result = self.sync(config)
        self.assertEqual(1, result["applied"])
        owned = [d for d in self.fake.decisions if ban_sync.is_sync_reason(d["scenario"])]
        self.assertEqual(1, len(owned))
        self.assertEqual(f"{4 * 3600 - 60}s", owned[0]["duration"])

    def test_allowlisted_and_protected_targets_are_skipped(self) -> None:
        self.fake.allowlisted = {HOSTILE_B}
        self.publish([self.central(HOSTILE_A), self.central(HOSTILE_B), self.central(HOSTILE_C)])
        config = agent_config(self.root, dry_run=False, local_allowlist=["9.9.9.9/32"])
        result = self.sync(config)
        self.assertEqual((1, 2), (result["applied"], result["skipped_protection"]))
        self.assertEqual([HOSTILE_A], [d["value"] for d in self.fake.decisions])

    def test_interval_and_digest_resync(self) -> None:
        self.publish([self.central(HOSTILE_A)])
        config = agent_config(self.root)
        first = ban_sync.run_agent_sync(config, runner=self.fake, opener=self.opener, now_epoch=NOW,
                                        interfaces=[], inventory_cidrs=[], crowdsec_present=True)
        self.assertEqual("ok", first["status"])
        not_due = ban_sync.run_agent_sync(config, runner=self.fake, opener=self.opener, now_epoch=NOW + 60,
                                          interfaces=[], inventory_cidrs=[], crowdsec_present=True)
        self.assertEqual("not-due", not_due["status"])
        # Corrupt the local mirror: the next delta digest mismatches and the
        # agent transparently refetches a full snapshot.
        state_path = Path(config["ban_sync"]["apply"]["state_file"])
        state = json.loads(state_path.read_text())
        state["mirror"] = {}
        state_path.write_text(json.dumps(state))
        self.clock[0] = NOW + 400
        self.opener.requests.clear()
        result = ban_sync.run_agent_sync(config, runner=self.fake, opener=self.opener, now_epoch=NOW + 400,
                                         interfaces=[], inventory_cidrs=[], crowdsec_present=True)
        self.assertEqual("ok", result["status"])
        self.assertEqual([state["cursor"], 0], self.opener.requests)
        self.assertEqual(1, result["mirror"])

    def test_persistent_digest_failure_applies_nothing(self) -> None:
        self.publish([self.central(HOSTILE_A)])
        self.opener.tamper = lambda view: dict(view, snapshot_sha256="0" * 64)
        result = self.sync(agent_config(self.root, dry_run=False))
        self.assertEqual("error", result["status"])
        self.assertEqual([], self.fake.mutating_calls())


class Fail2banSourceTest(unittest.TestCase):
    def test_current_and_permanent_bans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fail2ban.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, "
                               "bantime INTEGER NOT NULL, bancount INTEGER NOT NULL default 1, data JSON)")
            connection.executemany("INSERT INTO bans(jail, ip, timeofban, bantime) VALUES (?, ?, ?, ?)", [
                ("argentwolf-nginx-probe", HOSTILE_A, NOW - 60, 7 * 86400),
                ("sshd", HOSTILE_B, NOW - 7200, 600),          # expired
                ("recidive", HOSTILE_C, NOW - 60, -1),          # permanent
                ("sshd", "not-an-ip", NOW, 600),
            ])
            connection.commit()
            connection.close()
            bans = ban_sync.read_fail2ban_bans(path, now_epoch=NOW)
            by_value = {item["value"]: item for item in bans}
            self.assertEqual({HOSTILE_A, HOSTILE_C}, set(by_value))
            self.assertEqual(epoch_text(NOW - 60 + 7 * 86400), by_value[HOSTILE_A]["until"])
            self.assertIsNone(by_value[HOSTILE_C]["until"])
            self.assertEqual("fail2ban", by_value[HOSTILE_A]["origin"])
            self.assertEqual([HOSTILE_A], [b["value"] for b in ban_sync.read_fail2ban_bans(path, now_epoch=NOW, jails=["argentwolf-nginx-probe"])])


class AgentUpstreamTest(unittest.TestCase):
    def test_decisions_envelope_kind_and_digest_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = agent_config(root)
            fake = FakeCrowdSec()
            fake.add_foreign(HOSTILE_A, "crowdsecurity/ssh-bf")
            self.assertEqual(1, agent.stage_decisions_report(config, runner=fake))
            self.assertEqual(0, agent.stage_decisions_report(config, runner=fake))  # unchanged, within heartbeat
            fake.add_foreign(HOSTILE_B, "crowdsecurity/nginx-bf")
            self.assertEqual(1, agent.stage_decisions_report(config, runner=fake))
            envelopes = [json.loads(path.read_text()) for path in sorted((root / "pending").glob("*.json"))]
            self.assertEqual({"decisions"}, {item["kind"] for item in envelopes})
            payload = base64.b64decode(envelopes[0]["payload_b64"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), envelopes[0]["payload_sha256"])
            report = json.loads(payload)
            self.assertEqual("hermod", report["node_id"])

    def test_disabled_by_default(self) -> None:
        self.assertFalse(agent.DEFAULTS["ban_sync"]["enabled"])
        self.assertTrue(agent.DEFAULTS["ban_sync"]["apply"]["dry_run"])
        self.assertEqual(5, agent.DEFAULTS["ban_sync"]["apply"]["interval_minutes"])
        self.assertEqual(0, agent.stage_decisions_report(agent.DEFAULTS | {"node": {"id": "hermod"}}))
        example = json.loads((ROOT / "config/agent.json.example").read_text())
        self.assertFalse(example["ban_sync"]["enabled"])
        self.assertTrue(example["ban_sync"]["apply"]["dry_run"])

    def test_agent_sync_fails_closed_without_protection_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = agent_config(Path(temporary), dry_run=False)
            with mock.patch.object(agent.local_protection, "build_inventory",
                                   side_effect=agent.local_protection.ProtectionError("boom")), \
                    mock.patch.object(agent.ban_sync, "run_agent_sync") as sync:
                result = agent.run_ban_sync(config, force=True)
            self.assertEqual("protection-unavailable", result["status"])
            sync.assert_not_called()

    def test_config_validation_rejects_capi_origin(self) -> None:
        settings = json.loads(json.dumps(ban_sync.AGENT_DEFAULTS))
        settings["upstream"]["crowdsec_origins"] = ["crowdsec", "CAPI"]
        with self.assertRaises(ban_sync.BanSyncError):
            ban_sync.validate_agent_settings(settings)


class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "nodes.d").mkdir()
        self.config = server_api.deep_merge(server_api.DEFAULTS, {
            "nodes_dir": str(self.root / "nodes.d"),
            "receipt_db": str(self.root / "ingress.sqlite3"),
            "event_drop_root": str(self.root / "remote"),
            "ban_sync": {"enabled": True, "store_db": str(self.root / "ban-sync.sqlite3")},
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def enroll(self, node: str, services: list[str]) -> None:
        (self.root / "nodes.d" / f"{node}.json").write_text(json.dumps({"node_id": node, "enabled": True, "services": services}))

    def envelope(self, node: str, report: dict) -> bytes:
        payload = json.dumps(report).encode()
        return json.dumps(agent.make_envelope(node, "decisions", payload)).encode()

    def test_decisions_upstream_requires_explicit_service(self) -> None:
        report = ban_sync.build_decisions_report("hermod", [])
        self.enroll("hermod", [])
        ingress = server_api.Ingress(self.config)
        with self.assertRaises(server_api.APIError) as raised:
            ingress.accept(self.envelope("hermod", report), "hermod")
        self.assertEqual(403, raised.exception.status)
        self.enroll("hermod", ["nginx", "sshd", "decisions"])
        status, body = ingress.accept(self.envelope("hermod", report), "hermod")
        self.assertEqual((201, "accepted"), (status, body["status"]))
        self.assertEqual(1, len(list((self.root / "remote/hermod/decisions/incoming").glob("*.json"))))
        forged = ban_sync.build_decisions_report("nidhoggur", [])
        with self.assertRaises(server_api.APIError) as raised:
            ingress.accept(self.envelope("hermod", forged), "hermod")
        self.assertEqual(403, raised.exception.status)

    def test_get_decisions_authorization_and_pull_record(self) -> None:
        store = ban_sync.BanSyncStore(Path(self.config["ban_sync"]["store_db"]))
        computed, removed, _ = ban_sync.compute_effective([candidate("nidhoggur", HOSTILE_A, channel="central", origin="cscli")],
                                                          {}, now_epoch=int(time.time()))
        store.reconcile(computed, removed, now_epoch=int(time.time()), tombstone_retention_seconds=86400)
        store.close()
        self.enroll("hermod", ["nginx", "sshd"])
        with self.assertRaises(server_api.APIError) as raised:
            server_api.serve_decisions(self.config, "hermod", 0)
        self.assertEqual(403, raised.exception.status)
        self.enroll("hermod", ["nginx", "sshd", "decisions"])
        view = server_api.serve_decisions(self.config, "hermod", 0)
        self.assertTrue(view["reset"])
        self.assertEqual([HOSTILE_A], [entry["value"] for entry in view["entries"]])
        store = ban_sync.BanSyncStore(Path(self.config["ban_sync"]["store_db"]))
        self.assertEqual("hermod", store.node_pulls()[0]["node_id"])
        store.close()
        with self.assertRaises(server_api.APIError) as raised:
            server_api.serve_decisions(self.config, "unknown-node", 0)
        self.assertEqual(403, raised.exception.status)
        disabled = dict(self.config, ban_sync={"enabled": False, "store_db": self.config["ban_sync"]["store_db"]})
        with self.assertRaises(server_api.APIError) as raised:
            server_api.serve_decisions(disabled, "hermod", 0)
        self.assertEqual(404, raised.exception.status)

    def test_cursor_parsing(self) -> None:
        self.assertEqual(0, server_api.parse_cursor("/v1/decisions"))
        self.assertEqual(42, server_api.parse_cursor("/v1/decisions?cursor=42"))
        for bad in ("/v1/decisions?cursor=-1", "/v1/decisions?cursor=abc", "/v1/decisions?cursor=1&cursor=2"):
            with self.assertRaises(server_api.APIError):
                server_api.parse_cursor(bad)

    def test_nginx_examples_require_client_certificates(self) -> None:
        for name in ("nginx-sentinel.conf.example", "nginx-sentinel-dashboard.conf.example"):
            text = (ROOT / "config" / name).read_text()
            block = text[text.index("location = /v1/decisions"):]
            block = block[: block.index("\n    }\n")]
            self.assertIn("X-Argent-Client-DN $ssl_client_s_dn", block)
            self.assertIn("limit_except GET", block)
        dashboard_example = (ROOT / "config/nginx-sentinel-dashboard.conf.example").read_text()
        block = dashboard_example[dashboard_example.index("location = /v1/decisions"):]
        self.assertIn("if ($ssl_client_verify != SUCCESS)", block[:300])


class CollectorMergeTest(unittest.TestCase):
    def test_merge_ingests_reports_reads_central_and_publishes_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "effective.json"
            state.write_text(json.dumps({"schema_version": 1, "generated_epoch": NOW, "dynamic_cidrs": [], "nodes": []}))
            incoming = root / "remote/hermod/decisions/incoming"
            incoming.mkdir(parents=True)
            report = ban_sync.build_decisions_report("hermod", [
                {"source": "fail2ban", "source_id": f"probe:{HOSTILE_B}", "scope": "Ip", "value": HOSTILE_B,
                 "origin": "fail2ban", "scenario": "fail2ban/argentwolf-nginx-probe",
                 "reason": "fail2ban-argentwolf-nginx-probe", "started_at": epoch_text(NOW - 60), "until": None},
            ], now=dt.datetime.fromtimestamp(NOW, dt.timezone.utc))
            (incoming / "r1.json").write_text(json.dumps(report))
            # A report claiming another node under hermod's drop path is rejected.
            (incoming / "r2.json").write_text(json.dumps(ban_sync.build_decisions_report("nidhoggur", [])))
            fake = FakeCrowdSec()
            fake.add_foreign(HOSTILE_A, "argent-sentinel/sshd-credential-spray", origin="cscli", duration="719h0m0s")
            fake.add_foreign(HOSTILE_C, "argent-sentinel:hermod:fail2ban-sshd", origin="cscli")
            config = {
                "node": {"id": "nidhoggur"},
                "trusted_cidrs": ["127.0.0.0/8"],
                "enforcement_protection": {"protected_cidrs": [], "dynamic_state_file": str(state)},
                "crowdsec": {"cscli_path": "/usr/bin/cscli", "command_timeout_seconds": 5},
                "ban_sync": ban_sync.CENTRAL_DEFAULTS | {
                    "enabled": True,
                    "store_db": str(root / "ban-sync.sqlite3"),
                    "status_file": str(root / "ban-sync-status.json"),
                    "incoming_globs": [str(root / "remote/*/decisions/incoming/*.json")],
                    "archive_dir": str(root / "archive"),
                    "rejected_dir": str(root / "rejected"),
                },
            }
            result = ban_sync.run_central_merge(config, runner=fake, now_epoch=NOW)
            self.assertEqual("ok", result["status"])
            self.assertEqual(1, result["imported"])
            self.assertEqual(2, result["active"])
            self.assertEqual([], list(incoming.glob("*.json")))
            self.assertEqual(1, len(list((root / "rejected").rglob("*.error.txt"))))
            self.assertEqual("not-due", ban_sync.run_central_merge(config, runner=fake, now_epoch=NOW + 5)["status"])
            store = ban_sync.BanSyncStore(root / "ban-sync.sqlite3")
            view = store.node_view("hermod", 0, now_epoch=NOW)
            store.close()
            entries = {entry["value"]: entry for entry in view["entries"]}
            # Hermod receives nidhoggur's collector ban (capped to 7 days from
            # its start), not its own fail2ban ban or the synced decision.
            self.assertEqual([HOSTILE_A], list(entries))
            self.assertEqual(epoch_text(NOW - 60 + 7 * 86400), entries[HOSTILE_A]["until"])
            self.assertEqual("nidhoggur", entries[HOSTILE_A]["origin_node"])
            status = ban_sync.publish_status(config, now_epoch=NOW)
            self.assertEqual(2, status["active_entries"])
            published = json.loads((root / "ban-sync-status.json").read_text())
            self.assertNotIn("entries", published)
            # Stale protection state: fail closed, nothing new published.
            result = ban_sync.run_central_merge(config, runner=fake, now_epoch=NOW + 3600, force=True)
            self.assertEqual("protection-unavailable", result["status"])

    def test_collector_defaults_and_status(self) -> None:
        self.assertFalse(collector.DEFAULTS["ban_sync"]["enabled"])
        self.assertEqual(604800, collector.DEFAULTS["ban_sync"]["max_duration_seconds"])
        example = json.loads((ROOT / "config/collector.json.example").read_text())
        self.assertFalse(example["ban_sync"]["enabled"])
        ban_sync.validate_central_settings(example["ban_sync"])
        with self.assertRaises(ban_sync.BanSyncError):
            ban_sync.validate_central_settings(example["ban_sync"] | {"allowed_origins": ["crowdsec", "lists"]})
        self.assertEqual({"enabled": False}, collector.ban_sync_status({"ban_sync": {"enabled": False}}))


class ObservabilityTest(unittest.TestCase):
    def test_watchdog_evaluate(self) -> None:
        pulls = [{"node_id": "hermod", "last_pull_epoch": NOW - 600}, {"node_id": "nidhoggur", "last_pull_epoch": NOW - 1900}]
        result = ban_sync_lag.evaluate(pulls, ["hermod", "nidhoggur", "newnode"], now_epoch=NOW, max_pull_age_seconds=1800)
        self.assertEqual(["nidhoggur"], result["stale"])
        self.assertEqual(["newnode"], result["never"])
        self.assertEqual(600, result["lag_seconds"]["hermod"])
        definition = json.loads((ROOT / "config/watchdog.d/30-ban_sync_lag.json").read_text())
        self.assertFalse(definition["enabled"])
        self.assertEqual(1800, definition["max_pull_age_seconds"])
        self.assertEqual([], ban_sync_lag.validate(definition))

    def test_watchdog_check_reads_status_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status.json"
            definition = {"status_file": str(path), "max_pull_age_seconds": 1800, "max_status_age_seconds": 600,
                          "expected_nodes": ["hermod"]}
            self.assertEqual("warning", ban_sync_lag.check({}, definition, {})["status"])
            now = int(time.time())
            path.write_text(json.dumps({"schema_version": 1, "generated_epoch": now,
                                        "nodes": [{"node_id": "hermod", "last_pull_epoch": now - 2000}]}))
            result = ban_sync_lag.check({}, definition, {})
            self.assertEqual("critical", result["status"])
            self.assertIn("hermod", result["summary"])
            path.write_text(json.dumps({"schema_version": 1, "generated_epoch": now,
                                        "nodes": [{"node_id": "hermod", "last_pull_epoch": now - 60}]}))
            self.assertEqual("healthy", ban_sync_lag.check({}, definition, {})["status"])

    def test_dashboard_section_shows_per_node_lag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status.json"
            now = int(time.time())
            path.write_text(json.dumps({
                "schema_version": 1, "generated_epoch": now, "generated_at": "x", "head_cursor": 7,
                "active_entries": 3, "active_by_origin_node": {"nidhoggur": 3},
                "node_reports": [{"node_id": "hermod", "channel": "agent", "decision_count": 2,
                                  "received_at": "2026-11-17T14:00:00Z", "age_seconds": 30, "report_uuid": "secret"}],
                "nodes": [{"node_id": "hermod", "last_pull_epoch": now - 3600, "last_pull_at": "2026-11-17T13:00:00Z",
                           "cursor": 5, "cursor_behind": 2, "served_entries": 3, "pulls": 9, "last_reset": False}],
            }))
            section = dashboard_snapshot.ban_sync_section({"ban_sync": {"enabled": True, "status_file": str(path)}})
            self.assertEqual("ok", section["status"])
            self.assertTrue(section["nodes"][0]["lagging"])
            self.assertNotIn("report_uuid", section["node_reports"][0])
            html = dashboard.render_ban_sync({"ban_sync": section})
            self.assertIn("Cross-node ban sync", html)
            self.assertIn("hermod", html)
            self.assertIn("status-warning", html)
            disabled = dashboard_snapshot.ban_sync_section({})
            self.assertEqual("disabled", disabled["status"])
            self.assertIn("disabled", dashboard.render_ban_sync({"ban_sync": disabled}))


class PackagingTest(unittest.TestCase):
    def test_version_and_packaged_files(self) -> None:
        self.assertEqual("0.5.8.0", (ROOT / "VERSION").read_text().strip())
        for module in (agent, ban_sync, collector, server_api, dashboard_snapshot):
            self.assertEqual("0.5.8.0", module.APP_VERSION)
        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('("ban_sync.py", "ban_sync.py")', builder)
        self.assertIn('"test_v0580_ban_sync.py"', builder)
        self.assertTrue((ROOT / "docs/cross-node-ban-sync.md").is_file())


if __name__ == "__main__":
    unittest.main()
# EOF tests/test_v0580_ban_sync.py
