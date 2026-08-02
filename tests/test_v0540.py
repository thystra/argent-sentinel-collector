#!/usr/bin/env python3
# File: /home/alan/src/argent-sentinel-collector/tests/test_v0540.py
"""Regression coverage for Argent Sentinel 0.5.5.1."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import collector  # noqa: E402
import dashboard  # noqa: E402
import local_protection  # noqa: E402
import review_processor  # noqa: E402
import review_queue  # noqa: E402
import server_api  # noqa: E402

UTC = dt.timezone.utc


class FakeRunner:
    def __init__(self, *, virtual: str, addresses: list[dict], routes: list[dict]):
        self.virtual = virtual
        self.addresses = addresses
        self.routes = routes

    def __call__(self, command, **kwargs):
        if command[0] == "systemd-detect-virt":
            if self.virtual == "none":
                return subprocess.CompletedProcess(command, 1, "none\n", "")
            return subprocess.CompletedProcess(command, 0, self.virtual + "\n", "")
        if "address" in command:
            return subprocess.CompletedProcess(
                command, 0, json.dumps(self.addresses), ""
            )
        if "route" in command:
            return subprocess.CompletedProcess(
                command, 0, json.dumps(self.routes), ""
            )
        raise AssertionError(command)


class V0540Test(unittest.TestCase):
    def test_release_and_schema_markers(self) -> None:
        self.assertEqual("0.5.5.1", (ROOT / "VERSION").read_text().strip())
        self.assertEqual("0.5.5.1", agent.APP_VERSION)
        self.assertEqual("0.5.5.1", local_protection.APP_VERSION)
        self.assertEqual("0.5.5.1", collector.APP_VERSION)
        self.assertEqual("0.5.5.1", server_api.APP_VERSION)
        self.assertEqual(9, collector.SCHEMA_VERSION)
        self.assertEqual(9, review_queue.SCHEMA_VERSION)

    def test_custom_state_db_relocates_default_protection_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = collector.deep_merge(
                collector.DEFAULTS,
                {
                    "state_db": str(root / "state.sqlite3"),
                    "incoming_globs": [],
                    "abuse_context": {"enabled": False},
                    "crowdsec": {"enabled": False},
                    "enrichment": {"enabled": False},
                    "abuse_reporting": {"enabled": False},
                },
            )
            expected = root / "effective-protected-cidrs.json"
            self.assertEqual(expected, collector.protection_state_path(config))
            instance = collector.Collector(config)
            try:
                instance.publish_effective_protection_state()
            finally:
                instance.close()
            self.assertTrue(expected.is_file())

    def test_physical_ra_host_recommends_lan_prefix(self) -> None:
        runner = FakeRunner(
            virtual="none",
            addresses=[
                {
                    "ifname": "eno1",
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "2001:db8:100:200::10",
                            "prefixlen": 64,
                            "scope": "global",
                            "dynamic": True,
                        }
                    ],
                },
                {
                    "ifname": "eno2",
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "2001:db8:100:200::20",
                            "prefixlen": 64,
                            "scope": "global",
                            "dynamic": True,
                        }
                    ],
                },
                {
                    "ifname": "docker0",
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "fd00::1",
                            "prefixlen": 64,
                            "scope": "global",
                        }
                    ],
                },
            ],
            routes=[
                {"dev": "eno1", "gateway": "fe80::1", "protocol": "ra"},
                {"dev": "eno2", "gateway": "fe80::1", "protocol": "ra"},
            ],
        )
        result = local_protection.discover(runner=runner)
        self.assertEqual("lan-prefix", result["recommendation"]["mode"])
        self.assertEqual(["eno1", "eno2"], result["recommendation"]["interfaces"])
        self.assertEqual(2, len(result["addresses"]))
        self.assertEqual(
            ["2001:db8:100:200::/64"],
            result["recommendation"]["prefixes"],
        )

    def test_virtual_host_recommends_host_mode(self) -> None:
        runner = FakeRunner(
            virtual="kvm",
            addresses=[
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "2001:db8:500:1::10",
                            "prefixlen": 64,
                            "scope": "global",
                        }
                    ],
                },
                {
                    "ifname": "tun0",
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "fd42:42:42:42::1",
                            "prefixlen": 112,
                            "scope": "global",
                        }
                    ],
                },
            ],
            routes=[
                {"dev": "eth0", "gateway": "2001:db8:500:1::1", "protocol": "static"}
            ],
        )
        result = local_protection.discover(runner=runner)
        self.assertEqual("host", result["recommendation"]["mode"])
        self.assertEqual(["eth0"], result["recommendation"]["interfaces"])
        self.assertEqual(1, len(result["addresses"]))

    def test_physical_broad_prefix_recommends_host_mode(self) -> None:
        runner = FakeRunner(
            virtual="none",
            addresses=[
                {
                    "ifname": "eno1",
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "2001:db8:700::10",
                            "prefixlen": 32,
                            "scope": "global",
                            "dynamic": True,
                        }
                    ],
                }
            ],
            routes=[
                {"dev": "eno1", "gateway": "fe80::1", "protocol": "ra"}
            ],
        )
        result = local_protection.discover(runner=runner)
        self.assertEqual("host", result["recommendation"]["mode"])
        self.assertIn("broader than /48", result["recommendation"]["reason"])

    def test_unconfirmed_lan_mode_falls_back_to_dynamic_host_cidrs(self) -> None:
        discovery = {
            "addresses": [
                {
                    "interface": "eth0",
                    "address": "2001:db8:100::10",
                    "prefix_length": 64,
                    "network": "2001:db8:100::/64",
                    "address_class": "public",
                }
            ],
            "default_route_interfaces": ["eth0"],
            "virtualization": {"type": "none", "is_virtual": False},
            "recommendation": {"mode": "lan-prefix"},
        }
        config = {
            "node": {"id": "test-node"},
            "local_address_protection": {
                "enabled": True,
                "mode": "lan-prefix",
                "interfaces": ["eth0"],
                "manual_cidrs": [],
                "include_unique_local": False,
                "selection_source": "safe-default",
                "operator_confirmed": False,
                "inventory_state_file": "/tmp/unused",
                "inventory_heartbeat_seconds": 3600,
            },
        }
        inventory = local_protection.build_inventory(
            config,
            discovery=discovery,
        )
        self.assertEqual("host", inventory["effective_mode"])
        self.assertEqual("confirmation-required", inventory["status"])
        self.assertEqual(["2001:db8:100::10/128"], inventory["effective_cidrs"])

    def test_confirmed_broad_interface_prefix_falls_back_to_host(self) -> None:
        discovery = {
            "addresses": [
                {
                    "interface": "eth0",
                    "address": "2001:db8:700::10",
                    "prefix_length": 32,
                    "network": "2001:db8::/32",
                    "address_class": "public",
                }
            ],
            "default_route_interfaces": ["eth0"],
            "virtualization": {"type": "none", "is_virtual": False},
            "recommendation": {"mode": "lan-prefix"},
        }
        config = {
            "node": {"id": "physical-node"},
            "local_address_protection": {
                "enabled": True,
                "mode": "lan-prefix",
                "interfaces": [],
                "manual_cidrs": [],
                "include_unique_local": False,
                "selection_source": "debconf",
                "operator_confirmed": True,
                "inventory_state_file": "/tmp/unused",
                "inventory_heartbeat_seconds": 3600,
            },
        }
        inventory = local_protection.build_inventory(config, discovery=discovery)
        self.assertEqual("host", inventory["effective_mode"])
        self.assertEqual("unsafe-prefix-fallback", inventory["status"])
        self.assertEqual(["2001:db8:700::10/128"], inventory["effective_cidrs"])

    def test_remote_inventory_rejects_overly_broad_dynamic_prefix(self) -> None:
        inventory = {
            "schema_version": 1,
            "inventory_uuid": "44444444-4444-4444-8444-444444444444",
            "generated_at": "2026-07-30T02:00:00Z",
            "node_id": "vps-node",
            "enabled": True,
            "configured_mode": "manual",
            "effective_mode": "manual",
            "operator_confirmed": True,
            "selection_source": "debconf",
            "status": "active",
            "configured_interfaces": [],
            "effective_cidrs": ["2001:db8::/32"],
            "addresses": [],
            "default_route_interfaces": ["eth0"],
            "virtualization": {"type": "kvm", "is_virtual": True},
            "recommendation": {"mode": "host"},
        }
        with self.assertRaisesRegex(server_api.APIError, "broader than /48"):
            server_api.validate_protection_inventory(
                json.dumps(inventory).encode(),
                {"node_id": "vps-node"},
            )

    def test_agent_stages_only_changed_or_periodic_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {
                "node": {"id": "vps-node"},
                "pending_dir": str(root / "pending"),
                "local_address_protection": {
                    "enabled": True,
                    "mode": "host",
                    "interfaces": ["eth0"],
                    "manual_cidrs": [],
                    "include_unique_local": False,
                    "selection_source": "debconf",
                    "operator_confirmed": True,
                    "inventory_state_file": str(root / "state.json"),
                    "inventory_heartbeat_seconds": 3600,
                },
            }
            inventory = {
                "schema_version": 1,
                "inventory_uuid": "8dc202ea-43a3-45b8-b081-bfabfb4e3af7",
                "generated_at": "2026-07-30T02:00:00Z",
                "node_id": "vps-node",
                "enabled": True,
                "configured_mode": "host",
                "effective_mode": "host",
                "operator_confirmed": True,
                "selection_source": "debconf",
                "status": "active",
                "configured_interfaces": ["eth0"],
                "effective_cidrs": ["2001:db8:500:1::10/128"],
                "addresses": [],
                "default_route_interfaces": ["eth0"],
                "virtualization": {"type": "kvm", "is_virtual": True},
                "recommendation": {"mode": "host"},
            }
            with mock.patch.object(
                agent.local_protection,
                "build_inventory",
                return_value=inventory,
            ):
                self.assertEqual(1, agent.stage_protection_inventory(config))
                self.assertEqual(0, agent.stage_protection_inventory(config))
            envelopes = list((root / "pending").glob("*.json"))
            self.assertEqual(1, len(envelopes))
            envelope = json.loads(envelopes[0].read_text())
            self.assertEqual("protection_inventory", envelope["kind"])

    def test_inventory_digest_ignores_lifetime_countdown(self) -> None:
        inventory = {
            "schema_version": 1,
            "inventory_uuid": "8dc202ea-43a3-45b8-b081-bfabfb4e3af7",
            "generated_at": "2026-07-30T02:00:00Z",
            "node_id": "vps-node",
            "enabled": True,
            "configured_mode": "host",
            "effective_mode": "host",
            "operator_confirmed": True,
            "selection_source": "debconf",
            "status": "active",
            "configured_interfaces": ["eth0"],
            "effective_cidrs": ["2001:db8:500:1::10/128"],
            "addresses": [
                {
                    "interface": "eth0",
                    "address": "2001:db8:500:1::10",
                    "prefix_length": 64,
                    "network": "2001:db8:500:1::/64",
                    "address_class": "public",
                    "valid_life_time": 3600,
                    "preferred_life_time": 1800,
                }
            ],
            "default_route_interfaces": ["eth0"],
            "virtualization": {"type": "kvm", "is_virtual": True},
            "recommendation": {"mode": "host"},
        }
        changed = json.loads(json.dumps(inventory))
        changed["inventory_uuid"] = "11111111-1111-4111-8111-111111111111"
        changed["generated_at"] = "2026-07-30T02:01:00Z"
        changed["addresses"][0]["valid_life_time"] = 3540
        changed["addresses"][0]["preferred_life_time"] = 1740
        self.assertEqual(
            agent.protection_inventory_digest(inventory),
            agent.protection_inventory_digest(changed),
        )

    def test_api_accepts_authenticated_inventory_shape(self) -> None:
        inventory = {
            "schema_version": 1,
            "inventory_uuid": "8dc202ea-43a3-45b8-b081-bfabfb4e3af7",
            "generated_at": "2026-07-30T02:00:00Z",
            "node_id": "vps-node",
            "enabled": True,
            "configured_mode": "host",
            "effective_mode": "host",
            "operator_confirmed": True,
            "selection_source": "debconf",
            "status": "active",
            "configured_interfaces": ["eth0"],
            "effective_cidrs": ["2001:db8:500:1::10/128"],
            "addresses": [],
            "default_route_interfaces": ["eth0"],
            "virtualization": {"type": "kvm", "is_virtual": True},
            "recommendation": {"mode": "host"},
        }
        result = server_api.validate_protection_inventory(
            json.dumps(inventory).encode(),
            {"node_id": "vps-node"},
        )
        self.assertEqual(inventory["effective_cidrs"], result["effective_cidrs"])

    def test_collector_publishes_dynamic_protection_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = root / "drop" / "remote" / "vps-node" / "protection" / "incoming"
            incoming.mkdir(parents=True)
            inventory = {
                "schema_version": 1,
                "inventory_uuid": "8dc202ea-43a3-45b8-b081-bfabfb4e3af7",
                "generated_at": collector.utc_text(),
                "node_id": "vps-node",
                "enabled": True,
                "configured_mode": "host",
                "effective_mode": "host",
                "operator_confirmed": True,
                "selection_source": "debconf",
                "status": "active",
                "configured_interfaces": ["eth0"],
                "effective_cidrs": ["2001:db8:500:1::10/128"],
                "addresses": [],
                "default_route_interfaces": ["eth0"],
                "virtualization": {"type": "kvm", "is_virtual": True},
                "recommendation": {"mode": "host"},
            }
            (incoming / "inventory.json").write_text(json.dumps(inventory))
            config = collector.deep_merge(
                collector.DEFAULTS,
                {
                    "state_db": str(root / "state.sqlite3"),
                    "node": {"id": "central", "central_url": ""},
                    "incoming_globs": [],
                    "lock_file": str(root / "collector.lock"),
                    "abuse_context": {"enabled": False},
                    "protection_inventory": {
                        "incoming_globs": [str(incoming / "*.json")],
                        "processing_dir": str(root / "processing"),
                        "archive_dir": str(root / "archive"),
                        "rejected_dir": str(root / "rejected"),
                        "state_file": str(root / "effective.json"),
                    },
                    "crowdsec": {"enabled": False},
                    "abuse_reporting": {"enabled": False},
                },
            )
            instance = collector.Collector(config)
            try:
                self.assertEqual(1, instance.import_protection_inventory_files())
                state = instance.publish_effective_protection_state()
                schema = instance.db.conn.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
            finally:
                instance.close()
            self.assertEqual("9", schema)
            self.assertEqual(
                ["2001:db8:500:1::10/128"],
                state["dynamic_cidrs"],
            )
            self.assertEqual("vps-node", state["nodes"][0]["node_id"])

    def test_collector_replaces_changed_node_cidrs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = collector.deep_merge(
                collector.DEFAULTS,
                {
                    "state_db": str(root / "state.sqlite3"),
                    "node": {"id": "central", "central_url": ""},
                    "incoming_globs": [],
                    "lock_file": str(root / "collector.lock"),
                    "abuse_context": {"enabled": False},
                    "protection_inventory": {
                        "incoming_globs": [],
                        "processing_dir": str(root / "processing"),
                        "archive_dir": str(root / "archive"),
                        "rejected_dir": str(root / "rejected"),
                        "state_file": str(root / "effective.json"),
                    },
                    "crowdsec": {"enabled": False},
                    "abuse_reporting": {"enabled": False},
                },
            )
            instance = collector.Collector(config)
            try:
                first = {
                    "schema_version": 1,
                    "inventory_uuid": "11111111-1111-4111-8111-111111111111",
                    "generated_at": collector.utc_text(
                        collector.utc_now() - dt.timedelta(seconds=2)
                    ),
                    "node_id": "vps-node",
                    "enabled": True,
                    "configured_mode": "host",
                    "effective_mode": "host",
                    "operator_confirmed": True,
                    "selection_source": "debconf",
                    "status": "active",
                    "configured_interfaces": [],
                    "effective_cidrs": ["2001:db8:500:1::10/128"],
                    "addresses": [],
                    "default_route_interfaces": ["eth0"],
                    "virtualization": {"type": "kvm", "is_virtual": True},
                    "recommendation": {"mode": "host"},
                }
                second = dict(first)
                second["inventory_uuid"] = "22222222-2222-4222-8222-222222222222"
                second["generated_at"] = collector.utc_text()
                second["effective_cidrs"] = ["2001:db8:600:1::20/128"]
                self.assertTrue(
                    instance.db.import_protection_inventory(
                        collector.normalize_protection_inventory(first),
                        "a" * 64,
                        root / "first.json",
                    )
                )
                self.assertTrue(
                    instance.db.import_protection_inventory(
                        collector.normalize_protection_inventory(second),
                        "b" * 64,
                        root / "second.json",
                    )
                )
                state = instance.publish_effective_protection_state()
                history_count = instance.db.conn.execute(
                    "SELECT COUNT(*) FROM node_protection_inventory_history"
                ).fetchone()[0]
            finally:
                instance.close()
            self.assertEqual(["2001:db8:600:1::20/128"], state["dynamic_cidrs"])
            self.assertEqual(2, history_count)

    def test_stale_grace_inventory_remains_protected_then_expires(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = collector.deep_merge(
                collector.DEFAULTS,
                {
                    "state_db": str(root / "state.sqlite3"),
                    "node": {"id": "central", "central_url": ""},
                    "incoming_globs": [],
                    "lock_file": str(root / "collector.lock"),
                    "abuse_context": {"enabled": False},
                    "protection_inventory": {
                        "incoming_globs": [],
                        "processing_dir": str(root / "processing"),
                        "archive_dir": str(root / "archive"),
                        "rejected_dir": str(root / "rejected"),
                        "state_file": str(root / "effective.json"),
                        "active_max_age_seconds": 60,
                        "stale_grace_seconds": 120,
                    },
                    "crowdsec": {"enabled": False},
                    "abuse_reporting": {"enabled": False},
                },
            )
            instance = collector.Collector(config)
            try:
                inventory = collector.normalize_protection_inventory(
                    {
                        "schema_version": 1,
                        "inventory_uuid": "33333333-3333-4333-8333-333333333333",
                        "generated_at": collector.utc_text(
                            collector.utc_now() - dt.timedelta(seconds=90)
                        ),
                        "node_id": "vps-node",
                        "enabled": True,
                        "configured_mode": "host",
                        "effective_mode": "host",
                        "operator_confirmed": True,
                        "selection_source": "debconf",
                        "status": "active",
                        "configured_interfaces": [],
                        "effective_cidrs": ["2001:db8:500:1::10/128"],
                        "addresses": [],
                        "default_route_interfaces": ["eth0"],
                        "virtualization": {"type": "kvm", "is_virtual": True},
                        "recommendation": {"mode": "host"},
                    }
                )
                instance.db.import_protection_inventory(
                    inventory,
                    "c" * 64,
                    root / "inventory.json",
                )
                grace = instance.publish_effective_protection_state()
                instance.db.conn.execute(
                    "UPDATE node_protection_inventories SET generated_epoch=?",
                    (int(collector.utc_now().timestamp()) - 121,),
                )
                instance.db.conn.commit()
                expired = instance.publish_effective_protection_state()
            finally:
                instance.close()
            self.assertEqual("stale-grace", grace["nodes"][0]["freshness"])
            self.assertEqual(["2001:db8:500:1::10/128"], grace["dynamic_cidrs"])
            self.assertEqual("expired", expired["nodes"][0]["freshness"])
            self.assertEqual([], expired["dynamic_cidrs"])

    def test_root_processor_uses_fresh_dynamic_state_and_fails_closed_when_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "effective.json"
            config = root / "collector.json"
            now_epoch = int(dt.datetime.now(UTC).timestamp())
            state.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "generated_epoch": now_epoch,
                        "dynamic_cidrs": ["2001:db8:500:1::10/128"],
                        "dynamic_sources": {
                            "2001:db8:500:1::10/128": ["vps-node"]
                        },
                    }
                )
            )
            config.write_text(
                json.dumps(
                    {
                        "trusted_cidrs": [],
                        "enforcement_protection": {
                            "protected_cidrs": [],
                            "dynamic_state_file": str(state),
                            "dynamic_state_max_age_seconds": 600,
                        },
                        "policy": {
                            "network_block_min_ipv4_prefix_length": 24,
                            "network_block_min_ipv6_prefix_length": 48,
                        },
                    }
                )
            )
            policy = review_processor.load_network_policy(
                {"collector_config": str(config)}
            )
            with self.assertRaisesRegex(
                review_processor.ReviewError,
                "enforcement-protected",
            ):
                review_processor.validate_network_target(
                    "2001:db8:500:1::10/128",
                    "2001:db8:500:1::10/128",
                    policy,
                )
            payload = json.loads(state.read_text())
            payload["generated_epoch"] = now_epoch - 1000
            state.write_text(json.dumps(payload))
            with self.assertRaisesRegex(review_processor.ReviewError, "fail-closed"):
                review_processor.load_network_policy(
                    {"collector_config": str(config)}
                )

    def test_debconf_packaging_and_reconfiguration_are_present(self) -> None:
        config_script = (ROOT / "packaging/deb/agent.config").read_text()
        postinst = (ROOT / "packaging/deb/agent.postinst").read_text()
        templates = (ROOT / "packaging/deb/agent.templates").read_text()
        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn("DEBCONF_RECONFIGURE", config_script)
        self.assertIn("noninteractive-default", config_script)
        self.assertIn("network.prefixlen < minimum", config_script)
        self.assertIn("Choices-C: host, lan-prefix, manual, off", templates)
        self.assertIn("lan-confirm", templates)
        self.assertIn(
            "Description: Recommended local-address protection mode: ${RECOMMENDATION}",
            templates,
        )
        self.assertIn("Environment: ${ENVIRONMENT}", templates)
        self.assertIn("Detected public IPv6 addresses: ${ADDRESSES}", templates)
        self.assertNotIn("${SUMMARY}", templates)
        self.assertNotIn('print("\\\\n".join(lines))', config_script)
        self.assertIn(
            'db_subst argent-sentinel-agent/protection-discovery RECOMMENDATION',
            config_script,
        )
        self.assertIn("local_protection.py apply-config", postinst)
        self.assertIn('"config": ROOT / "packaging/deb/agent.config"', builder)
        self.assertIn('"templates": ROOT / "packaging/deb/agent.templates"', builder)
        self.assertIn("debconf", builder)
        self.assertIn("iproute2", builder)

    def test_agent_stages_protection_before_telemetry(self) -> None:
        order: list[str] = []
        config = {
            "enabled": True,
            "wordpress_globs": ["wordpress"],
            "abuse_context_globs": [],
            "pending_dir": "/tmp/unused-pending",
            "max_files_per_run": 25,
        }
        with (
            mock.patch.object(
                agent,
                "stage_protection_inventory",
                side_effect=lambda _config: order.append("protection") or 1,
            ),
            mock.patch.object(
                agent,
                "discover_files",
                side_effect=lambda patterns, _suffixes: (
                    [Path("event.json")] if patterns == ["wordpress"] else []
                ),
            ),
            mock.patch.object(
                agent,
                "stage_file",
                side_effect=lambda _config, _path, _kind: order.append("telemetry"),
            ),
            mock.patch.object(agent, "collect_sshd", return_value=0),
            mock.patch.object(Path, "glob", return_value=[]),
        ):
            agent.run_agent(config)
        self.assertEqual(["protection", "telemetry"], order)

    def test_agent_prioritizes_protection_inventory_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / "event.json"
            protection = root / "protection.json"
            event.write_text(json.dumps({"kind": "event_batch"}))
            protection.write_text(json.dumps({"kind": "protection_inventory"}))
            ordered = sorted(
                [event, protection],
                key=agent.pending_delivery_key,
            )
            self.assertEqual(protection, ordered[0])

    def test_api_rejects_non_host_prefix_in_effective_host_mode(self) -> None:
        inventory = {
            "schema_version": 1,
            "inventory_uuid": "8dc202ea-43a3-45b8-b081-bfabfb4e3af7",
            "generated_at": "2026-07-30T02:00:00Z",
            "node_id": "vps-node",
            "enabled": True,
            "configured_mode": "lan-prefix",
            "effective_mode": "host",
            "operator_confirmed": False,
            "selection_source": "safe-default",
            "status": "confirmation-required",
            "configured_interfaces": ["eth0"],
            "effective_cidrs": ["2001:db8:500:1::/64"],
            "addresses": [],
            "default_route_interfaces": ["eth0"],
            "virtualization": {"type": "kvm", "is_virtual": True},
            "recommendation": {"mode": "host"},
        }
        with self.assertRaisesRegex(server_api.APIError, "Host mode"):
            server_api.validate_protection_inventory(
                json.dumps(inventory).encode(),
                {"node_id": "vps-node"},
            )

    def test_debconf_pre_unpack_discovery_is_self_contained(self) -> None:
        source = (ROOT / "packaging/deb/agent.config").read_text()
        script = source.split(
            "<<'PYDISCOVERY' >/dev/null 2>&1 || true\n",
            1,
        )[1].split("\nPYDISCOVERY", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            ip_command = fake_bin / "ip"
            ip_command.write_text(
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "  *\" address \"*) cat <<'JSON'\n"
                "[{\"ifname\":\"eth0\",\"addr_info\":[{\"family\":\"inet6\",\"local\":\"2001:db8:500:1::10\",\"prefixlen\":64,\"scope\":\"global\"}]}]\n"
                "JSON\n"
                "  ;;\n"
                "  *\" route \"*) cat <<'JSON'\n"
                "[{\"dev\":\"eth0\",\"gateway\":\"2001:db8:500:1::1\",\"protocol\":\"static\"}]\n"
                "JSON\n"
                "  ;;\n"
                "esac\n"
            )
            ip_command.chmod(0o755)
            virt_command = fake_bin / "systemd-detect-virt"
            virt_command.write_text("#!/bin/sh\nprintf 'kvm\\n'\n")
            virt_command.chmod(0o755)
            output = root / "discovery.json"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
            result = subprocess.run(
                [sys.executable, "-", str(output)],
                input=script,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(output.read_text())
            self.assertEqual("host", payload["recommendation"]["mode"])
            self.assertEqual(["eth0"], payload["recommendation"]["interfaces"])
            self.assertEqual("2001:db8:500:1::10", payload["addresses"][0]["address"])

    def test_debconf_discovery_rejects_overly_broad_lan_recommendation(self) -> None:
        source = (ROOT / "packaging/deb/agent.config").read_text()
        script = source.split(
            "<<'PYDISCOVERY' >/dev/null 2>&1 || true\n",
            1,
        )[1].split("\nPYDISCOVERY", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            ip_command = fake_bin / "ip"
            ip_command.write_text(
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "  *\" address \"*) cat <<'JSON'\n"
                "[{\"ifname\":\"eno1\",\"addr_info\":[{\"family\":\"inet6\",\"local\":\"2001:db8:700::10\",\"prefixlen\":32,\"scope\":\"global\",\"dynamic\":true}]}]\n"
                "JSON\n"
                "  ;;\n"
                "  *\" route \"*) cat <<'JSON'\n"
                "[{\"dev\":\"eno1\",\"gateway\":\"fe80::1\",\"protocol\":\"ra\"}]\n"
                "JSON\n"
                "  ;;\n"
                "esac\n"
            )
            ip_command.chmod(0o755)
            virt_command = fake_bin / "systemd-detect-virt"
            virt_command.write_text("#!/bin/sh\nprintf 'none\n'\nexit 1\n")
            virt_command.chmod(0o755)
            output = root / "discovery.json"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
            result = subprocess.run(
                [sys.executable, "-", str(output)],
                input=script,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(output.read_text())
            self.assertEqual("host", payload["recommendation"]["mode"])
            self.assertIn("broader than /48", payload["recommendation"]["reason"])

    def test_dashboard_displays_node_protection_inventory(self) -> None:
        html = dashboard.render_networks(
            {
                "network_cases": [],
                "network_review_actions": [],
                "local_address_protection": {
                    "nodes": [
                        {
                            "node_id": "vps-node",
                            "configured_mode": "host",
                            "effective_mode": "host",
                            "freshness": "active",
                            "operator_confirmed": True,
                            "selection_source": "debconf",
                            "addresses": [
                                {
                                    "interface": "eth0",
                                    "address": "2001:db8:500:1::10",
                                    "prefix_length": 64,
                                }
                            ],
                            "effective_cidrs": [
                                "2001:db8:500:1::10/128"
                            ],
                            "generated_at": "2026-07-30T02:00:00Z",
                        }
                    ]
                },
            },
            {"review_note_max_chars": 2000},
        )
        self.assertIn("Dynamic local-address protection", html)
        self.assertIn("vps-node", html)
        self.assertIn("2001:db8:500:1::10/128", html)


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v0540.py
