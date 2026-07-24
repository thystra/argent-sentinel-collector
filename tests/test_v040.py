#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import importlib.util
import json
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector_module = load("argent_collector_v040", ROOT / "src/collector.py")
agent_module = load("argent_agent_v040", ROOT / "src/agent.py")
api_module = load("argent_api_v040", ROOT / "src/server_api.py")


class V040Test(unittest.TestCase):
    def make_collector(self, root: Path, *, context: bool = False):
        incoming = root / "events"
        context_incoming = root / "context"
        incoming.mkdir(parents=True)
        context_incoming.mkdir(parents=True)
        config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "state_db": str(root / "state.sqlite3"),
                "lock_file": str(root / "collector.lock"),
                "incoming_globs": [str(incoming / "*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "crowdsec": {"enabled": False},
                "enrichment": {"enabled": False},
                "abuse_reporting": {"enabled": False},
                "abuse_context": {
                    "enabled": context,
                    "incoming_globs": [str(context_incoming / "*.jsonl")],
                    "processing_dir": str(root / "context-processing"),
                    "archive_dir": str(root / "context-archive"),
                    "rejected_dir": str(root / "context-rejected"),
                },
            },
        )
        return collector_module.Collector(config), config, incoming, context_incoming

    def test_agent_uses_system_server_ca_and_requires_enrollment_when_enabled(self) -> None:
        self.assertEqual(
            "/etc/ssl/certs/ca-certificates.crt",
            agent_module.DEFAULTS["ca_file"],
        )
        config = agent_module.deep_merge(agent_module.DEFAULTS, {
            "enabled": True,
            "node": {"id": "hermod", "fqdn": "hermod.argentwolf.org"},
            "cert_file": "/nonexistent/node.crt",
            "key_file": "/nonexistent/node.key",
        })
        with self.assertRaises(agent_module.AgentError):
            agent_module.validate_config(config)

    def test_sshd_parser_hashes_username_and_keeps_network_tuple(self) -> None:
        row = {
            "MESSAGE": "Failed publickey for alan from 198.51.100.44 port 54211 ssh2",
            "__CURSOR": "s=unit-test",
            "__REALTIME_TIMESTAMP": "1784900000000000",
        }
        event = agent_module.parse_sshd_row(
            row,
            node_id="hermod",
            secret=b"x" * 32,
            destination_ip="203.0.113.15",
            destination_port=22,
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual("198.51.100.44", event["source_ip"])
        self.assertEqual(54211, event["source_port"])
        self.assertEqual("203.0.113.15", event["destination_ip"])
        self.assertEqual(22, event["destination_port"])
        self.assertEqual(64, len(event["account_hash"]))
        self.assertNotIn("alan", json.dumps(event))
        invalid_event = agent_module.parse_sshd_row(
            {"MESSAGE": "Invalid user administrator from 198.51.100.44 port 54211", "__CURSOR": "x"},
            node_id="hermod", secret=b"x" * 32, destination_ip="203.0.113.15", destination_port=22,
        )
        self.assertIsNotNone(invalid_event)
        assert invalid_event is not None
        self.assertEqual("invalid", invalid_event["metadata"]["account_class"])
        self.assertEqual("invalid-user-preauth", invalid_event["metadata"]["auth_method"])

    def test_remote_ingress_is_authorized_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nodes = root / "nodes"
            nodes.mkdir()
            (nodes / "hermod.json").write_text(json.dumps({
                "node_id": "hermod", "enabled": True,
                "services": ["sshd"], "site_ids": [],
            }))
            config = api_module.deep_merge(api_module.DEFAULTS, {
                "nodes_dir": str(nodes),
                "receipt_db": str(root / "receipts.sqlite3"),
                "event_drop_root": str(root / "drop"),
            })
            event = {
                "event_uuid": str(uuid.uuid4()), "occurred_at": "2026-07-24T15:00:00Z",
                "event_type": "ssh_auth_failed", "outcome": "denied",
                "source_ip": "198.51.100.9", "account_hash": "a" * 64,
            }
            payload = json.dumps({
                "schema_version": 1, "batch_uuid": str(uuid.uuid4()),
                "created_at": "2026-07-24T15:00:01Z",
                "source": {"host": "hermod", "site_id": "sshd-hermod",
                           "site_url": "ssh://hermod.argentwolf.org:22/", "service": "sshd",
                           "plugin_version": "0.4.0"},
                "events": [event],
            }).encode()
            envelope = agent_module.make_envelope("hermod", "event_batch", payload)
            raw = json.dumps(envelope).encode()
            ingress = api_module.Ingress(config)
            status, result = ingress.accept(raw, "hermod")
            self.assertEqual(201, status)
            stored = list((root / "drop" / "hermod" / "events" / "incoming").glob("*.json"))
            self.assertEqual(1, len(stored))
            status2, result2 = ingress.accept(raw, "hermod")
            self.assertEqual(200, status2)
            self.assertEqual("duplicate", result2["status"])
            with self.assertRaises(api_module.APIError):
                ingress.accept(raw, "nidhoggur")

    def test_remote_ingress_handles_concurrent_duplicate_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nodes = root / "nodes"
            nodes.mkdir()
            (nodes / "hermod.json").write_text(json.dumps({
                "node_id": "hermod", "enabled": True,
                "services": ["sshd"], "site_ids": [],
            }))
            config = api_module.deep_merge(api_module.DEFAULTS, {
                "nodes_dir": str(nodes),
                "receipt_db": str(root / "receipts.sqlite3"),
                "event_drop_root": str(root / "drop"),
            })
            payload = json.dumps({
                "schema_version": 1, "batch_uuid": str(uuid.uuid4()),
                "created_at": "2026-07-24T15:00:01Z",
                "source": {"host": "hermod", "site_id": "sshd-hermod",
                           "site_url": "ssh://hermod.argentwolf.org:22/", "service": "sshd",
                           "plugin_version": "0.4.0"},
                "events": [{"event_uuid": str(uuid.uuid4()),
                            "occurred_at": "2026-07-24T15:00:00Z",
                            "event_type": "ssh_auth_failed", "outcome": "denied",
                            "source_ip": "198.51.100.9", "account_hash": "a" * 64}],
            }).encode()
            raw = json.dumps(agent_module.make_envelope("hermod", "event_batch", payload)).encode()
            ingress = api_module.Ingress(config)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: ingress.accept(raw, "hermod")[0], range(8)))
            self.assertEqual(1, results.count(201))
            self.assertEqual(7, results.count(200))
            self.assertEqual(
                1,
                len(list((root / "drop" / "hermod" / "events" / "incoming").glob("*.json"))),
            )

    def test_sshd_batch_creates_reportable_incident(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            collector, _, incoming, _ = self.make_collector(root)
            try:
                now = collector_module.utc_now().replace(microsecond=0)
                events = []
                for index in range(8):
                    when = now + dt.timedelta(seconds=index * 5)
                    events.append({
                        "event_uuid": str(uuid.uuid4()),
                        "occurred_at": collector_module.utc_text(when),
                        "recorded_at": collector_module.utc_text(when),
                        "event_type": "ssh_auth_failed", "outcome": "denied",
                        "source_ip": "198.51.100.77", "source_port": 50000 + index,
                        "destination_ip": "203.0.113.10", "destination_port": 22,
                        "transport_protocol": "TCP", "application_protocol": "SSH",
                        "account_hash": f"{index % 3 + 1:064x}", "metadata": {},
                    })
                batch = {
                    "schema_version": 1, "batch_uuid": str(uuid.uuid4()),
                    "created_at": collector_module.utc_text(now),
                    "source": {"host": "nidhoggur", "site_id": "sshd-nidhoggur",
                               "site_url": "ssh://nidhoggur.argentwolf.org:22/", "service": "sshd",
                               "plugin_version": "0.4.0"},
                    "events": events,
                }
                (incoming / "sshd.json").write_text(json.dumps(batch))
                collector.run()
                incident = collector.db.conn.execute(
                    "SELECT * FROM incidents WHERE rule_id='sshd-credential-spray'"
                ).fetchone()
                self.assertIsNotNone(incident)
                self.assertEqual(8, incident["event_count"])
            finally:
                collector.close()

    def test_abuse_context_creates_web_probe_incident(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            collector, _, _, context_incoming = self.make_collector(root, context=True)
            try:
                now = collector_module.utc_now().replace(microsecond=0)
                paths = ["/.env", "/wp-config.php.bak", "/cgi-bin/test?cmd=id"]
                rows = []
                for index, path in enumerate(paths):
                    rows.append({
                        "occurred_at": collector_module.utc_text(now + dt.timedelta(seconds=index)),
                        "request_id": f"request{index:010d}",
                        "source_ip": "198.51.100.88", "source_port": 51000 + index,
                        "destination_ip": "203.0.113.10", "destination_port": 443,
                        "transport_protocol": "TCP", "application_protocol": "HTTP/2.0",
                        "tls_protocol": "TLSv1.3", "host": "example.org",
                        "request_method": "GET", "request_uri": path,
                        "http_status": 404, "user_agent": "scanner",
                    })
                (context_incoming / "web.jsonl").write_text("\n".join(json.dumps(x) for x in rows) + "\n")
                collector.run()
                incident = collector.db.conn.execute(
                    "SELECT * FROM incidents WHERE rule_id='nginx-hostile-web-probing'"
                ).fetchone()
                self.assertIsNotNone(incident)
                self.assertEqual(3, incident["event_count"])
            finally:
                collector.close()

    def test_client_subject_cn_extraction_is_strict(self) -> None:
        self.assertEqual("hermod", api_module.client_node_from_subject("CN=hermod"))
        self.assertEqual(
            "nidhoggur",
            api_module.client_node_from_subject("O=Argent Sentinel,CN=nidhoggur"),
        )
        with self.assertRaises(api_module.APIError):
            api_module.client_node_from_subject("")
        with self.assertRaises(api_module.APIError):
            api_module.client_node_from_subject("CN=hermod,CN=nidhoggur")
        with self.assertRaises(api_module.APIError):
            api_module.client_node_from_subject("CN=bad node")

    def test_client_subject_cn_extraction_is_strict(self) -> None:
        self.assertEqual("hermod", api_module.client_node_from_subject("CN=hermod"))
        self.assertEqual(
            "nidhoggur",
            api_module.client_node_from_subject("O=Argent Sentinel,CN=nidhoggur"),
        )
        with self.assertRaises(api_module.APIError):
            api_module.client_node_from_subject("")
        with self.assertRaises(api_module.APIError):
            api_module.client_node_from_subject("CN=hermod,CN=nidhoggur")
        with self.assertRaises(api_module.APIError):
            api_module.client_node_from_subject("CN=bad node")

    def test_registry_abuse_addresses_are_filtered(self) -> None:
        payload = {"entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@arin.net"],
                                                             ["email", {}, "text", "abuse@example.net"]]]}]}
        self.assertEqual({"abuse@example.net"}, collector_module.extract_abuse_emails(payload))


if __name__ == "__main__":
    unittest.main()
