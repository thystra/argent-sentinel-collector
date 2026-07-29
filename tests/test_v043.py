#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/collector.py"
spec = importlib.util.spec_from_file_location("argent_collector_v043", MODULE_PATH)
assert spec and spec.loader
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)
UTC = dt.timezone.utc
FIXED_NOW = dt.datetime(2026, 7, 24, 22, 0, 0, tzinfo=UTC)


class CompletedSendmail:
    returncode = 0
    stdout = b""
    stderr = b""


class V043Test(unittest.TestCase):
    def setUp(self) -> None:
        self.original_utc_now = collector_module.utc_now
        collector_module.utc_now = lambda: FIXED_NOW
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = collector_module.deep_merge(
            collector_module.DEFAULTS,
            {
                "state_db": str(root / "state.sqlite3"),
                "lock_file": str(root / "collector.lock"),
                "incoming_globs": [str(root / "incoming/*.json")],
                "processing_dir": str(root / "processing"),
                "archive_dir": str(root / "archive"),
                "rejected_dir": str(root / "rejected"),
                "crowdsec": {"enabled": True},
                "abuse_reporting": {
                    "enabled": True,
                    "test_mode": True,
                    "from": "postmaster@argentwolf.org",
                    "admin_copy": "postmaster@argentwolf.org",
                    "recipient_override": "goshawk066@gmail.com",
                    "operator_contact": "postmaster@argentwolf.org",
                    "reporter_org": "Argent Wolf",
                    "reporter_org_domain": "argentwolf.org",
                    "reporter_contact_name": "Server Operator",
                    "attach_xarf": True,
                    "xarf_version": "4.2.0",
                    "xarf_max_evidence_lines": 20,
                    "resolve_target_dns": False,
                    "resolve_source_rdns": False,
                    "public_target_ips": [
                        "108.226.59.220",
                        "2600:1702:6530:bdff:abac:7ca7:c15a:6646",
                    ],
                },
            },
        )
        self.collector = collector_module.Collector(self.config)

    def tearDown(self) -> None:
        self.collector.close()
        self.temp.cleanup()
        collector_module.utc_now = self.original_utc_now

    def test_web_report_format_and_xarf_attachment(self) -> None:
        incident = {
            "incident_uuid": "11111111-2222-4333-8444-555555555555",
            "source_ip": "20.151.13.152",
            "rule_id": "nginx-hostile-web-probing",
            "first_seen": "2026-07-23T17:19:38Z",
            "last_seen": "2026-07-23T17:19:38Z",
            "event_count": 3,
            "distinct_accounts": 1,
            "site_count": 1,
            "network_cidr": "20.128.0.0/9",
            "registered_cidr": "20.150.0.0/15",
            "asn": 8075,
            "asn_holder": "Microsoft Corporation",
            "decision_status": "refused",
        }
        evidence = []
        network = []
        for index, source_port in enumerate((60932, 60356, 60933), 1):
            event_uuid = f"00000000-0000-4000-8000-{index:012d}"
            metadata = {
                "probe_category": "wp-content-php-probe",
                "http_status": 444,
                "host": "arnhalla.com",
            }
            evidence.append({
                "event_uuid": event_uuid,
                "occurred_at": "2026-07-23T17:19:38Z",
                "source_ip": "20.151.13.152",
                "source_port": source_port,
                "destination_ip": "192.168.1.29",
                "destination_port": 80,
                "transport_protocol": "TCP",
                "application_protocol": "HTTP/1.1",
                "request_method": "GET",
                "request_path": "/wp-content/plugins/hellopress/wp_filemanager.php",
                "user_agent": None,
                "metadata_json": json.dumps(metadata),
            })
            network.append({
                "observation_uuid": f"10000000-0000-4000-8000-{index:012d}",
                "occurred_at": "2026-07-23T17:19:38Z",
                "source_ip": "20.151.13.152",
                "source_port": source_port,
                "destination_ip": "192.168.1.29",
                "destination_port": 80,
                "transport_protocol": "TCP",
                "application_protocol": "HTTP/1.1",
                "tls_protocol": None,
                "host": "arnhalla.com",
                "server_name": "_",
                "request_method": "GET",
                "request_uri": "/wp-content/plugins/hellopress/wp_filemanager.php",
                "http_status": 444,
                "user_agent": None,
                "correlation_method": "request-id",
            })

        self.collector.db.incident_evidence = mock.Mock(return_value=evidence)
        self.collector.db.incident_sites = mock.Mock(return_value=["nginx-nidhoggur"])
        self.collector.db.incident_network_evidence = mock.Mock(return_value=network)
        self.collector.source_protection_status = lambda source_ip: (
            "protected",
            "CrowdSec reports address is allowlisted",
        )
        enrichment = {
            "network_cidr": "20.150.0.0/15",
            "network_name": "MSFT",
            "asn": 8075,
            "asn_holder": "Microsoft Corporation",
            "abuse_emails": ["abuse@microsoft.com"],
            "network_class": "hosting",
        }

        with mock.patch.object(
            collector_module.subprocess,
            "run",
            return_value=CompletedSendmail(),
        ) as sendmail:
            status, detail, message_id = self.collector.send_abuse_report(
                incident,
                enrichment,
                ["goshawk066@gmail.com"],
            )

        self.assertEqual("sent", status)
        self.assertIn("test bypass", detail)
        self.assertIsNotNone(message_id)
        payload = sendmail.call_args.kwargs["input"]
        message = BytesParser(policy=policy.default).parsebytes(payload)
        self.assertEqual("goshawk066@gmail.com", str(message["To"]))
        self.assertIsNone(message["Bcc"])
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertTrue(body.startswith("*** TEST MODE ***\n"))
        self.assertEqual(2, body.count("*** TEST MODE ***"))
        self.assertLess(body.find("*** TEST MODE ***"), body.find("Hello,"))
        self.assertIn("Source IP: 20.151.13.152", body)
        self.assertIn("Affected site(s): arnhalla.com", body)
        self.assertIn("Connection details:", body)
        self.assertIn("src=20.151.13.152:60932", body)
        self.assertIn("dst=108.226.59.220:80", body)
        self.assertIn("observed_dst=192.168.1.29:80", body)
        self.assertIn("wp-content-php-probe: 3", body)
        self.assertIn("444: 3", body)
        self.assertIn("XARF JSON report is attached", body)

        attachments = list(message.iter_attachments())
        self.assertEqual(1, len(attachments))
        attachment = attachments[0]
        self.assertEqual("xarf.json", attachment.get_filename())
        self.assertEqual("application/json", attachment.get_content_type())
        xarf = json.loads(attachment.get_payload(decode=True))
        self.assertEqual("4.2.0", xarf["xarf_version"])
        self.assertEqual("connection", xarf["category"])
        self.assertEqual("vulnerability_scan", xarf["type"])
        self.assertEqual("20.151.13.152", xarf["source_identifier"])
        self.assertEqual(60932, xarf["source_port"])
        self.assertEqual("108.226.59.220", xarf["destination_ip"])
        self.assertEqual([80], xarf["targeted_ports"])
        self.assertEqual("arnhalla.com", xarf["destination_fqdn"])
        self.assertEqual("web_vuln_scan", xarf["scan_type"])
        self.assertEqual("tcp", xarf["protocol"])
        tuples = xarf["connection_tuples"]
        self.assertEqual(3, len(tuples))
        self.assertEqual(
            "192.168.1.29", tuples[0]["observed_destination_ip"]
        )
        self.assertEqual("108.226.59.220", tuples[0]["destination_ip"])
        self.assertNotIn("abuse@microsoft.com", json.dumps(xarf))
        evidence = xarf["evidence"]
        self.assertGreaterEqual(len(evidence), 1)
        self.assertTrue(evidence[0]["payload"])
        self.assertRegex(evidence[0]["hash"], r"^sha256:[0-9a-f]{64}$")

    def test_release_and_collector_unit(self) -> None:
        self.assertEqual("0.5.2.1", (ROOT / "VERSION").read_text().strip())
        for name in ("agent.py", "collector.py", "server_api.py"):
            self.assertIn(
                'APP_VERSION = "0.5.2.1"',
                (ROOT / "src" / name).read_text(),
            )
        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('if upstream != "0.5.2.1":', builder)
        self.assertIn('"test_v043.py"', builder)
        unit = (
            ROOT / "packaging/systemd/argent-sentinel-collector.service"
        ).read_text()
        self.assertIn(
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            unit,
        )


if __name__ == "__main__":
    unittest.main()
