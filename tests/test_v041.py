#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent_module = load("argent_agent_v041", ROOT / "src/agent.py")


class V041Test(unittest.TestCase):
    def parse(self, message: str, cursor: str = "cursor"):
        return agent_module.parse_sshd_row(
            {
                "MESSAGE": message,
                "__CURSOR": cursor,
                "__REALTIME_TIMESTAMP": "1784919737003944",
            },
            node_id="nidhoggur",
            secret=b"x" * 32,
            destination_ip="108.226.59.220",
            destination_port=22,
        )

    def test_invalid_user_ipv6_is_counted_once(self) -> None:
        event = self.parse(
            "Invalid user sentinel-test from "
            "2600:1702:6530:bdff:1b9e:74eb:63af:20a port 56284"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(
            "2600:1702:6530:bdff:1b9e:74eb:63af:20a",
            event["source_ip"],
        )
        self.assertEqual("invalid", event["metadata"]["account_class"])
        self.assertEqual("invalid-user-preauth", event["metadata"]["auth_method"])
        self.assertNotIn("sentinel-test", json.dumps(event))

        self.assertIsNone(self.parse(
            "Connection closed by invalid user sentinel-test "
            "2600:1702:6530:bdff:1b9e:74eb:63af:20a port 56284 [preauth]",
            "close-cursor",
        ))
        self.assertIsNone(self.parse(
            "Failed publickey for invalid user sentinel-test from "
            "198.51.100.44 port 56284 ssh2",
            "duplicate-cursor",
        ))

    def test_known_user_failed_publickey_remains_supported(self) -> None:
        event = self.parse(
            "Failed publickey for alan from 198.51.100.44 port 54211 ssh2"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual("known-or-unresolved", event["metadata"]["account_class"])
        self.assertEqual("publickey", event["metadata"]["auth_method"])
        self.assertNotIn("alan", json.dumps(event))

    def test_v041_runtime_layout_and_versions(self) -> None:
        self.assertEqual("0.4.2", (ROOT / "VERSION").read_text().strip())
        for name in ("agent.py", "collector.py", "server_api.py"):
            self.assertIn(
                'APP_VERSION = "0.4.2"',
                (ROOT / "src" / name).read_text(),
            )

        package_builder = (
            ROOT / "packaging/build_debs.py"
        ).read_text()
        self.assertIn('if upstream != "0.4.2":', package_builder)
        self.assertIn('"test_v041.py"', package_builder)
        self.assertIn('"test_v042.py"', package_builder)

        api_unit = (
            ROOT / "packaging/systemd/argent-sentinel-api.service"
        ).read_text()
        self.assertIn(
            "RuntimeDirectory=argent-sentinel argent-sentinel-api",
            api_unit,
        )
        self.assertIn("RuntimeDirectoryMode=0755", api_unit)
        self.assertIn("RuntimeDirectoryPreserve=yes", api_unit)
        self.assertIn("ReadWritePaths=/run/argent-sentinel-api", api_unit)

        for name in (
            "argent-sentinel-agent.service",
            "argent-sentinel-collector.service",
        ):
            unit = (ROOT / "packaging/systemd" / name).read_text()
            self.assertIn("RuntimeDirectoryMode=0755", unit)
            self.assertIn("RuntimeDirectoryPreserve=yes", unit)

        api_example = json.loads(
            (ROOT / "config/server-api.json.example").read_text()
        )
        self.assertEqual(
            "/run/argent-sentinel-api/api.sock",
            api_example["socket_path"],
        )
        nginx = (ROOT / "config/nginx-sentinel.conf.example").read_text()
        self.assertEqual(2, nginx.count("/run/argent-sentinel-api/api.sock"))


if __name__ == "__main__":
    unittest.main()
