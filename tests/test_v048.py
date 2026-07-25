#!/usr/bin/env python3
# Argent Sentinel v0.4.8 SSH normalization regression tests.

from __future__ import annotations

from pathlib import Path
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402


class V048Test(unittest.TestCase):
    def make_batch(self, field: str, token: str) -> dict:
        return {
            "schema_version": 1,
            "batch_uuid": str(uuid.uuid4()),
            "created_at": "2026-07-25T03:18:55Z",
            "source": {
                "host": "nidhoggur",
                "site_id": "sshd-nidhoggur",
                "site_url": "ssh://nidhoggur.example:22/",
                "service": "sshd",
                "plugin_version": "0.4.8",
            },
            "events": [
                {
                    "event_uuid": str(uuid.uuid4()),
                    "occurred_at": "2026-07-25T03:18:55Z",
                    "recorded_at": "2026-07-25T03:18:56Z",
                    "event_type": "ssh_auth_failed",
                    "outcome": "denied",
                    "source_ip": "2001:db8::123",
                    "source_port": 49938,
                    "destination_ip": "203.0.113.10",
                    "destination_port": 22,
                    "transport_protocol": "TCP",
                    "application_protocol": "SSH",
                    field: token,
                    "metadata": {
                        "account_class": "invalid",
                        "auth_method": "invalid-user-preauth",
                    },
                }
            ],
        }

    def test_canonical_account_key_survives_normalize_batch(self) -> None:
        token = "a" * 64
        _, events = collector.normalize_batch(
            self.make_batch("account_key", token)
        )
        self.assertEqual(
            f"sshd-nidhoggur:account:{token}",
            events[0]["account_key"],
        )

    def test_legacy_account_hash_survives_normalize_batch(self) -> None:
        token = "b" * 64
        _, events = collector.normalize_batch(
            self.make_batch("account_hash", token)
        )
        self.assertEqual(
            f"sshd-nidhoggur:account:{token}",
            events[0]["account_key"],
        )

    def test_canonical_key_takes_precedence_over_legacy_alias(self) -> None:
        canonical = "c" * 64
        legacy = "d" * 64
        batch = self.make_batch("account_key", canonical)
        batch["events"][0]["account_hash"] = legacy
        _, events = collector.normalize_batch(batch)
        self.assertEqual(
            f"sshd-nidhoggur:account:{canonical}",
            events[0]["account_key"],
        )

    def test_invalid_non_wordpress_token_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            collector.CollectorError,
            "SHA-256 hex value",
        ):
            collector.normalize_batch(
                self.make_batch("account_key", "not-a-valid-token")
            )

    def test_eight_canonical_accounts_remain_distinct(self) -> None:
        batch = self.make_batch("account_key", "0" * 64)
        source_ip = "2001:db8::123"
        batch["events"] = []
        for index in range(8):
            batch["events"].append(
                {
                    "event_uuid": str(uuid.uuid4()),
                    "occurred_at": (
                        "2026-07-25T03:18:54Z"
                        if index < 2
                        else "2026-07-25T03:18:55Z"
                    ),
                    "recorded_at": "2026-07-25T03:18:56Z",
                    "event_type": "ssh_auth_failed",
                    "outcome": "denied",
                    "source_ip": source_ip,
                    "source_port": 49938 + index,
                    "destination_ip": "203.0.113.10",
                    "destination_port": 22,
                    "transport_protocol": "TCP",
                    "application_protocol": "SSH",
                    "account_key": f"{index:064x}",
                    "metadata": {
                        "account_class": "invalid",
                        "auth_method": "invalid-user-preauth",
                    },
                }
            )

        _, events = collector.normalize_batch(batch)
        self.assertEqual(
            8,
            len({event["account_key"] for event in events}),
        )


if __name__ == "__main__":
    unittest.main()
