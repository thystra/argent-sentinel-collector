#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collector  # noqa: E402
import nginx_429_export  # noqa: E402
import review_digest  # noqa: E402


class V0410Test(unittest.TestCase):
    def test_release_versions(self) -> None:
        self.assertEqual("0.5.5.1", (ROOT / "VERSION").read_text().strip())
        for module in (collector, nginx_429_export, review_digest):
            self.assertEqual("0.5.5.1", module.APP_VERSION)

    def test_extended_nginx_429_line_parser(self) -> None:
        line = (
            '2a03:2880:f812:17:: - - [24/Jul/2026:21:33:55 -0400] '
            '"GET /picture.php?/2193/category/32 HTTP/2.0" 429 571 "-" '
            '"Mozilla/5.0 compatible; meta-externalagent/1.1" '
            'src_ip="2a03:2880:f812:17::" src_port="53856" '
            'dst_ip="2600:1702:6530:bdff::1" dst_port="443" '
            'host="photos.argentwolf.org" server_name="photos.argentwolf.org" '
            'scheme="https"'
        )
        parsed = nginx_429_export.parse_access_line(
            line,
            source_host="nidhoggur",
            log_path="/var/log/nginx/access.log",
            device=1,
            inode=2,
            byte_offset=3,
        )
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(429, parsed["http_status"])
        self.assertEqual("2a03:2880:f812:17::", parsed["source_ip"])
        self.assertEqual("/picture.php?/2193/category/32", parsed["request_uri"])
        self.assertEqual("photos.argentwolf.org", parsed["host"])

    def test_meta_variants_group_under_one_identity(self) -> None:
        rows = [
            {
                "occurred_epoch": 1000,
                "source_ip": "2a03:2880:f812:1::",
                "host": "photos.example",
                "request_uri": "/one",
                "user_agent": "Mozilla Windows Chrome meta-externalagent/1.1",
            },
            {
                "occurred_epoch": 1400,
                "source_ip": "2a03:2880:f812:2::",
                "host": "photos.example",
                "request_uri": "/two",
                "user_agent": "Mozilla Macintosh Safari meta-externalagent/1.1",
            },
        ]
        groups = review_digest.aggregate_429(rows)
        self.assertEqual(1, len(groups))
        self.assertEqual("crawler:meta-externalagent", groups[0]["identity"])
        self.assertEqual("2a03:2880:f812::/48", groups[0]["prefix"])

    def test_long_block_recommendations_are_review_only(self) -> None:
        policy = dict(collector.DEFAULTS["policy"])
        status, days, detail = collector.network_case_recommendation(
            policy, hostile_ips=20, incident_count=30, active_days=1
        )
        self.assertEqual("long-block-review", status)
        self.assertEqual(180, days)
        self.assertIn("operator review", detail)
        status, days, _ = collector.network_case_recommendation(
            policy, hostile_ips=50, incident_count=60, active_days=1
        )
        self.assertEqual("long-block-review", status)
        self.assertEqual(365, days)

    def test_registered_cidr_groups_multiple_fallback_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = collector.StateDB(Path(temporary) / "state.sqlite3")
            try:
                now = int(dt.datetime.now(dt.timezone.utc).timestamp())
                for index, source_ip in enumerate(("203.0.113.10", "203.0.114.20"), 1):
                    event_time = collector.epoch_text(now - index)
                    database.conn.execute(
                        """INSERT INTO incidents (
                            incident_uuid, source_ip, rule_id,
                            first_seen_epoch, last_seen_epoch,
                            first_seen, last_seen, event_count,
                            distinct_accounts, site_count,
                            network_cidr, registered_cidr,
                            network_class, decision_status,
                            report_status, created_at, updated_at
                        ) VALUES (?, ?, 'test', ?, ?, ?, ?, 1, 0, 1,
                                  ?, '203.0.0.0/16', 'hosting',
                                  'none', 'suppressed', ?, ?)""",
                        (
                            str(uuid.uuid4()), source_ip, now - index, now - index,
                            event_time, event_time,
                            collector.candidate_network(source_ip), event_time, event_time,
                        ),
                    )
                database.conn.commit()
                policy = dict(collector.DEFAULTS["policy"])
                policy["network_review_distinct_ips"] = 2
                candidates = database.network_candidates(policy)
                self.assertEqual(1, len(candidates))
                self.assertEqual("203.0.0.0/16", candidates[0]["network_cidr"])
                self.assertEqual(2, candidates[0]["hostile_ips"])
                self.assertEqual("registered", candidates[0]["grouping_basis"])
            finally:
                database.close()

    def test_review_database_is_query_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "review.sqlite3"
            connection = sqlite3.connect(database_path)
            connection.execute("CREATE TABLE example(value INTEGER)")
            connection.execute("INSERT INTO example VALUES (7)")
            connection.commit()
            connection.close()
            config = {
                "state_db": str(database_path),
                "lock_file": str(Path(temporary) / "collector.lock"),
            }
            with review_digest.open_review_database(config) as opened:
                self.assertEqual(7, opened.execute("SELECT value FROM example").fetchone()[0])
                self.assertEqual(1, opened.execute("PRAGMA query_only").fetchone()[0])

    def test_custom_policy_uses_runtime_network_defaults(self) -> None:
        merged = collector.deep_merge(
            collector.DEFAULTS,
            {"policy": {"failure_threshold": 99}},
        )
        self.assertEqual(99, merged["policy"]["failure_threshold"])
        self.assertEqual(
            16,
            merged["policy"]["network_long_block_distinct_ips"],
        )
        self.assertEqual(
            180,
            merged["policy"]["network_long_block_days"],
        )
        self.assertEqual(
            365,
            merged["policy"]["network_severe_block_days"],
        )

    def test_review_database_remains_application_read_only(self) -> None:
        source = (ROOT / "src/review_digest.py").read_text()
        self.assertIn("?mode=ro", source)
        self.assertIn("PRAGMA query_only=ON", source)
        self.assertIn("PRAGMA busy_timeout=5000", source)

    def test_new_systemd_assets_exist(self) -> None:
        for relative in (
            "packaging/systemd/argent-sentinel-nginx-429-export.service",
            "packaging/systemd/argent-sentinel-nginx-429-export.timer",
            "packaging/bin/argent-sentinel-nginx-429-export",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)
        review_unit = (
            ROOT / "packaging/systemd/argent-sentinel-review-digest.service"
        ).read_text()
        self.assertNotIn(
            "ReadOnlyPaths=/var/lib/argent-sentinel/collector",
            review_unit,
        )
        self.assertIn(
            "ReadWritePaths=/var/lib/argent-sentinel/collector",
            review_unit,
        )
        self.assertIn(
            "ReadWritePaths=/run/argent-sentinel",
            review_unit,
        )


if __name__ == "__main__":
    unittest.main()
