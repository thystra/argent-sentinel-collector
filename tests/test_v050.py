#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import awstats_manager  # noqa: E402
import collector  # noqa: E402
import dashboard  # noqa: E402
import dashboard_snapshot  # noqa: E402
import nginx_429_export  # noqa: E402
import review_digest  # noqa: E402
import server_api  # noqa: E402


class V050Test(unittest.TestCase):
    def test_release_versions(self) -> None:
        self.assertEqual("0.5.1.1", (ROOT / "VERSION").read_text().strip())
        for module in (
            awstats_manager,
            collector,
            dashboard,
            dashboard_snapshot,
            nginx_429_export,
            review_digest,
            server_api,
        ):
            self.assertEqual("0.5.1.1", module.APP_VERSION)

    def test_meta_policy_block_and_preview_allow(self) -> None:
        mapping = (
            ROOT / "config/nginx-crawler-map.conf.example"
        ).read_text()
        enforcement = (
            ROOT / "config/nginx-crawler-enforcement.conf.example"
        ).read_text()
        self.assertIn("facebookexternalhit", mapping)
        self.assertIn("meta-externalagent", mapping)
        self.assertRegex(
            mapping,
            r"~\*facebookexternalhit\s+allow;",
        )
        self.assertRegex(
            mapping,
            r"~\*meta-externalagent\s+block;",
        )
        self.assertIn("return 403;", enforcement)
        self.assertIn(
            "meta-externalagent",
            collector.DEFAULTS["web_policy"][
                "policy_denied_user_agents"
            ],
        )

    def test_policy_denied_crawler_is_not_hostile_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = collector.StateDB(
                Path(temporary) / "state.sqlite3"
            )
            try:
                observations = [
                    {
                        "observation_uuid": "00000000-0000-4000-8000-000000000001",
                        "occurred_epoch": 1000,
                        "occurred_at": "2026-07-25T14:00:00Z",
                        "source_ip": "203.0.113.10",
                        "source_port": 44321,
                        "destination_ip": "198.51.100.10",
                        "destination_port": 443,
                        "transport_protocol": "TCP",
                        "application_protocol": "HTTP",
                        "request_method": "GET",
                        "request_uri": "/gallery/page",
                        "http_status": 403,
                        "user_agent": (
                            "Mozilla/5.0 compatible; "
                            "meta-externalagent/1.1"
                        ),
                        "raw": {},
                    }
                ]
                policy = dict(collector.DEFAULTS["web_policy"])
                policy["high_volume_threshold"] = 1
                policy["high_volume_distinct_targets"] = 1
                events = database.materialize_web_probe_events(
                    "00000000-0000-4000-8000-000000000002",
                    "nidhoggur",
                    observations,
                    policy,
                )
                self.assertEqual([], events)
            finally:
                database.close()

    def test_distributed_crawler_is_not_single_source_enumeration(self) -> None:
        item = {
            "events": 600,
            "distinct_ips": 124,
            "distinct_paths": 590,
            "duration_seconds": 34000,
        }
        review = {
            "min_429_events": 10,
            "min_429_distinct_ips": 3,
            "min_429_duration_seconds": 300,
            "min_429_single_ip_events": 50,
            "min_429_single_ip_paths": 25,
            "min_429_single_ip_duration_seconds": 600,
        }
        reasons = review_digest.review_reasons(item, review)
        self.assertIn("distributed-prefix-pressure", reasons)
        self.assertNotIn("sustained-path-enumeration", reasons)

    def test_awstats_uses_per_site_normalized_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = {
                **awstats_manager.DEFAULTS,
                "_config_path": str(
                    Path(temporary) / "traffic-sites.json"
                ),
            }
            rendered = awstats_manager.render_site_config(
                config,
                {
                    "id": "photos.argentwolf.org",
                    "domain": "photos.argentwolf.org",
                    "aliases": [],
                },
            )
        self.assertIn(
            'SiteDomain="photos.argentwolf.org"',
            rendered,
        )
        self.assertIn("AllowToUpdateStatsFromBrowser=0", rendered)
        self.assertIn("LogFormat=1", rendered)
        self.assertIn(
            "stream --site photos.argentwolf.org",
            rendered,
        )
        self.assertNotIn("%virtualname", rendered)
    def test_dashboard_nginx_requires_lan_and_password(self) -> None:
        config = (
            ROOT
            / "config/nginx-sentinel-dashboard.conf.example"
        ).read_text()
        self.assertIn("ssl_verify_client optional;", config)
        self.assertIn("$ssl_client_verify != SUCCESS", config)
        self.assertIn("allow 192.168.0.0/16;", config)
        self.assertIn("allow fc00::/7;", config)
        self.assertIn("deny all;", config)
        self.assertIn('auth_basic "Argent Sentinel";', config)
        self.assertIn(
            "argent-sentinel-dashboard.htpasswd",
            config,
        )

    def test_dashboard_service_is_unprivileged_and_snapshot_only(self) -> None:
        service = (
            ROOT
            / "packaging/systemd/argent-sentinel-dashboard.service"
        ).read_text()
        self.assertIn("User=argent-sentinel-dashboard", service)
        self.assertIn(
            "ReadOnlyPaths=/var/lib/argent-sentinel/dashboard",
            service,
        )
        self.assertNotIn(
            "/var/lib/argent-sentinel/collector",
            service,
        )
        snapshot = (
            ROOT
            / "packaging/systemd/"
            "argent-sentinel-dashboard-snapshot.service"
        ).read_text()
        self.assertIn(
            "ReadWritePaths=/var/lib/argent-sentinel/collector",
            snapshot,
        )

    def test_new_packaging_assets_exist(self) -> None:
        required = (
            "src/dashboard.py",
            "src/dashboard_snapshot.py",
            "src/awstats_manager.py",
            "packaging/bin/argent-sentinel-dashboard",
            "packaging/bin/argent-sentinel-dashboard-snapshot",
            "packaging/bin/argent-sentinel-awstats",
            "packaging/systemd/argent-sentinel-dashboard.service",
            "packaging/systemd/argent-sentinel-dashboard-snapshot.service",
            "packaging/systemd/argent-sentinel-dashboard-snapshot.timer",
            "packaging/systemd/argent-sentinel-awstats.service",
            "packaging/systemd/argent-sentinel-awstats.timer",
            "scripts/setup-dashboard.sh",
            "scripts/install-nginx-crawler-policy.sh",
            "config/dashboard.json.example",
            "config/dashboard-snapshot.json.example",
            "config/traffic-sites.json.example",
            "config/nginx-site-access-log-format.conf.example",
            "scripts/install-nginx-site-log-format.sh",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)


if __name__ == "__main__":
    unittest.main()
