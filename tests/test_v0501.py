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


class V0501Test(unittest.TestCase):
    def test_release_version(self) -> None:
        self.assertEqual("0.5.3.0", (ROOT / "VERSION").read_text().strip())
        self.assertEqual("0.5.3.0", awstats_manager.APP_VERSION)

    def test_standard_and_extended_logs_normalize(self) -> None:
        base = (
            '192.0.2.10 - - [25/Jul/2026:12:00:00 -0400] '
            '"GET /example HTTP/2.0" 200 123 "-" "ExampleAgent/1.0"'
        )
        legacy = awstats_manager.parse_access_line(base)
        self.assertIsNotNone(legacy)
        assert legacy is not None
        self.assertEqual("", legacy["virtual_host"])

        extended = awstats_manager.parse_access_line(
            base
            + ' src_ip="192.0.2.10" src_port="12345"'
              ' dst_ip="198.51.100.5" dst_port="443"'
              ' host="wolfandraven.blog"'
              ' server_name="wolfandraven.blog" scheme="https"'
        )
        self.assertIsNotNone(extended)
        assert extended is not None
        self.assertEqual(
            "wolfandraven.blog",
            extended["virtual_host"],
        )
        self.assertEqual(
            base,
            awstats_manager.canonical_combined(extended),
        )

    def test_www_site_is_merged_as_alias(self) -> None:
        sites = awstats_manager.normalize_sites(
            [
                {
                    "id": "wolfandraven.blog",
                    "domain": "wolfandraven.blog",
                    "aliases": [],
                },
                {
                    "id": "www.wolfandraven.blog",
                    "domain": "www.wolfandraven.blog",
                    "aliases": [],
                },
            ]
        )
        self.assertEqual(1, len(sites))
        self.assertEqual("wolfandraven.blog", sites[0]["domain"])
        self.assertEqual(
            ["www.wolfandraven.blog"],
            sites[0]["aliases"],
        )

    def test_per_site_filename_and_shared_host_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site_log = root / "wolfandraven.blog.access.log"
            site_log.write_text(
                '192.0.2.10 - - [25/Jul/2026:12:00:00 -0400] '
                '"GET /legacy HTTP/1.1" 200 12 "-" "Legacy"\n'
            )
            shared_log = root / "access.log"
            shared_log.write_text(
                '192.0.2.11 - - [25/Jul/2026:12:01:00 -0400] '
                '"GET /extended HTTP/1.1" 200 13 "-" "Extended" '
                'host="wolfandraven.blog"\n'
            )
            config = {
                **awstats_manager.DEFAULTS,
                "log_globs": [str(root / "*.log")],
            }
            site = {
                "id": "wolfandraven.blog",
                "domain": "wolfandraven.blog",
                "aliases": ["www.wolfandraven.blog"],
            }
            sources = awstats_manager.resolve_site_sources(config, site)
            selected = {
                Path(item["path"]).name: item["require_host"]
                for item in sources
            }
            self.assertEqual(False, selected[site_log.name])
            self.assertNotIn(shared_log.name, selected)

    def test_awstats_config_uses_normalized_site_stream(self) -> None:
        config = {
            **awstats_manager.DEFAULTS,
            "_config_path": "/etc/argent-sentinel/traffic-sites.json",
        }
        rendered = awstats_manager.render_site_config(
            config,
            {
                "id": "photos.argentwolf.org",
                "domain": "photos.argentwolf.org",
                "aliases": [],
            },
        )
        self.assertIn("LogFormat=1", rendered)
        self.assertIn(" stream --site photos.argentwolf.org |", rendered)
        self.assertNotIn("%virtualname", rendered)
        self.assertIn("ShowPagesStats=PBEX", rendered)
        self.assertIn("ShowRobotsStats=HBL", rendered)
        self.assertIn("ShowHostsStats=PHBL", rendered)
        self.assertIn("ShowHTTPErrorsStats=1", rendered)

    def test_dashboard_service_uses_systemd_credential(self) -> None:
        service = (
            ROOT
            / "packaging/systemd/argent-sentinel-dashboard.service"
        ).read_text()
        self.assertIn(
            "LoadCredential=dashboard.json:"
            "/etc/argent-sentinel/dashboard.json",
            service,
        )
        self.assertIn("${CREDENTIALS_DIRECTORY}/dashboard.json", service)
        self.assertNotIn(
            "ReadOnlyPaths=/etc/argent-sentinel/dashboard.json",
            service,
        )

    def test_dashboard_publication_permissions_are_packaged(self) -> None:
        postinst = (ROOT / "packaging/deb/server.postinst").read_text()
        self.assertIn(
            "setfacl -m g:www-data:--x /var/lib/argent-sentinel",
            postinst,
        )
        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn("adduser, acl, openssl", builder)
        snapshot_source = (ROOT / "src/dashboard_snapshot.py").read_text()
        self.assertIn("os.chown(path.parent, -1, group_id)", snapshot_source)
        dashboard_source = (ROOT / "src/dashboard.py").read_text()
        self.assertIn("except PermissionError as exc:", dashboard_source)

    def test_agent_notes_record_host_paths(self) -> None:
        notes = (ROOT / "AGENTS.md").read_text()
        self.assertIn("~/src/argent-sentinel-collector", notes)
        self.assertIn("~/Downloads/", notes)
        self.assertIn("/var/lib/argent-sentinel/dashboard", notes)
        self.assertIn("/run/argent-sentinel-dashboard/", notes)
        self.assertIn("/mnt/data/file.patch", notes)

    def test_two_log_formats_and_readme_commands(self) -> None:
        format_file = (
            ROOT
            / "config/nginx-site-access-log-format.conf.example"
        ).read_text()
        self.assertIn("log_format argent_site_access", format_file)

        readme = (ROOT / "README.md").read_text()
        self.assertIn("argent_site_access", readme)
        self.assertIn("argent_sentinel_json", readme)
        self.assertIn(
            "argent-sentinel-install-site-log-format",
            readme,
        )
        self.assertIn(
            "argent-sentinel-awstats inspect",
            readme,
        )
        self.assertIn("--write-proposed", readme)


if __name__ == "__main__":
    unittest.main()
