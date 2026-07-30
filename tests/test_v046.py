#!/usr/bin/env python3
# Argent Sentinel v0.5.4.0 packaging regression tests.

from pathlib import Path
import importlib.util
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_builder():
    path = ROOT / "packaging/build_debs.py"
    spec = importlib.util.spec_from_file_location(
        "argent_sentinel_build_debs",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load packaging/build_debs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class V046Test(unittest.TestCase):
    def test_release_versions_are_consistent(self) -> None:
        self.assertEqual("0.5.4.0", (ROOT / "VERSION").read_text().strip())
        for relative in (
            "src/collector.py",
            "src/agent.py",
            "src/server_api.py",
        ):
            source = (ROOT / relative).read_text()
            self.assertIn('APP_VERSION = "0.5.4.0"', source)

        builder = (ROOT / "packaging/build_debs.py").read_text()
        self.assertIn('if upstream != "0.5.4.0":', builder)
        self.assertIn('"test_v046.py"', builder)

    def test_server_package_root_contains_timer_assets(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = builder.make_server(root, "0.5.4.0-1")

            self.assertTrue(
                (
                    root
                    / "usr/lib/systemd/system/"
                    "argent-sentinel-nginx-logrotate.service"
                ).is_file()
            )
            self.assertTrue(
                (
                    root
                    / "usr/lib/systemd/system/"
                    "argent-sentinel-nginx-logrotate.timer"
                ).is_file()
            )
            self.assertTrue(
                (
                    root
                    / "usr/share/argent-sentinel/"
                    "argent-sentinel-nginx.logrotate"
                ).is_file()
            )
            self.assertIn("logrotate", metadata["depends"])

    def test_nginx_logrotate_service_and_timer(self) -> None:
        service = (
            ROOT
            / "packaging/systemd/argent-sentinel-nginx-logrotate.service"
        ).read_text()
        timer = (
            ROOT
            / "packaging/systemd/argent-sentinel-nginx-logrotate.timer"
        ).read_text()

        self.assertIn(
            "ConditionPathExists=/etc/logrotate.d/argent-sentinel-nginx",
            service,
        )
        self.assertIn(
            "ConditionPathExists=/var/log/nginx/"
            "argent-sentinel-abuse-context.jsonl",
            service,
        )
        self.assertIn(
            "ExecStart=/usr/sbin/logrotate "
            "/etc/logrotate.d/argent-sentinel-nginx",
            service,
        )
        self.assertNotIn("--state", service)

        self.assertIn("OnCalendar=hourly", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=2min", timer)
        self.assertIn(
            "Unit=argent-sentinel-nginx-logrotate.service",
            timer,
        )
        self.assertIn("WantedBy=timers.target", timer)

    def test_default_logrotate_rule_stages_rotated_jsonl(self) -> None:
        rule = (
            ROOT / "packaging/logrotate/argent-sentinel-nginx"
        ).read_text()
        self.assertIn(
            "/var/log/nginx/argent-sentinel-abuse-context.jsonl",
            rule,
        )
        self.assertIn("hourly", rule)
        self.assertIn("delaycompress", rule)
        self.assertIn("kill -USR1", rule)
        self.assertIn(
            "/usr/sbin/argent-sentinel-stage-abuse-context",
            rule,
        )

    def test_server_package_lifecycle_manages_timer(self) -> None:
        postinst = (ROOT / "packaging/deb/server.postinst").read_text()
        prerm = (ROOT / "packaging/deb/server.prerm").read_text()
        postrm = (ROOT / "packaging/deb/server.postrm").read_text()

        self.assertIn(
            "Preserved existing $NGINX_LOGROTATE_CONFIG",
            postinst,
        )
        self.assertIn(
            "archive_legacy_unit "
            "argent-sentinel-nginx-logrotate.service",
            postinst,
        )
        self.assertIn(
            "archive_legacy_unit "
            "argent-sentinel-nginx-logrotate.timer",
            postinst,
        )
        self.assertIn(
            "systemctl restart "
            "argent-sentinel-nginx-logrotate.timer",
            postinst,
        )
        self.assertIn(
            "rm -f /var/lib/logrotate/"
            "status-argent-sentinel-nginx",
            postinst,
        )
        self.assertIn(
            "argent-sentinel-nginx-logrotate.timer",
            prerm,
        )
        self.assertIn(
            "/etc/logrotate.d/argent-sentinel-nginx",
            postrm,
        )


if __name__ == "__main__":
    unittest.main()
