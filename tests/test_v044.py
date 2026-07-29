#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/tests/test_v044.py
import ast
# Argent Sentinel v0.5.1.1 release regression tests.

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class V044Test(unittest.TestCase):
    def test_release_versions_and_banner_layout(self) -> None:
        expected_version = "0.5.1.1"
        self.assertEqual(
            expected_version,
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        )

        for relative in (
            "src/collector.py",
            "src/agent.py",
            "src/server_api.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            tree = ast.parse(source)
            versions = [
                node.value.value
                for node in tree.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == "APP_VERSION"
                    for target in node.targets
                )
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ]
            self.assertEqual(
                [expected_version],
                versions,
                f"{relative} must declare the release APP_VERSION once.",
            )

        builder_source = (
            ROOT / "packaging" / "build_debs.py"
        ).read_text(encoding="utf-8")
        builder_tree = ast.parse(builder_source)
        self.assertTrue(
            any(
                isinstance(node, ast.Compare)
                and isinstance(node.left, ast.Name)
                and node.left.id == "upstream"
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.NotEq)
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value == expected_version
                for node in ast.walk(builder_tree)
            ),
            "The package builder must reject an unexpected upstream version.",
        )
        self.assertTrue(
            any(
                isinstance(node, ast.Constant)
                and node.value == "test_v044.py"
                for node in ast.walk(builder_tree)
            ),
            "The package builder must include test_v044.py.",
        )

        collector_source = (
            ROOT / "src" / "collector.py"
        ).read_text(encoding="utf-8")
        collector_tree = ast.parse(collector_source)
        send_methods = [
            child
            for node in collector_tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "Collector"
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name == "send_abuse_report"
        ]
        self.assertEqual(
            1,
            len(send_methods),
            "Collector.send_abuse_report must exist exactly once.",
        )
        send_method = send_methods[0]

        body_initializers = [
            node
            for node in ast.walk(send_method)
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "body"
            and isinstance(node.value, ast.List)
            and not node.value.elts
        ]
        self.assertEqual(
            1,
            len(body_initializers),
            "send_abuse_report must initialize one empty body list.",
        )

        constant_extend_payloads: list[list[object]] = []
        for node in ast.walk(send_method):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Attribute)
                or not isinstance(node.func.value, ast.Name)
                or node.func.value.id != "body"
                or node.func.attr != "extend"
                or len(node.args) != 1
                or not isinstance(node.args[0], ast.List)
                or not all(
                    isinstance(element, ast.Constant)
                    for element in node.args[0].elts
                )
            ):
                continue
            constant_extend_payloads.append(
                [
                    element.value
                    for element in node.args[0].elts
                ]
            )

        self.assertIn(
            ["*** TEST MODE ***", ""],
            constant_extend_payloads,
            "The TEST MODE body must finish with a closing banner and blank line.",
        )
        self.assertIn(
            ["Hello,", ""],
            constant_extend_payloads,
            "The report body must begin its normal content with a greeting.",
        )


if __name__ == "__main__":
    unittest.main()

# EOF: /home/alan/src/argent-sentinel-collector/tests/test_v044.py
