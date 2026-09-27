from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import lintreport


class LintReportTest(unittest.TestCase):
    def test_materialization_keeps_failure_logs_and_source_ignores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "example.py").write_text("value = object()  # type: ignore[arg-type]\n")
            manifest = repo / "manifest.json"
            manifest.write_text(json.dumps({"schema_version": lintreport.MANIFEST_VERSION, "tools": [{
                "id": "example", "name": "Example", "scope": "Python", "kind": "linter",
                "commands": [["aspect", "test", "//tools/lint:example_test"]],
                "ignore": {"pattern": r"#\s*type:\s*ignore\b", "extensions": [".py"]},
            }]}))
            result = repo / "result"
            result.mkdir()
            (result / "result.json").write_text(json.dumps({
                "schema_version": "hovel.lint-action/v1", "id": "example", "status": "FAILED",
                "exit_code": 3, "duration": 1.25,
            }))
            (result / "diagnostics.log").write_text("\x1b[31mbad input\x1b[0m\n")
            output = repo / "report"
            self.assertEqual(lintreport.materialize_results(repo, manifest, output, [result]), 1)
            report = json.loads((output / "report.json").read_text())["tools"][0]
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["duration"], 1.25)
            self.assertEqual(len(report["ignore_statements"]), 1)
            self.assertIn("bad input", (output / "logs/example.log").read_text())
            self.assertNotIn("\x1b", (output / "logs/example.log").read_text())

    def test_missing_native_evidence_never_becomes_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            manifest = repo / "manifest.json"
            manifest.write_text(json.dumps({"schema_version": lintreport.MANIFEST_VERSION, "tools": [{
                "id": "nilness", "name": "Nilness", "scope": "Go", "kind": "static-analysis",
                "commands": [["aspect", "build", "@hovel_core//:build"]],
            }]}))
            self.assertEqual(lintreport.materialize_results(repo, manifest, repo / "report", []), 1)
            self.assertEqual(lintreport.materialize_results(repo, manifest, repo / "report", [], verified_native={"nilness"}), 0)

    def test_checked_in_manifest_covers_unique_tools(self) -> None:
        manifest = json.loads((Path(__file__).with_name("lint_tools.json")).read_text(encoding="utf-8"))
        lintreport.validate_manifest(manifest)
        ids = {tool["id"] for tool in manifest["tools"]}
        self.assertEqual(
            ids,
            {
                "buildifier",
                "clang-format",
                "clang-tidy",
                "cppcheck",
                "gazelle",
                "gofmt",
                "golangci-lint",
                "lizard",
                "mypy",
                "nilness",
                "pydoclint",
                "repository-policy",
                "ruff",
                "rustfmt",
            },
        )


if __name__ == "__main__":
    unittest.main()
