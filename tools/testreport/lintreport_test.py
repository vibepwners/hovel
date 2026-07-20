from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import lintreport


class LintReportTest(unittest.TestCase):
    def test_runs_every_command_and_emits_standard_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pkg").mkdir()
            (repo / "pkg/example.py").write_text(
                'example = "# type: ignore[string-literal]"\n'
                "value = object()  # type: ignore[arg-type]\n",
                encoding="utf-8",
            )
            manifest = repo / "tools.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": lintreport.MANIFEST_VERSION,
                        "tools": [
                            {
                                "id": "example",
                                "name": "Example analyzer",
                                "kind": "static-analysis",
                                "scope": "Example Python",
                                "commands": [[sys.executable, "-c", "print('analysis clean')"]],
                                "ignore": {"pattern": r"#\s*type:\s*ignore\b", "extensions": [".py"]},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = repo / ".test-report/linters"

            self.assertEqual(lintreport.run_manifest(repo, manifest, output), 0)

            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], lintreport.SCHEMA_VERSION)
            self.assertEqual(report["tools"][0]["status"], "PASSED")
            self.assertEqual(report["tools"][0]["ignore_statements"][0]["path"], "pkg/example.py")
            self.assertEqual(len(report["tools"][0]["ignore_statements"]), 1)
            self.assertEqual(report["tools"][0]["ignore_statements"][0]["line"], 2)
            self.assertIn("analysis clean", (repo / report["tools"][0]["raw_log_path"]).read_text())

    def test_logs_are_plain_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            manifest = repo / "tools.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": lintreport.MANIFEST_VERSION,
                        "tools": [
                            {
                                "id": "color-output",
                                "name": "Color output",
                                "kind": "linter",
                                "scope": "Example",
                                "commands": [
                                    [sys.executable, "-c", "print('\\N{ESC}[32mclean\\N{ESC}[0m')"]
                                ],
                                "ignore": {"pattern": "", "extensions": [".py"]},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = repo / "lint"

            self.assertEqual(lintreport.run_manifest(repo, manifest, output), 0)
            log = (output / "logs/color-output.log").read_text(encoding="utf-8")
            self.assertIn("clean", log)
            self.assertNotIn("\N{ESC}", log)

    def test_failure_is_reported_without_dropping_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            manifest = repo / "tools.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": lintreport.MANIFEST_VERSION,
                        "tools": [
                            {
                                "id": "failing",
                                "name": "Failing linter",
                                "kind": "linter",
                                "scope": "Example",
                                "commands": [[sys.executable, "-c", "raise SystemExit(3)"]],
                                "ignore": {"pattern": "", "extensions": [".py"]},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = repo / "lint"

            self.assertEqual(lintreport.run_manifest(repo, manifest, output), 1)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["tools"][0]["status"], "FAILED")
            self.assertIn("[exit code: 3]", (repo / report["tools"][0]["raw_log_path"]).read_text())

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
