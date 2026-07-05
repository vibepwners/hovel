from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import testreport


class TestReportTest(unittest.TestCase):
    def test_scans_testlogs_and_renders_static_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            testlog = repo / "bazel-testlogs/sdk/rust/hovel/hovel_test"
            testlog.mkdir(parents=True)
            (testlog / "test.log").write_text("running 1 test\ntest tests::round_trip ... ok\ntest result: ok\n", encoding="utf-8")
            (testlog / "test.xml").write_text(
                """<?xml version="1.0"?>
<testsuites><testsuite name="sdk/rust/hovel/hovel_test" tests="1" failures="0">
<testcase name="tests::round_trip" classname="sdk.rust" time="0.01" />
</testsuite></testsuites>
""",
                encoding="utf-8",
            )
            write_docs_assets(repo)

            report = testreport.build_report(
                repo=repo,
                title="Example",
                bep_files=[],
                testlog_roots=[repo / "bazel-testlogs"],
                cache_roots=[],
                workflow="CI",
                job="sdk",
                commit="abc",
                ref="main",
            )
            out = repo / ".test-report/site"
            testreport.render_report(report, repo=repo, output=out)

            data = json.loads((out / "data/report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["totals"]["targets"], 1)
            self.assertEqual(data["targets"][0]["label"], "//sdk/rust/hovel:hovel_test")
            self.assertEqual(data["targets"][0]["status"], "PASSED")
            self.assertEqual(data["targets"][0]["cases"][0]["name"], "tests::round_trip")
            self.assertTrue((out / data["targets"][0]["log_path"]).is_file())
            index_html = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn("report.js", index_html)
            self.assertIn('data-commit="abc"', index_html)
            self.assertIn("<code>abc</code>", index_html)

    def test_ingests_bep_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            log = repo / "core/bazel-testlogs/schemas/schema_smoke_test/test.log"
            xml = log.with_name("test.xml")
            log.parent.mkdir(parents=True)
            log.write_text("OK\n", encoding="utf-8")
            xml.write_text("<testsuites><testsuite tests='1'><testcase name='schema'/></testsuite></testsuites>", encoding="utf-8")
            bep = repo / ".test-report/bep/core.json"
            bep.parent.mkdir(parents=True)
            bep.write_text(
                json.dumps(
                    {
                        "id": {"testResult": {"label": "//schemas:schema_smoke_test", "run": 1, "shard": 0, "attempt": 1}},
                        "testResult": {
                            "status": "PASSED",
                            "testAttemptDurationMillis": "25",
                            "testActionOutput": [
                                {"name": "test.log", "uri": log.as_uri()},
                                {"name": "test.xml", "uri": xml.as_uri()},
                            ],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            report = testreport.build_report(
                repo=repo,
                title="Example",
                bep_files=[bep],
                testlog_roots=[],
                cache_roots=[],
                workflow="CI",
                job="core",
                commit="abc",
                ref="main",
            )

            self.assertEqual(report.targets[0].label, "//schemas:schema_smoke_test")
            self.assertEqual(report.targets[0].raw_log_path, "core/bazel-testlogs/schemas/schema_smoke_test/test.log")
            self.assertEqual(report.targets[0].duration, 0.025)

    def test_recovers_bytestream_outputs_from_disk_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            cache = repo / "cache"
            digest = "a" * 64
            blob = cache / "cas" / "aa" / digest
            blob.parent.mkdir(parents=True)
            blob.write_text("remote log\n", encoding="utf-8")
            bep = repo / "bep.json"
            bep.write_text(
                json.dumps(
                    {
                        "id": {"testResult": {"label": "//pkg:target", "run": 1, "shard": 0, "attempt": 1}},
                        "testResult": {
                            "status": "PASSED",
                            "testActionOutput": [
                                {"name": "test.log", "uri": f"bytestream:/cache/blobs/{digest}/11"},
                            ],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            write_docs_assets(repo)

            report = testreport.build_report(
                repo=repo,
                title="Example",
                bep_files=[bep],
                testlog_roots=[],
                cache_roots=[cache],
                workflow="CI",
                job="core",
                commit="abc",
                ref="main",
            )
            out = repo / "out"
            testreport.render_report(report, repo=repo, output=out)

            self.assertEqual((out / report.targets[0].log_path).read_text(encoding="utf-8"), "remote log\n")


def write_docs_assets(repo: Path) -> None:
    assets = repo / "docs/site/assets"
    assets.mkdir(parents=True)
    (assets / "site.css").write_text("body { color: white; }\n", encoding="utf-8")
    (assets / "hovel.png").write_bytes(b"png")


if __name__ == "__main__":
    unittest.main()
