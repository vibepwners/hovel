from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import testreport


class TestReportTest(unittest.TestCase):
    def test_scans_testlogs_and_renders_report_evidence(self) -> None:
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
            out = repo / ".test-report/evidence"
            testreport.render_report(report, repo=repo, output=out)

            data = json.loads((out / "data/report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["totals"]["targets"], 1)
            self.assertEqual(data["totals"]["suite_breakdown"]["sdk"]["targets"], 1)
            self.assertEqual(data["totals"]["suite_breakdown"]["sdk"]["cases"], 1)
            self.assertEqual(data["targets"][0]["label"], "//sdk/rust/hovel:hovel_test")
            self.assertEqual(data["targets"][0]["status"], "PASSED")
            self.assertEqual(data["targets"][0]["cases"][0]["name"], "tests::round_trip")
            self.assertTrue((out / data["targets"][0]["log_path"]).is_file())
            self.assertFalse((out / "index.html").exists())

    def test_failed_xml_cases_preserve_messages_outputs_and_suite_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            testlog = repo / "bazel-testlogs/pkg/failing_test"
            testlog.mkdir(parents=True)
            (testlog / "test.log").write_text("FAIL\n", encoding="utf-8")
            (testlog / "test.xml").write_text(
                """<?xml version="1.0"?>
<testsuites><testsuite name="pkg/failing_test" tests="4" failures="1" errors="1" skipped="1" time="1.2">
<testcase name="passes" classname="pkg" time="0.1" />
<testcase name="fails" classname="pkg" time="0.2"><failure>expected true</failure><system-out>failure output</system-out></testcase>
<testcase name="errors" classname="pkg" time="0.3"><error>panic stack</error></testcase>
<testcase name="skips" classname="pkg" time="0"><skipped>not relevant</skipped></testcase>
</testsuite></testsuites>
""",
                encoding="utf-8",
            )

            report = testreport.build_report(
                repo=repo,
                title="Example",
                bep_files=[],
                testlog_roots=[repo / "bazel-testlogs"],
                cache_roots=[],
                workflow="CI",
                job="core",
                commit="abc",
                ref="main",
            )

            target = report.targets[0]
            self.assertEqual(target.status, "ERROR")
            self.assertEqual([case.status for case in target.cases], ["PASSED", "FAILED", "ERROR", "SKIPPED"])
            self.assertEqual(target.cases[1].message, "expected true")
            self.assertEqual(target.cases[1].output, "failure output")
            self.assertEqual(target.cases[2].message, "panic stack")
            self.assertEqual(report.totals["suite_breakdown"]["root"]["targets"], 1)
            self.assertEqual(report.totals["suite_breakdown"]["root"]["cases"], 4)
            self.assertEqual(report.totals["suite_breakdown"]["root"]["statuses"]["ERROR"], 1)

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

    def test_bep_limits_scanned_testlogs_to_current_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            current = repo / "bazel-testlogs/pkg/current_test"
            current.mkdir(parents=True)
            (current / "test.log").write_text("PASS\n", encoding="utf-8")
            (current / "test.xml").write_text(
                "<testsuites><testsuite tests='1'><testcase name='current'/></testsuite></testsuites>",
                encoding="utf-8",
            )
            stale = repo / "bazel-testlogs/pkg/stale_test"
            stale.mkdir(parents=True)
            (stale / "test.log").write_text("FAIL\n", encoding="utf-8")
            (stale / "test.xml").write_text(
                "<testsuites><testsuite tests='1' failures='1'><testcase name='stale'><failure>old failure</failure></testcase></testsuite></testsuites>",
                encoding="utf-8",
            )
            bep = repo / ".test-report/bep/root.json"
            bep.parent.mkdir(parents=True)
            bep.write_text(
                json.dumps(
                    {
                        "id": {"testResult": {"label": "//pkg:current_test", "run": 1, "shard": 0, "attempt": 1}},
                        "testResult": {"status": "PASSED"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            report = testreport.build_report(
                repo=repo,
                title="Example",
                bep_files=[bep],
                testlog_roots=[repo / "bazel-testlogs"],
                cache_roots=[],
                workflow="CI",
                job="root",
                commit="abc",
                ref="main",
            )

            self.assertEqual([target.label for target in report.targets], ["//pkg:current_test"])
            self.assertEqual(report.targets[0].status, "PASSED")
            self.assertEqual([case.name for case in report.targets[0].cases], ["current"])
            self.assertEqual(report.totals["statuses"], {"PASSED": 1})

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


if __name__ == "__main__":
    unittest.main()
