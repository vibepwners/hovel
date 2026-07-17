from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import materialize_site


class MaterializeSiteTest(unittest.TestCase):
    def test_copy_report_stages_every_referenced_evidence_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "evidence"
            destination = root / "site/reports/tests/latest"
            referenced = {
                "logs/unit.log": "unit test log\n",
                "xml/unit.xml": "<testsuite />\n",
                "jobs/e2e.log": "complete e2e log\n",
                "coverage/squatter.lcov": "LH:1\nLF:1\n",
            }
            for relative, contents in referenced.items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            data = {
                "targets": [{"log_path": "logs/unit.log", "xml_path": "xml/unit.xml"}],
                "jobs": [{"log_path": "jobs/e2e.log"}],
                "coverage": [{"source_path": "coverage/squatter.lcov"}],
            }
            report = source / "data/report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps(data), encoding="utf-8")

            materialize_site.copy_report(source, destination)

            for relative, contents in referenced.items():
                self.assertEqual((destination / relative).read_text(encoding="utf-8"), contents)

    def test_copy_report_rejects_a_missing_referenced_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "evidence"
            report = source / "data/report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({"jobs": [{"log_path": "jobs/missing.log"}]}), encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "jobs/missing.log"):
                materialize_site.copy_report(source, root / "site/reports/tests/latest")


if __name__ == "__main__":
    unittest.main()
