#!/usr/bin/env python3
"""Protect the GitHub Pages publication and test-report contract."""

from __future__ import annotations

import pathlib
import sys
import unittest


CI_WORKFLOW = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
PAGES_WORKFLOW = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
sys.argv[1:] = []


def position(workflow: str, fragment: str, start: int = 0) -> int:
    index = workflow.find(fragment, start)
    if index < 0:
        raise AssertionError(f"workflow is missing {fragment!r}")
    return index


class PagesWorkflowTest(unittest.TestCase):
    def test_only_publishes_successful_main_ci_or_manual_runs(self) -> None:
        self.assertIn('workflows: ["CI"]', PAGES_WORKFLOW)
        self.assertIn("branches: [main]", PAGES_WORKFLOW)
        self.assertGreaterEqual(PAGES_WORKFLOW.count("github.event.workflow_run.conclusion == 'success'"), 2)
        self.assertIn("github.event_name == 'workflow_dispatch'", PAGES_WORKFLOW)
        self.assertIn("ref: ${{ github.event.workflow_run.head_sha || github.sha }}", PAGES_WORKFLOW)

    def test_ci_artifact_contains_the_final_report_site(self) -> None:
        docs_job = position(CI_WORKFLOW, "  docs:\n")
        report = position(CI_WORKFLOW, "run: task docs:report", docs_job)
        upload = position(CI_WORKFLOW, "uses: actions/upload-artifact@", report)

        self.assertLess(docs_job, report)
        self.assertLess(report, upload, "docs-site must be uploaded after report-aware staging")
        self.assertIn("name: docs-site", CI_WORKFLOW[report:])
        self.assertIn("path: _site/", CI_WORKFLOW[report:])
        self.assertIn("include-hidden-files: true", CI_WORKFLOW[report:])

    def test_successful_ci_artifact_is_promoted_without_rebuilding(self) -> None:
        download = position(PAGES_WORKFLOW, "uses: actions/download-artifact@")
        upload = position(PAGES_WORKFLOW, "uses: actions/upload-pages-artifact@")

        self.assertLess(download, upload)
        self.assertIn("if: github.event_name == 'workflow_run'", PAGES_WORKFLOW[:download])
        self.assertIn("name: docs-site", PAGES_WORKFLOW[download:upload])
        self.assertIn("path: _site", PAGES_WORKFLOW[download:upload])
        self.assertIn("run-id: ${{ github.event.workflow_run.id }}", PAGES_WORKFLOW[download:upload])
        self.assertIn("github-token: ${{ secrets.GITHUB_TOKEN }}", PAGES_WORKFLOW[download:upload])

    def test_upload_and_deploy_match_the_pages_contract(self) -> None:
        self.assertIn("actions: read", PAGES_WORKFLOW)
        self.assertIn("pages: write", PAGES_WORKFLOW)
        self.assertIn("id-token: write", PAGES_WORKFLOW)
        self.assertIn("uses: actions/configure-pages@", PAGES_WORKFLOW)
        self.assertIn("path: _site", PAGES_WORKFLOW)
        self.assertIn("include-hidden-files: true", PAGES_WORKFLOW)
        self.assertIn("needs: build", PAGES_WORKFLOW)
        self.assertIn("name: github-pages", PAGES_WORKFLOW)
        self.assertIn("uses: actions/deploy-pages@", PAGES_WORKFLOW)

    def test_manual_dispatch_builds_the_same_report_site(self) -> None:
        report = position(PAGES_WORKFLOW, "run: task docs:report")
        preceding_step = PAGES_WORKFLOW[max(0, report - 180) : report]
        self.assertIn("if: github.event_name == 'workflow_dispatch'", preceding_step)
        self.assertNotIn("run: task docs:site", PAGES_WORKFLOW)
        self.assertNotIn("run: task docs:build", PAGES_WORKFLOW)


if __name__ == "__main__":
    unittest.main()
