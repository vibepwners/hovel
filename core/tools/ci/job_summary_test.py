#!/usr/bin/env python3
"""Tests for the GitHub Actions job summary renderer."""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import contextmanager
from unittest import mock

import job_summary


@contextmanager
def patched_root(root: pathlib.Path):
    with mock.patch.object(job_summary, "ROOT", root):
        yield


@contextmanager
def patched_env(**values: str):
    original = os.environ.copy()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


class JobSummaryTest(unittest.TestCase):
    def test_build_summary_embeds_coverage_ratchets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            coverage = root / "coverage"
            coverage.mkdir()
            (coverage / "summary.md").write_text(
                "### Coverage Ratchets\n\n| Layer | Status |\n| --- | --- |\n| domain | pass |\n",
                encoding="utf-8",
            )
            with patched_root(root), patched_env(JOB_STATUS="success", GITHUB_WORKFLOW="CI", GITHUB_JOB="build-test"):
                rendered = job_summary.render_summary(job_summary.JOBS["ci-build-test"])

        self.assertIn("## CI Core Gate", rendered)
        self.assertIn("`task lint`", rendered)
        self.assertIn("`task build -- //:build`", rendered)
        self.assertIn("`task coverage`", rendered)
        self.assertIn("### Coverage Ratchets", rendered)
        self.assertIn("| domain | pass |", rendered)

    def test_publish_summary_lists_release_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            wheel = root / "dist/hovel-0.1.0-py3-none-any.whl"
            wheel.parent.mkdir()
            wheel.write_bytes(b"wheel")
            with patched_root(root), patched_env(JOB_STATUS="success"):
                rendered = job_summary.render_summary(job_summary.JOBS["publish-hovel-build"])

        self.assertIn("## Publish Hovel Wheels", rendered)
        self.assertIn("`task release:hovel-wheels`", rendered)
        self.assertIn("`dist/hovel-0.1.0-py3-none-any.whl`", rendered)

    def test_pages_summary_reports_site_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            root = repo / "core"
            root.mkdir()
            site = repo / "docs/site"
            site.mkdir(parents=True)
            (site / "index.html").write_text("<!doctype html>\n", encoding="utf-8")
            with patched_root(root), patched_env(JOB_STATUS="success"):
                rendered = job_summary.render_summary(job_summary.JOBS["pages-build"])

        self.assertIn("| HTML pages | 1 |", rendered)
        self.assertIn("| Total size | 16 B |", rendered)

    def test_main_appends_to_github_step_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            summary_path = root / "summary.md"
            with (
                patched_root(root),
                patched_env(GITHUB_STEP_SUMMARY=str(summary_path), JOB_STATUS="failure"),
                mock.patch.object(sys, "argv", ["job_summary.py", "ci-build-test"]),
            ):
                self.assertEqual(job_summary.main(), 0)

            written = summary_path.read_text(encoding="utf-8")

        self.assertIn("## CI Core Gate", written)
        self.assertIn("| Status | failure |", written)
        self.assertIn("`task lint`", written)


if __name__ == "__main__":
    unittest.main()
