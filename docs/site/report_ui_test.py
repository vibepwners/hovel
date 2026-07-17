from __future__ import annotations

import pathlib
import sys
import unittest


REPORT_JS = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
REPORT_CSS = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
sys.argv[1:] = []


class ReportUITest(unittest.TestCase):
    def test_top_level_tabs_have_matching_accessible_panels(self) -> None:
        self.assertIn('role="tablist" aria-label="Test report sections"', REPORT_JS)
        for view in ("overview", "coverage", "suites", "jobs", "targets"):
            self.assertIn(f'viewTab("{view}"', REPORT_JS)
            self.assertIn(f'id="report-panel-{view}" role="tabpanel"', REPORT_JS)
            self.assertIn(f'data-report-panel="{view}"', REPORT_JS)
        self.assertIn('event.key === "ArrowRight"', REPORT_JS)
        self.assertIn('event.key === "ArrowLeft"', REPORT_JS)

    def test_jobs_have_a_dedicated_view_after_suites(self) -> None:
        suites_panel = REPORT_JS.index('data-report-panel="suites"')
        jobs_panel = REPORT_JS.index('data-report-panel="jobs"')
        jobs = REPORT_JS.index("${renderJobs(report)}")
        targets_panel = REPORT_JS.index('data-report-panel="targets"')

        self.assertLess(suites_panel, jobs_panel)
        self.assertLess(jobs_panel, jobs)
        self.assertLess(jobs, targets_panel)
        self.assertEqual(REPORT_JS.count("${renderJobs(report)}"), 1)
        self.assertIn("<h2>Execution jobs</h2>", REPORT_JS)
        self.assertIn('const marker = "\\nRAW TRANSCRIPT APPENDICES\\n"', REPORT_JS)
        self.assertIn('class="job-raw-transcripts"', REPORT_JS)

    def test_hidden_panels_and_selected_tabs_have_explicit_styles(self) -> None:
        self.assertIn(".report-panel[hidden]", REPORT_CSS)
        self.assertIn('.report-view-tab[aria-selected="true"]', REPORT_CSS)
        self.assertIn("@media (prefers-reduced-motion: reduce)", REPORT_CSS)


if __name__ == "__main__":
    unittest.main()
