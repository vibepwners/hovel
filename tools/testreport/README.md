# Report evidence contracts

The report-producing workflow accepts linter and static-analysis evidence in
the versioned `hovel.lint-report/v1` format defined by
`lint-report.schema.json`. A document contains one entry per unique tool with:

- a stable tool id, display name, kind, and monorepo scope;
- `PASSED` or `FAILED` status and elapsed duration;
- the exact Task-backed commands that were run;
- every detected source-level ignore statement as a path, line, and source
  excerpt; and
- the path to the tool's complete captured log.

`lint_tools.json` is the checked-in adapter manifest. The generic
`run_lint_report` runner executes those adapters, writes the standard document
to `.test-report/linters/report.json`, and keeps one log per tool. The test
report generator accepts one or more documents with `--lint-report` and
materializes their logs alongside the rest of the site evidence.

Use `task lint:report` to produce only linter evidence or `task docs:report` to
run and publish the complete quality and test report.
