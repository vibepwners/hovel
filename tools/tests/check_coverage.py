#!/usr/bin/env python3
"""Task-backed coverage ratchet for Hovel's highest-value layers."""

from __future__ import annotations

import argparse
import io
import pathlib
import shutil
import subprocess
import sys
import trace
import unittest
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]
COVERAGE_DIR = ROOT / "coverage"


@dataclass(frozen=True)
class CoverageResult:
    name: str
    covered: int
    total: int
    minimum: float

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 100.0
        return self.covered * 100.0 / self.total

    @property
    def ok(self) -> bool:
        return self.percent >= self.minimum


GO_LAYERS = (
    ("domain", 75.0, ("//internal/domain/...",)),
    ("app", 65.0, ("//internal/app/...",)),
)

PYTHON_SDK_MINIMUM = 80.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-go", action="store_true", help="Only run Python SDK coverage.")
    parser.add_argument("--skip-python", action="store_true", help="Only run Go/Bazel coverage.")
    args = parser.parse_args()

    COVERAGE_DIR.mkdir(exist_ok=True)
    results: list[CoverageResult] = []
    if not args.skip_go:
        for name, minimum, targets in GO_LAYERS:
            results.append(run_go_coverage(name, minimum, targets))
    if not args.skip_python:
        results.append(run_python_sdk_coverage())

    print("\nCoverage ratchet")
    print("LAYER       COVERED/TOTAL   COVERAGE   FLOOR")
    failed = False
    for result in results:
        status = "ok" if result.ok else "FAIL"
        print(f"{result.name:<11} {result.covered:>5}/{result.total:<7} {result.percent:>7.2f}% {result.minimum:>6.2f}% {status}")
        failed = failed or not result.ok
    if failed:
        print("\nCoverage fell below the ratchet floor. Add tests or intentionally adjust the Task-backed floor.")
        return 1
    return 0


def run_go_coverage(name: str, minimum: float, targets: tuple[str, ...]) -> CoverageResult:
    report = ROOT / "bazel-out/_coverage/_coverage_report.dat"
    report.unlink(missing_ok=True)
    run(["task", "coverage:go", "--", *targets])
    if not report.exists():
        raise SystemExit(f"coverage report not found: {report}")
    covered, total = parse_lcov(report)
    shutil.copyfile(report, COVERAGE_DIR / f"{name}.lcov")
    return CoverageResult(name=name, covered=covered, total=total, minimum=minimum)


def parse_lcov(path: pathlib.Path) -> tuple[int, int]:
    covered = 0
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("DA:"):
            continue
        total += 1
        _, payload = line.split(":", 1)
        _, hits = payload.split(",", 1)
        if int(hits) > 0:
            covered += 1
    return covered, total


def run_python_sdk_coverage() -> CoverageResult:
    sdk = ROOT / "sdk/python"
    old_path = list(sys.path)
    sys.path.insert(0, str(sdk))
    try:
        tracer = trace.Trace(count=True, trace=False, ignoredirs=[sys.prefix, sys.exec_prefix])
        result = tracer.runfunc(run_python_sdk_tests, sdk)
        if not result.wasSuccessful():
            return CoverageResult(name="python-sdk", covered=0, total=1, minimum=PYTHON_SDK_MINIMUM)
        counts = tracer.results().counts
    finally:
        sys.path[:] = old_path

    covered = 0
    total = 0
    report_lines = ["file,covered,total,percent"]
    for path in sorted((sdk / "hovel_sdk").glob("*.py")):
        if path.name.endswith("_test.py"):
            continue
        executable = set(trace._find_executable_linenos(str(path)))  # noqa: SLF001 - stdlib trace has no public total-lines API.
        file_covered = sum(1 for line in executable if line_count(counts, path, line) > 0)
        file_total = len(executable)
        covered += file_covered
        total += file_total
        percent = 100.0 if file_total == 0 else file_covered * 100.0 / file_total
        report_lines.append(f"{path.relative_to(ROOT)},{file_covered},{file_total},{percent:.2f}")
    (COVERAGE_DIR / "python-sdk.csv").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    return CoverageResult(name="python-sdk", covered=covered, total=total, minimum=PYTHON_SDK_MINIMUM)


def run_python_sdk_tests(sdk: pathlib.Path) -> unittest.result.TestResult:
    suite = unittest.defaultTestLoader.discover(str(sdk), pattern="*_test.py", top_level_dir=str(sdk))
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=1)
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.stderr.write(stream.getvalue())
    return result


def line_count(counts: dict[tuple[str, int], int], path: pathlib.Path, line: int) -> int:
    return counts.get((str(path), line), 0) + counts.get((str(path.resolve()), line), 0)


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
