#!/usr/bin/env python3
"""Task-backed coverage ratchet for Hovel's highest-value layers."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import trace
import unittest
from dataclasses import dataclass
from typing import Iterable


ROOT = pathlib.Path(__file__).resolve().parents[2]
COVERAGE_DIR = ROOT / "coverage"
SUMMARY_PATH = COVERAGE_DIR / "summary.md"


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


GO_LAYERS: tuple[tuple[str, float, tuple[str, ...], str], ...] = (
    ("domain", 75.0, ("//internal/domain/...",), "internal/domain/"),
    ("app", 65.0, ("//internal/app/...",), "internal/app/"),
)

PYTHON_SDK_MINIMUM = 80.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-go", action="store_true", help="Only run Python SDK coverage.")
    parser.add_argument("--skip-python", action="store_true", help="Only run Go/Bazel coverage.")
    args = parser.parse_args()

    COVERAGE_DIR.mkdir(exist_ok=True)
    mode = coverage_mode(args.skip_go, args.skip_python)
    fingerprint = coverage_fingerprint(args.skip_go, args.skip_python)
    cached = read_cached_results(mode, fingerprint)
    if cached is not None:
        write_markdown_summary(cached)
        return print_results(cached, cached=True)

    results: list[CoverageResult] = []
    if not args.skip_go:
        results.extend(run_go_coverage_layers())
    if not args.skip_python:
        results.append(run_python_sdk_coverage())

    write_cached_results(mode, fingerprint, results)
    write_markdown_summary(results)
    return print_results(results)


def print_results(results: list[CoverageResult], cached: bool = False) -> int:
    title = "\nCoverage ratchet"
    if cached:
        title += " (cached)"
    print(title)
    print("LAYER       COVERED/TOTAL   COVERAGE   FLOOR")
    failed = False
    for result in results:
        status = "ok" if result.ok else "FAIL"
        print(f"{result.name:<11} {result.covered:>5}/{result.total:<7} {result.percent:>7.2f}% {result.minimum:>6.2f}% {status}")
        failed = failed or not result.ok
    write_markdown_summary(results)
    if failed:
        print("\nCoverage fell below the ratchet floor. Add tests or intentionally adjust the Task-backed floor.")
        return 1
    return 0


def coverage_mode(skip_go: bool, skip_python: bool) -> str:
    if skip_go and skip_python:
        return "empty"
    if skip_go:
        return "python"
    if skip_python:
        return "go"
    return "full"


def coverage_fingerprint(skip_go: bool, skip_python: bool) -> str:
    digest = hashlib.sha256()
    digest.update(f"skip_go={skip_go};skip_python={skip_python}".encode())
    digest.update(b"\0")
    digest.update(repr(GO_LAYERS).encode())
    digest.update(b"\0")
    digest.update(repr(PYTHON_SDK_MINIMUM).encode())
    digest.update(b"\0")
    for path in coverage_inputs(skip_go, skip_python):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def coverage_inputs(skip_go: bool, skip_python: bool) -> list[pathlib.Path]:
    paths: set[pathlib.Path] = {
        ROOT / ".bazelrc",
        ROOT / "Taskfile.yml",
        ROOT / "MODULE.bazel.lock",
        ROOT / "tools/tests/check_coverage.py",
    }
    if not skip_go:
        paths.update({
            ROOT / "BUILD.bazel",
            ROOT / "go.mod",
            ROOT / "go.sum",
        })
        paths.update((ROOT / "internal").rglob("*.go"))
        paths.update((ROOT / "internal").rglob("BUILD.bazel"))
    if not skip_python:
        paths.update({
            ROOT / "sdk/python/BUILD.bazel",
            ROOT / "sdk/python/pyproject.toml",
            ROOT / "sdk/python/uv.lock",
        })
        paths.update((ROOT / "sdk/python/hovel_sdk").rglob("*.py"))
        paths.update((ROOT / "sdk/python").glob("*_test.py"))
    return sorted(path for path in paths if path.is_file())


def read_cached_results(mode: str, fingerprint: str) -> list[CoverageResult] | None:
    stamp = COVERAGE_DIR / f".{mode}.inputs.sha256"
    results_path = COVERAGE_DIR / f"{mode}.results.json"
    if not stamp.exists() or stamp.read_text(encoding="utf-8").strip() != fingerprint:
        return None
    if not results_path.is_file():
        return None
    raw_results = json.loads(results_path.read_text(encoding="utf-8"))
    return [
        CoverageResult(
            name=str(item["name"]),
            covered=int(item["covered"]),
            total=int(item["total"]),
            minimum=float(item["minimum"]),
        )
        for item in raw_results
    ]


def write_cached_results(mode: str, fingerprint: str, results: list[CoverageResult]) -> None:
    results_path = COVERAGE_DIR / f"{mode}.results.json"
    stamp = COVERAGE_DIR / f".{mode}.inputs.sha256"
    results_path.write_text(
        json.dumps(
            [
                {
                    "name": result.name,
                    "covered": result.covered,
                    "total": result.total,
                    "minimum": result.minimum,
                }
                for result in results
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    stamp.write_text(fingerprint + "\n", encoding="utf-8")


def run_go_coverage_layers() -> list[CoverageResult]:
    report = ROOT / "bazel-out/_coverage/_coverage_report.dat"
    report.unlink(missing_ok=True)
    targets = tuple(target for _, _, layer_targets, _ in GO_LAYERS for target in layer_targets)
    run(["task", "coverage:go", "--", *targets])
    if not report.exists():
        raise SystemExit(f"coverage report not found: {report}")
    records = list(read_lcov_records(report))
    results: list[CoverageResult] = []
    for name, minimum, _, prefix in GO_LAYERS:
        layer_records = [record for record in records if source_in_prefix(record_source(record), prefix)]
        if not layer_records:
            raise SystemExit(f"coverage report contained no records for {prefix}")
        covered, total = parse_lcov_records(layer_records)
        write_lcov_records(COVERAGE_DIR / f"{name}.lcov", layer_records)
        results.append(CoverageResult(name=name, covered=covered, total=total, minimum=minimum))
    return results


def parse_lcov(path: pathlib.Path) -> tuple[int, int]:
    return parse_lcov_records(read_lcov_records(path))


def read_lcov_records(path: pathlib.Path) -> list[list[str]]:
    records: list[list[str]] = []
    record: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record.append(line)
        if line == "end_of_record":
            records.append(record)
            record = []
    if record:
        records.append(record)
    return records


def source_in_prefix(source: str, prefix: str) -> bool:
    if source.startswith(str(ROOT) + "/"):
        source = source[len(str(ROOT)) + 1 :]
    return source.startswith(prefix)


def record_source(record: list[str]) -> str:
    for line in record:
        if line.startswith("SF:"):
            return line.removeprefix("SF:")
    return ""


def parse_lcov_records(records: Iterable[list[str]]) -> tuple[int, int]:
    covered = 0
    total = 0
    for record in records:
        for line in record:
            if not line.startswith("DA:"):
                continue
            total += 1
            _, payload = line.split(":", 1)
            _, hits = payload.split(",", 1)
            if int(hits) > 0:
                covered += 1
    return covered, total


def write_lcov_records(path: pathlib.Path, records: list[list[str]]) -> None:
    lines = [line for record in records for line in record]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


def write_markdown_summary(results: list[CoverageResult]) -> None:
    lines = [
        "### Coverage Ratchets",
        "",
        "| Layer | Covered | Coverage | Floor | Status |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for result in results:
        status = "pass" if result.ok else "fail"
        lines.append(f"| {result.name} | {result.covered}/{result.total} | {result.percent:.2f}% | {result.minimum:.2f}% | {status} |")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
