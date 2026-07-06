#!/usr/bin/env python3
"""Run repository lint checks.

Enforces Ruff linting for Python plus cyclomatic complexity via lizard.

Usage:
    python tools/lint.py            # run lint checks
    python tools/lint.py --check    # accepted for CI symmetry with fmt.py
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

from quality_paths import PROJECT_ROOT, collect_files

log = logging.getLogger("lint")

if TYPE_CHECKING:
    from pathlib import Path

LIZARD_THRESHOLD = 10
BASELINE_FILE = PROJECT_ROOT / "tools/lizard_baseline.txt"
RUFF_ROOTS = ["python/picblobs", "python/tests", "python_cli", "tools", "kernel"]

LIZARD_ROOTS = ["src", "tests", "python", "python_cli", "tools", "kernel"]
BUILDIFIER_ROOTS = [
    "bazel",
    "platforms",
    "release",
    "src",
    "tests",
    "toolchains",
    "tools",
    "python",
    "python_cli",
    "mbed",
    "kernel",
]
BUILDIFIER_EXTENSIONS = {".bzl"}
BUILDIFIER_NAMES = {
    "BUILD",
    "BUILD.bazel",
    "WORKSPACE",
    "WORKSPACE.bazel",
    "MODULE.bazel",
}
EXCLUDE = {
    "bazel-bin",
    "bazel-out",
    "bazel-testlogs",
    "bazel-pic",
    "bazel-picblobs",
    ".venv",
    "__pycache__",
    ".cache",
    "node_modules",
    "dist",
    "build",
}


def _relativize(paths: list[Path]) -> list[str]:
    return [str(path.relative_to(PROJECT_ROOT)) for path in paths]


def _build_lizard_command(paths: list[Path] | None = None) -> list[str]:
    cmd = [
        "lizard",
        f"--CCN={LIZARD_THRESHOLD}",
        "--warnings_only",
    ]
    for name in sorted(EXCLUDE):
        cmd.append(f"--exclude={name}")
        cmd.append(f"--exclude=*/{name}/*")
    cmd.extend(_relativize(paths) if paths is not None else LIZARD_ROOTS)
    return cmd


def _build_ruff_command(paths: list[Path] | None = None) -> list[str]:
    return ["ruff", "check", *(_relativize(paths) if paths is not None else RUFF_ROOTS)]


def _supports_appimage_extract(binary: str) -> bool:
    result = subprocess.run(
        [binary, "--appimage-version"],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _run_buildifier_check(paths: list[Path] | None = None) -> int:
    if paths == []:
        log.info("buildifier: no matching Bazel files")
        return 0

    binary = _resolve_tool("buildifier")
    if binary is None:
        if os.environ.get("PICBLOBS_REQUIRE_LINT_TOOLS"):
            log.error("buildifier not found but PICBLOBS_REQUIRE_LINT_TOOLS is set")
            return 1
        log.warning("buildifier not found; skipping Starlark lint")
        return 0

    targets = (
        _relativize(paths)
        if paths is not None
        else _relativize(_default_buildifier_paths())
    )
    cmd = [binary, "--lint=warn", "--mode=check", *targets]
    log.info("buildifier: %d Starlark files", len(targets))
    result = subprocess.run(
        cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, check=False
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def _default_buildifier_paths() -> list[Path]:
    files = collect_files(
        [],
        roots=BUILDIFIER_ROOTS,
        extensions=BUILDIFIER_EXTENSIONS,
        exclude=EXCLUDE,
        names=BUILDIFIER_NAMES,
    )
    # Root-level Bazel files aren't under any of the BUILDIFIER_ROOTS.
    for name in ("MODULE.bazel", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel"):
        candidate = PROJECT_ROOT / name
        if candidate.exists():
            files.append(candidate)
    return sorted(set(files))


def _run_ruff_check(paths: list[Path] | None = None) -> int:
    if paths == []:
        log.info("ruff: no matching Python files")
        return 0

    binary = _resolve_tool("ruff")
    if binary is None:
        log.error("ruff not found. Install it to run Python lint checks.")
        return 1

    cmd = [binary, *_build_ruff_command(paths)[1:]]
    log.info("ruff: Python lint checks")
    result = subprocess.run(
        cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, check=False
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def _run_lizard_check(paths: list[Path] | None, *, check_stale: bool) -> int:
    binary = _resolve_tool("lizard")
    if binary is None:
        log.error("lizard not found. Install it to run complexity checks.")
        return 1

    cmd = [binary, *_build_lizard_command(paths)[1:]]
    if _supports_appimage_extract(binary):
        cmd.insert(1, "--appimage-extract-and-run")
    log.info("lizard: cyclomatic complexity threshold <= %d", LIZARD_THRESHOLD)
    baseline = _load_baseline()
    result = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    current, stale = _filter_warnings(result.stdout, baseline)

    if current:
        for line in current:
            sys.stdout.write(f"{line}\n")
    if result.stderr:
        sys.stderr.write(result.stderr)
    if stale and check_stale:
        log.error("Stale lizard baseline entries found:")
        for entry in stale:
            log.error("  %s", entry)
        return 1
    if current:
        log.error("Complexity issues found.")
        return 1

    log.info("ok")
    return 0


def _resolve_tool(name: str) -> str | None:
    env_name = {
        "buildifier": "PICBLOBS_BUILDIFIER",
        "lizard": "PICBLOBS_LIZARD",
        "ruff": "PICBLOBS_RUFF",
    }.get(name)
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value
    return shutil.which(name)


def _load_baseline() -> set[str]:
    if not BASELINE_FILE.exists():
        return set()
    return {
        line.strip()
        for line in BASELINE_FILE.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def _warning_key(line: str) -> str | None:
    match = re.match(r"^(.*?):\d+: warning: ([^( ]+)\s+has\s+", line)
    if not match:
        return None
    path, func = match.groups()
    return f"{path}:{func}"


def _filter_warnings(stdout: str, baseline: set[str]) -> tuple[list[str], list[str]]:
    current: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        key = _warning_key(line)
        if key is None:
            continue
        seen.add(key)
        if key not in baseline:
            current.append(line)
    stale = sorted(baseline - seen)
    return current, stale


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run repository lint checks")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Accepted for CI symmetry; lint checks are always non-mutating",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional files or directories to lint. Defaults to repo source roots.",
    )
    return parser.parse_args()


def _collect_targets(paths: list[str]) -> tuple[list[Path], list[Path], list[Path]]:
    ruff_paths = collect_files(
        paths,
        roots=RUFF_ROOTS,
        extensions={".py"},
        exclude=EXCLUDE,
    )
    lizard_paths = collect_files(
        paths,
        roots=LIZARD_ROOTS,
        extensions={".c", ".h", ".py"},
        exclude=EXCLUDE,
    )
    buildifier_paths = collect_files(
        paths,
        roots=BUILDIFIER_ROOTS,
        extensions=BUILDIFIER_EXTENSIONS,
        exclude=EXCLUDE,
        names=BUILDIFIER_NAMES,
    )
    if paths:
        # Root-level files aren't under any of the BUILDIFIER_ROOTS but may
        # be passed explicitly.
        for raw in paths:
            candidate = (PROJECT_ROOT / raw).resolve()
            if candidate.name in BUILDIFIER_NAMES and candidate.is_file():
                buildifier_paths.append(candidate)
    buildifier_paths = sorted(set(buildifier_paths))
    return ruff_paths, lizard_paths, buildifier_paths


def _arg_or_default(paths: list[Path], have_explicit: bool) -> list[Path] | None:
    """Pass explicit paths through; otherwise let the runner use its defaults."""
    return paths if have_explicit else None


def main() -> int:
    args = _parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

    ruff_paths, lizard_paths, buildifier_paths = _collect_targets(args.paths)
    have_explicit = bool(args.paths)

    if have_explicit and not (ruff_paths or lizard_paths or buildifier_paths):
        log.info("No matching files.")
        return 0

    checks = (
        ("Ruff", _run_ruff_check, ruff_paths),
        ("Buildifier", _run_buildifier_check, buildifier_paths),
    )
    for label, runner, paths in checks:
        if runner(paths=_arg_or_default(paths, have_explicit)) != 0:
            log.error("%s issues found.", label)
            return 1

    if have_explicit and not lizard_paths:
        log.info("ok")
        return 0

    return _run_lizard_check(
        _arg_or_default(lizard_paths, have_explicit),
        check_stale=not have_explicit,
    )


if __name__ == "__main__":
    raise SystemExit(main())
