#!/usr/bin/env python3
"""Format all project source files.

Runs clang-format on C/H files and Ruff format on Python files.
Excludes build artifacts, venvs, and external dependencies.

Usage:
    python tools/fmt.py            # format in place
    python tools/fmt.py --check    # exit 1 if anything would change (for CI)
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

from quality_paths import PROJECT_ROOT, collect_files

log = logging.getLogger("fmt")

if TYPE_CHECKING:
    from pathlib import Path

# Directories to search for source files.
C_ROOTS = ["src", "tests"]
PY_ROOTS = [
    "python/picblobs",
    "python/tests",
    "python_cli/picblobs_cli",
    "python_cli/tests",
    "tools",
    "kernel",
]
# Roots for Starlark / BUILD files. Buildifier walks these recursively.
BAZEL_ROOTS = [
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
BAZEL_EXTENSIONS = {".bzl"}
BAZEL_NAMES = {"BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"}

# Directories to exclude (relative to project root).
EXCLUDE = {
    "bazel-bin",
    "bazel-out",
    "bazel-testlogs",
    "bazel-picblobs",
    ".venv",
    "__pycache__",
    ".cache",
    "node_modules",
}
CLANG_FORMAT_STYLE = f"file:{PROJECT_ROOT / '.clang-format'}"


def _run_formatter(
    name: str,
    cmd: list[str],
    files: list[Path],
    check: bool,
) -> bool:
    """Run a formatter on a list of files. Returns True if all clean."""
    if not files:
        return True

    binary = shutil.which(cmd[0])
    if binary is None:
        log.error("%s not found. Install it to format %d files.", cmd[0], len(files))
        return False

    full_cmd = cmd + [str(f) for f in files]
    log.info("%s: %d files", name, len(files))
    log.debug("  %s", " ".join([*cmd[:3], "..."]))

    result = subprocess.run(
        full_cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    if result.returncode != 0:
        if check:
            # Show which files need formatting.
            if result.stdout:
                for line in result.stdout.strip().splitlines():
                    log.error("  %s", line)
            if result.stderr:
                for line in result.stderr.strip().splitlines():
                    log.error("  %s", line)
        return False
    return True


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Format all project source files")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check formatting without modifying (exit 1 if unformatted)",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional files or directories to format. Defaults to repo source roots.",
    )
    return parser.parse_args()


def _collect_targets(paths: list[str]) -> tuple[list[Path], list[Path], list[Path]]:
    c_files = collect_files(
        paths,
        roots=C_ROOTS,
        extensions={".c", ".h"},
        exclude=EXCLUDE,
    )
    py_files = collect_files(
        paths,
        roots=PY_ROOTS,
        extensions={".py"},
        exclude=EXCLUDE,
    )
    bazel_files = collect_files(
        paths,
        roots=BAZEL_ROOTS,
        extensions=BAZEL_EXTENSIONS,
        exclude=EXCLUDE,
        names=BAZEL_NAMES,
    )
    # MODULE.bazel and root BUILD.bazel live at the repo root, not under any
    # of the BAZEL_ROOTS — pick them up explicitly when no paths were given.
    if not paths:
        for name in ("MODULE.bazel", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel"):
            candidate = PROJECT_ROOT / name
            if candidate.exists():
                bazel_files.append(candidate)
        bazel_files = sorted(set(bazel_files))
    return c_files, py_files, bazel_files


def _format_c_files(files: list[Path], *, check: bool) -> bool:
    if not files:
        return True
    if check:
        cmd = ["clang-format", "--dry-run", "--Werror", f"--style={CLANG_FORMAT_STYLE}"]
    else:
        cmd = ["clang-format", "-i", f"--style={CLANG_FORMAT_STYLE}"]
    return _run_formatter("clang-format", cmd, files, check)


def _format_python_files(files: list[Path], *, check: bool) -> bool:
    if not files:
        return True
    cmd = ["ruff", "format", "--check"] if check else ["ruff", "format"]
    return _run_formatter("ruff", cmd, files, check)


def _format_bazel_files(files: list[Path], *, check: bool) -> bool:
    if not files:
        return True
    if shutil.which("buildifier") is None:
        if os.environ.get("PICBLOBS_REQUIRE_LINT_TOOLS"):
            log.error("buildifier not found but PICBLOBS_REQUIRE_LINT_TOOLS is set")
            return False
        log.warning("buildifier not found; skipping %d Bazel files", len(files))
        return True
    cmd = ["buildifier", "--mode=check"] if check else ["buildifier"]
    return _run_formatter("buildifier", cmd, files, check)


def main() -> int:
    args = _parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

    c_files, py_files, bazel_files = _collect_targets(args.paths)

    if not c_files and not py_files and not bazel_files:
        log.info("No matching files.")
        return 0

    ok = _format_c_files(c_files, check=args.check)
    ok = _format_python_files(py_files, check=args.check) and ok
    ok = _format_bazel_files(bazel_files, check=args.check) and ok

    if ok:
        log.info("ok")
    else:
        if args.check:
            log.error("Formatting issues found. Run: python tools/fmt.py")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
