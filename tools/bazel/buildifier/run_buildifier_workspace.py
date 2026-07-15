#!/usr/bin/env python3
"""Run pinned buildifier against repository Starlark and Bazel files."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

NAMES = {"BUILD", "BUILD.bazel", "MODULE.bazel"}
SUFFIXES = {".bzl"}
EXCLUDED_PARTS = {
    ".git",
    ".local",
    ".sl",
    ".task",
    "__pycache__",
    "_site",
    "bazel-bin",
    "bazel-out",
    "bazel-testlogs",
    "dist",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buildifier-linux-amd64", required=True)
    parser.add_argument("--buildifier-linux-arm64", required=True)
    parser.add_argument("--mode", choices=("check", "fix"), default="check")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    repo = find_repo_root()
    files = collect_files(repo, args.paths)
    if not files:
        return 0

    buildifier = resolve_runfile(
        args.buildifier_linux_arm64
        if os.uname().machine in {"aarch64", "arm64"}
        else args.buildifier_linux_amd64,
    )
    mode = "fix" if args.mode == "fix" else "check"
    command = [
        str(buildifier),
        f"-mode={mode}",
        "-lint=warn",
        *[str(path) for path in files],
    ]
    return subprocess.run(command, cwd=repo, check=False).returncode


def collect_files(repo: Path, inputs: list[str]) -> list[Path]:
    raw_paths = [repo / path for path in inputs] if inputs else [repo]
    files: set[Path] = set()
    for path in raw_paths:
        path = path.resolve()
        if path.is_file():
            if is_buildifier_file(repo, path):
                files.add(path)
            continue
        if not path.exists():
            raise SystemExit(f"path does not exist: {path}")
        for candidate in repository_files(repo, path):
            if candidate.is_file() and is_buildifier_file(repo, candidate):
                files.add(candidate)
    return sorted(files)


def repository_files(repo: Path, root: Path) -> list[Path]:
    if excluded(repo, root):
        return []
    files: list[Path] = []
    for directory, names, filenames in os.walk(root):
        current = Path(directory)
        names[:] = [name for name in names if not excluded(repo, current / name)]
        files.extend(current / filename for filename in filenames)
    return files


def is_buildifier_file(repo: Path, path: Path) -> bool:
    if excluded(repo, path):
        return False
    return path.name in NAMES or path.suffix in SUFFIXES


def excluded(repo: Path, path: Path) -> bool:
    try:
        rel = path.relative_to(repo)
    except ValueError:
        return True
    return any(part in EXCLUDED_PARTS or part.startswith("bazel-") for part in rel.parts)


def find_repo_root() -> Path:
    env = os.environ.get("BUILD_WORKSPACE_DIRECTORY")
    if env:
        candidate = Path(env).resolve()
        if (candidate / "MODULE.bazel").is_file():
            return candidate
    for root in candidate_roots():
        candidate = root.resolve()
        if (candidate / "MODULE.bazel").is_file() and (candidate / "Taskfile.yml").is_file():
            return candidate
    raise SystemExit("unable to locate repository root")


def resolve_runfile(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path.resolve()
    for root in candidate_roots():
        candidate = root / value
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"unable to locate runfile {value}")


def candidate_roots() -> list[Path]:
    roots = [Path.cwd()]
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    expanded: list[Path] = []
    for root in roots:
        expanded.extend([root, root / "_main", root / "hovel_slices"])
    return expanded


if __name__ == "__main__":
    raise SystemExit(main())
