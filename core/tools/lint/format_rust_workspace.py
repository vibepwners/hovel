#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


RUST_SOURCE_GLOBS = (
    "sdk/rust/hovel/src/*.rs",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Format or check Rust source files with Bazel-provided rustfmt.")
    parser.add_argument("--rustfmt", required=True, type=Path)
    parser.add_argument("--mode", choices=("check", "write"), required=True)
    args = parser.parse_args()

    workspace = workspace_root()
    rustfmt = resolve_tool(runfiles_root(workspace), args.rustfmt)
    sources = rust_sources(workspace)
    command = [rustfmt, "--edition", "2021"]
    if args.mode == "check":
        command.append("--check")
    command.extend(str(path) for path in sources)
    subprocess.run(command, check=True, cwd=workspace)
    return 0


def rust_sources(workspace: Path) -> list[Path]:
    sources: list[Path] = []
    for pattern in RUST_SOURCE_GLOBS:
        sources.extend(workspace.glob(pattern))
    if not sources:
        raise SystemExit("no Rust sources found")
    return sorted(sources)


def workspace_root() -> Path:
    for name in ("HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY"):
        value = os.environ.get(name)
        if not value:
            continue
        candidate = Path(value)
        for root in (candidate, candidate.parent):
            if (root / "sdk/rust/hovel/BUILD.bazel").exists():
                return root.resolve()
    cwd = Path.cwd()
    for parent in (cwd, *cwd.parents):
        if (parent / "sdk/rust/hovel/BUILD.bazel").exists():
            return parent.resolve()
    raise SystemExit("could not locate Hovel repository root")


def runfiles_root(workspace: Path) -> Path:
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if not value:
            continue
        root = Path(value)
        for prefix in ("_main", "hovel", ""):
            candidate = root / prefix
            if (candidate / "MODULE.bazel").exists():
                return candidate.resolve()
    return workspace


def resolve_tool(root: Path, path: Path) -> str:
    if path.is_absolute() and path.exists():
        return str(path)
    for candidate in (root / path, Path.cwd() / path):
        if candidate.exists():
            return str(candidate)
    raise SystemExit(f"missing Bazel-provided rustfmt: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
