#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Bazel-provided golangci-lint over workspace Go packages.")
    parser.add_argument("--golangci-lint", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("packages", nargs="*", default=["./..."])
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    golangci_lint = resolve_runfile(args.golangci_lint)
    go = resolve_runfile(args.go)

    env = os.environ.copy()
    env["PATH"] = str(go.parent) + os.pathsep + env.get("PATH", "")
    env.setdefault("GOLANGCI_LINT_CACHE", str(workspace / "tmp" / "golangci-lint"))
    Path(env["GOLANGCI_LINT_CACHE"]).mkdir(parents=True, exist_ok=True)

    command = [
        str(golangci_lint),
        "run",
        "--config",
        str(workspace / ".golangci.yml"),
        *args.packages,
    ]
    return subprocess.run(command, cwd=workspace, env=env).returncode


def resolve_runfile(path: str) -> Path:
    raw = Path(path)
    if raw.is_absolute() and raw.exists():
        return raw.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            candidate = Path(root) / prefix / path
            if candidate.exists():
                return candidate.resolve()
    candidate = Path.cwd() / path
    if candidate.exists():
        return candidate.resolve()
    raise SystemExit(f"missing runfile: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
