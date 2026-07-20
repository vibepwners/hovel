#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Python lint, type, and doc checks with Bazel-provided tools.")
    parser.add_argument("--ruff", required=True, type=Path)
    parser.add_argument("--mypy", required=True, type=Path)
    parser.add_argument("--pydoclint", required=True, type=Path)
    parser.add_argument("--only", choices=("all", "ruff", "mypy", "pydoclint"), default="all")
    args = parser.parse_args()

    root = runfiles_root()
    project = Path("sdk/python")
    package = project / "hovel_sdk"
    examples = Path("modules/examples/python")
    cache = Path(os.environ.get("TEST_TMPDIR", "/tmp")) / "python-check"
    env = os.environ | {
        "RUFF_CACHE_DIR": str(cache / "ruff"),
        "MYPY_CACHE_DIR": str(cache / "mypy"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    ruff = resolve_tool(root, args.ruff)
    mypy = resolve_tool(root, args.mypy)
    pydoclint = resolve_tool(root, args.pydoclint)

    if args.only in {"all", "ruff"}:
        subprocess.run([ruff, "check", str(package), str(examples)], check=True, cwd=root, env=env)
    if args.only in {"all", "mypy"}:
        type_stubs = root / "core/tools/lint/stubs"
        for source_root, import_roots in mypy_invocations(root):
            subprocess.run(
                [
                    mypy,
                    "--strict",
                    "--explicit-package-bases",
                    "--config-file",
                    str(project / "pyproject.toml"),
                    str(source_root),
                ],
                check=True,
                cwd=root,
                env=env | {"MYPYPATH": os.pathsep.join(str(item) for item in (*import_roots, type_stubs))},
            )
    if args.only in {"all", "pydoclint"}:
        subprocess.run(
            [
                pydoclint,
                "--config",
                str(project / "pyproject.toml"),
                str(package),
                str(examples),
            ],
            check=True,
            cwd=root,
            env=env,
        )
    return 0


def mypy_invocations(root: Path) -> list[tuple[Path, list[Path]]]:
    sdk = root / "sdk/python"
    examples = root / "modules/examples/python"
    return [
        (Path("sdk/python/hovel_sdk"), [sdk]),
        (
            Path("modules/examples/python/ms17_010_exploit/hovel_ms17_010_exploit"),
            [sdk, examples / "ms17_010_exploit"],
        ),
        (
            Path("modules/examples/python/ms17_010_survey/hovel_ms17_010_survey"),
            [sdk, examples / "ms17_010_survey"],
        ),
        (
            Path("modules/examples/python/mock_exploit/hovel_example_exploit"),
            [sdk, examples / "mock_exploit"],
        ),
        (
            Path("modules/examples/python/mock_exploit_session/hovel_example_exploit_session"),
            [sdk, examples / "mock_exploit_session"],
        ),
        (
            Path("modules/examples/python/mock_survey/hovel_example_survey"),
            [sdk, examples / "mock_survey"],
        ),
    ]


def runfiles_root() -> Path:
    for name in ("HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY"):
        value = os.environ.get(name)
        if value:
            candidate = Path(value)
            if (candidate / "sdk/python/pyproject.toml").exists():
                return candidate.resolve()
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if not value:
            continue
        root = Path(value)
        for prefix in ("_main", "hovel", ""):
            candidate = root / prefix
            if (candidate / "sdk/python/pyproject.toml").exists():
                return candidate.resolve()
    cwd = Path.cwd()
    if (cwd / "sdk/python/pyproject.toml").exists():
        return cwd.resolve()
    raise SystemExit("could not locate runfiles root")


def resolve_tool(root: Path, path: Path) -> str:
    if path.is_absolute() and path.exists():
        return str(path)
    for candidate in (root / path, Path.cwd() / path):
        if candidate.exists():
            return str(candidate)
    raise SystemExit(f"missing Bazel-provided Python tool: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
