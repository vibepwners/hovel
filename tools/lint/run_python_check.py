#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = runfiles_root()
    project = Path("sdk/python")
    examples = Path("examples/python")
    cache = Path(os.environ.get("TEST_TMPDIR", "/tmp")) / "python-check"
    env = os.environ | {
        "UV_CACHE_DIR": str(cache / "uv"),
        "UV_PROJECT_ENVIRONMENT": str(cache / "venv"),
        "RUFF_CACHE_DIR": str(cache / "ruff"),
        "MYPY_CACHE_DIR": str(cache / "mypy"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    uv = find_tool("uv")
    subprocess.run([uv, "run", "--project", str(project), "--group", "dev", "ruff", "check", str(project), str(examples)], check=True, cwd=root, env=env)
    for source_root, import_roots in mypy_invocations(root):
        subprocess.run(
            [
                uv,
                "run",
                "--project",
                str(project),
                "--group",
                "dev",
                "mypy",
                "--strict",
                "--explicit-package-bases",
                "--config-file",
                str(project / "pyproject.toml"),
                str(source_root),
            ],
            check=True,
            cwd=root,
            env=env | {"MYPYPATH": os.pathsep.join(str(item) for item in import_roots)},
        )
    commands = [
        [
            uv,
            "run",
            "--project",
            str(project),
            "--group",
            "dev",
            "pydoclint",
            "--config",
            str(project / "pyproject.toml"),
            str(project / "hovel_sdk"),
            str(examples),
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True, cwd=root, env=env)
    return 0


def find_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved:
        return resolved
    candidates = []
    home = os.environ.get("HOME")
    if home:
        candidates.append(Path(home) / ".local/bin" / name)
    candidates.extend([Path("/home/user/.local/bin") / name, Path("/home/runner/.local/bin") / name])
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise SystemExit(f"{name} is required for task python:check")


def mypy_invocations(root: Path) -> list[tuple[Path, list[Path]]]:
    sdk = root / "sdk/python"
    return [
        (Path("sdk/python/hovel_sdk"), [sdk]),
        (Path("examples/python/etro_exploit/hovel_etro_exploit"), [sdk, root / "examples/python/etro_exploit"]),
        (Path("examples/python/etro_survey/hovel_etro_survey"), [sdk, root / "examples/python/etro_survey"]),
        (Path("examples/python/mock_exploit/hovel_example_exploit"), [sdk, root / "examples/python/mock_exploit"]),
        (
            Path("examples/python/mock_exploit_session/hovel_example_exploit_session"),
            [sdk, root / "examples/python/mock_exploit_session"],
        ),
        (Path("examples/python/mock_survey/hovel_example_survey"), [sdk, root / "examples/python/mock_survey"]),
    ]


def runfiles_root() -> Path:
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


if __name__ == "__main__":
    raise SystemExit(main())
