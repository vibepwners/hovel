#!/usr/bin/env python3
"""Check repository architecture, ownership, and hermeticity policy."""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path

SOURCE_ROOTS = {"core", "docs", "modules", "platforms", "repo-tools", "sdk", "tools"}
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
NON_HERMETIC_BAZEL_SETTINGS = ('"no-remote"', '"no-sandbox"', "use_default_shell_env = True")
HOST_ACTION_ALLOWLIST = {
    # VHS drives local tmux/Chrome and optionally Docker.
    Path("docs/demo/demo_defs.bzl"): {'"no-remote"', '"no-sandbox"', "use_default_shell_env = True"},
    # Manual QEMU tests manage host networking and nested VM processes.
    Path("modules/picblobs/kernel/BUILD.bazel"): {'"no-sandbox"'},
}
REMOTE_COMPATIBLE_TASKS = ("ci", "docs:check")
REMOTE_TASK_FORBIDDEN_DOCS = re.compile(r"\bdocs:(?:ci|site|demos(?::[A-Za-z0-9:_-]+)?)\b")


@dataclass(frozen=True)
class Violation:
    path: Path
    message: str
    line: int = 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", choices=("all", "hermeticity", "layers", "ownership", "visibility"), default="all")
    args = parser.parse_args()

    repo = find_repo_root()
    checks = [args.check] if args.check != "all" else ["hermeticity", "layers", "ownership", "visibility"]
    violations: list[Violation] = []
    if "hermeticity" in checks:
        violations.extend(check_hermeticity(repo))
    if "layers" in checks:
        violations.extend(check_layers(repo))
    if "ownership" in checks:
        violations.extend(check_ownership(repo))
    if "visibility" in checks:
        violations.extend(check_visibility(repo))

    if not violations:
        return 0
    for violation in sorted(violations, key=lambda item: (item.path.as_posix(), item.line, item.message)):
        location = relative(repo, violation.path)
        if violation.line:
            location += f":{violation.line}"
        print(f"{location}: {violation.message}")
    return 1


def check_hermeticity(repo: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in starlark_files(repo):
        rel = path.relative_to(repo)
        allowed = HOST_ACTION_ALLOWLIST.get(rel, set())
        for line, text in numbered_lines(path):
            for setting in NON_HERMETIC_BAZEL_SETTINGS:
                if setting in text and setting not in allowed:
                    violations.append(Violation(path, f"non-hermetic Bazel setting {setting!r} is not allowlisted", line))

    taskfile = repo / "Taskfile.yml"
    if not taskfile.is_file():
        return violations
    taskfile_text = taskfile.read_text(encoding="utf-8")
    for task_name in REMOTE_COMPATIBLE_TASKS:
        body, body_offset = task_block(taskfile_text, task_name)
        for match in REMOTE_TASK_FORBIDDEN_DOCS.finditer(body):
            violations.append(
                Violation(
                    taskfile,
                    f"remote-compatible task {task_name!r} invokes host-service task {match.group(0)!r}",
                    line_number(taskfile_text, body_offset + match.start()),
                )
            )
    return violations


def check_layers(repo: Path) -> list[Violation]:
    violations: list[Violation] = []
    policies = [
        ("core/internal/domain", ("/internal/adapters/", "/internal/app/", "/internal/infra/", "/internal/moduleruntime/", "/internal/protocol/")),
        ("core/internal/app", ("/internal/adapters/", "/internal/infra/", "/internal/moduleruntime/")),
        ("core/internal/infra", ("/internal/adapters/", "/internal/moduleruntime/")),
    ]
    for prefix, forbidden in policies:
        root = repo / prefix
        if not root.exists():
            continue
        for path in root.rglob("*.go"):
            if excluded(repo, path) or path.name.endswith("_test.go"):
                continue
            for line, imported in go_imports(path):
                for needle in forbidden:
                    if needle in imported:
                        violations.append(Violation(path, f"forbidden layer import {imported!r}", line))
    return violations


def check_ownership(repo: Path) -> list[Violation]:
    violations: list[Violation] = []
    if not (repo / "OWNERS").is_file():
        violations.append(Violation(repo / "OWNERS", "missing root OWNERS file"))
    for package in package_dirs(repo):
        if package == repo:
            continue
        rel = package.relative_to(repo)
        if not rel.parts or rel.parts[0] not in SOURCE_ROOTS:
            continue
        slice_root = repo / rel.parts[0]
        if not owner_between(slice_root, package):
            violations.append(Violation(package / "BUILD.bazel", f"missing OWNERS file from {rel.parts[0]}/ through package"))
    return violations


def check_visibility(repo: Path) -> list[Violation]:
    violations: list[Violation] = []
    root = repo / "core/internal"
    if not root.exists():
        return violations
    for path in root.rglob("BUILD*"):
        if excluded(repo, path) or not path.is_file():
            continue
        for line, text in numbered_lines(path):
            if "//visibility:public" in text:
                violations.append(Violation(path, "core internal target must not use //visibility:public", line))
    return violations


def go_imports(path: Path) -> list[tuple[int, str]]:
    imports: list[tuple[int, str]] = []
    in_block = False
    for line, text in numbered_lines(path):
        stripped = text.strip()
        if stripped == "import (":
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block:
            match = re.search(r'"([^"]+)"', stripped)
            if match:
                imports.append((line, match.group(1)))
            continue
        match = re.match(r'import\s+(?:[._a-zA-Z0-9]+\s+)?\"([^\"]+)\"', stripped)
        if match:
            imports.append((line, match.group(1)))
    return imports


def package_dirs(repo: Path) -> list[Path]:
    packages: set[Path] = set()
    for name in ("BUILD", "BUILD.bazel"):
        for path in repo.rglob(name):
            if path.is_file() and not excluded(repo, path):
                packages.add(path.parent)
    return sorted(packages)


def starlark_files(repo: Path) -> list[Path]:
    files: set[Path] = set()
    for pattern in ("*.bzl", "BUILD", "BUILD.bazel"):
        files.update(path for path in repo.rglob(pattern) if path.is_file() and not excluded(repo, path))
    return sorted(files)


def task_block(text: str, task_name: str) -> tuple[str, int]:
    match = re.search(rf"(?m)^  {re.escape(task_name)}:\s*$", text)
    if match is None:
        return "", 0
    start = match.end()
    next_task = re.search(r"(?m)^  [A-Za-z0-9:_-]+:\s*$", text[start:])
    end = start + next_task.start() if next_task else len(text)
    return text[start:end], start


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def owner_between(root: Path, package: Path) -> bool:
    current = package
    while True:
        if (current / "OWNERS").is_file():
            return True
        if current == root:
            return False
        if current.parent == current:
            return False
        current = current.parent


def numbered_lines(path: Path) -> list[tuple[int, str]]:
    return list(enumerate(path.read_text(encoding="utf-8").splitlines(), start=1))


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


def relative(repo: Path, path: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
