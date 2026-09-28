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
    ".aspect-cache",
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
REMOTE_CHECK_FILE = Path(".aspect/check.axl")
REMOTE_CHECK_FORBIDDEN_TARGETS = ("materialize_docs_demo_outputs", "materialize_squatter_wine_demo_outputs")
HERMETIC_CC_VERSION = 'bazel_dep(name = "hermetic_cc_toolchain", version = "4.3.0")'
HERMETIC_CC_TOOLCHAINS = (
    '"@zig_sdk//toolchain:linux_amd64_gnu.2.28"',
    '"@zig_sdk//toolchain:linux_arm64_gnu.2.28"',
)
LOCAL_CC_DETECTION_DISABLED = "build --repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1"


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
    violations.extend(check_hermetic_cc_toolchain(repo))
    for path in starlark_files(repo):
        rel = path.relative_to(repo)
        allowed = HOST_ACTION_ALLOWLIST.get(rel, set())
        for line, text in numbered_lines(path):
            for setting in NON_HERMETIC_BAZEL_SETTINGS:
                if setting in text and setting not in allowed:
                    violations.append(Violation(path, f"non-hermetic Bazel setting {setting!r} is not allowlisted", line))

    check_file = repo / REMOTE_CHECK_FILE
    if not check_file.is_file():
        return violations
    check_text = check_file.read_text(encoding="utf-8")
    for target in REMOTE_CHECK_FORBIDDEN_TARGETS:
        for match in re.finditer(re.escape(target), check_text):
            violations.append(
                Violation(
                    check_file,
                    f"remote-compatible Aspect gate invokes host-service target {target!r}",
                    line_number(check_text, match.start()),
                )
            )
    return violations


def check_hermetic_cc_toolchain(repo: Path) -> list[Violation]:
    violations: list[Violation] = []
    for workspace in (repo, repo / "core"):
        module = workspace / "MODULE.bazel"
        bazelrc = workspace / ".bazelrc"
        if not module.is_file() or not bazelrc.is_file():
            continue
        module_text = module.read_text(encoding="utf-8")
        bazelrc_text = bazelrc.read_text(encoding="utf-8")
        required_module_fragments = (HERMETIC_CC_VERSION, *HERMETIC_CC_TOOLCHAINS)
        for fragment in required_module_fragments:
            if fragment not in module_text:
                violations.append(Violation(module, f"missing hermetic C/C++ toolchain configuration {fragment!r}"))
        if LOCAL_CC_DETECTION_DISABLED not in bazelrc_text:
            violations.append(Violation(bazelrc, "local C/C++ toolchain auto-detection must be disabled"))
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
        for path in repository_files(repo, root):
            if path.suffix != ".go" or path.name.endswith("_test.go"):
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
    for path in repository_files(repo, root):
        if not path.name.startswith("BUILD"):
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
    return sorted(
        {
            path.parent
            for path in repository_files(repo)
            if path.name in {"BUILD", "BUILD.bazel"}
        }
    )


def starlark_files(repo: Path) -> list[Path]:
    return sorted(
        path
        for path in repository_files(repo)
        if path.suffix == ".bzl" or path.name in {"BUILD", "BUILD.bazel"}
    )


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


def repository_files(repo: Path, root: Path | None = None) -> list[Path]:
    start = root or repo
    if excluded(repo, start):
        return []
    files: list[Path] = []
    for directory, names, filenames in os.walk(start):
        current = Path(directory)
        names[:] = [name for name in names if not excluded(repo, current / name)]
        files.extend(current / filename for filename in filenames)
    return files


def find_repo_root() -> Path:
    env = os.environ.get("BUILD_WORKSPACE_DIRECTORY")
    if env:
        candidate = Path(env).resolve()
        if (candidate / "MODULE.bazel").is_file():
            return candidate
    for root in candidate_roots():
        candidate = root.resolve()
        if (candidate / "MODULE.bazel").is_file() and (candidate / ".aspect").is_dir():
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
