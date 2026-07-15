#!/usr/bin/env python3
"""Stage Picblobs artifacts from declared Bazel runfiles."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from artifact_arch import verify_artifact_arch

log = logging.getLogger("picblobs.stage")

UL_EXEC_TEST_BINARY_NAME = "hello_et_exec"


@dataclass(frozen=True)
class BlobArtifact:
    os_name: str
    arch: str
    target: str
    staged_name: str
    path: Path


@dataclass(frozen=True)
class RunnerArtifact:
    runner_type: str
    os_name: str
    arch: str
    path: Path


@dataclass(frozen=True)
class TestBinaryArtifact:
    fixture_type: str
    os_name: str
    arch: str
    name: str
    path: Path


@dataclass
class StageSummary:
    passed: int = 0
    total: int = 0

    def add(self, ok: bool) -> None:
        self.total += 1
        self.passed += int(ok)

    def merge(self, other: StageSummary) -> None:
        self.passed += other.passed
        self.total += other.total


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

    if args.debug:
        raise SystemExit(
            "debug staging is not supported by the Bazel runfile materializer"
        )

    workspace = workspace_root()
    project_root = workspace / "modules" / "picblobs"
    selected_configs = set(args.configs or [])
    selected_targets = set(args.targets or [])

    summary = stage_blobs(
        parse_blobs(args.blob),
        workspace,
        project_root,
        selected_configs,
        selected_targets,
    )
    if not args.no_runners:
        summary.merge(
            stage_runners(
                parse_runners(args.runner),
                workspace,
                project_root,
                selected_configs,
            )
        )
        summary.merge(
            stage_test_binaries(
                parse_test_binaries(args.test_binary),
                workspace,
                project_root,
                selected_configs,
            )
        )

    log.info("%d/%d staged", summary.passed, summary.total)
    if summary.passed < summary.total:
        return 1

    if not args.no_extract and summary.passed > 0:
        return extract_blobs(project_root)

    return 0


def stage_blobs(
    blobs: list[BlobArtifact],
    workspace: Path,
    project_root: Path,
    configs: set[str],
    targets: set[str],
) -> StageSummary:
    summary = StageSummary()
    for blob in blobs:
        if not selected_blob(blob, configs, targets):
            continue
        summary.add(stage_blob(blob, workspace, project_root))
    return summary


def stage_blob(blob: BlobArtifact, workspace: Path, project_root: Path) -> bool:
    src = resolve_runfile(blob.path, workspace)
    dest = blob_dest(project_root, blob)
    tag = f"    {blob.staged_name}.so -> {blob.os_name}/{blob.arch}"
    if not src.exists():
        log.error("%-50s NOT FOUND: %s", tag, src)
        return False
    if not verify_artifact_arch(src, blob.arch):
        log.error("%-50s ARCH MISMATCH (expected %s): %s", tag, blob.arch, src)
        return False
    stage_file(src, dest)
    log.info("%-50s OK", tag)
    return True


def stage_runners(
    runners: list[RunnerArtifact],
    workspace: Path,
    project_root: Path,
    configs: set[str],
) -> StageSummary:
    summary = StageSummary()
    for runner in runners:
        if not selected(runner.os_name, runner.arch, configs):
            continue
        src = resolve_runfile(runner.path, workspace)
        dest = runner_dest(project_root, runner)
        tag = f"    runner -> {runner.runner_type}/{runner.arch}"
        summary.add(stage_executable(src, dest, tag, runner.arch))
    return summary


def stage_test_binaries(
    test_binaries: list[TestBinaryArtifact],
    workspace: Path,
    project_root: Path,
    configs: set[str],
) -> StageSummary:
    summary = StageSummary()
    for test_binary in test_binaries:
        if not selected(test_binary.os_name, test_binary.arch, configs):
            continue
        src = resolve_runfile(test_binary.path, workspace)
        dest = test_binary_dest(project_root, test_binary)
        tag = test_binary_tag(test_binary)
        summary.add(stage_executable(src, dest, tag, test_binary.arch))
    return summary


def stage_executable(src: Path, dest: Path, tag: str, expected_arch: str) -> bool:
    if not src.exists():
        log.error("%-50s NOT FOUND: %s", tag, src)
        return False
    if not verify_artifact_arch(src, expected_arch):
        log.error("%-50s ARCH MISMATCH (expected %s): %s", tag, expected_arch, src)
        return False
    stage_file(src, dest, executable=True)
    log.info("%-50s OK", tag)
    return True


def extract_blobs(project_root: Path) -> int:
    log.info("  extracting release blobs...")
    from extract_release import extract_release

    so_dir = project_root / "python" / "picblobs" / "_blobs"
    out_dir = project_root / "python" / "picblobs"
    extracted, errors = extract_release(so_dir, out_dir)
    log.info("  %d blobs extracted (%d errors)", extracted, errors)
    return int(bool(errors))


def selected_blob(
    blob: BlobArtifact,
    configs: set[str],
    targets: set[str],
) -> bool:
    if not selected(blob.os_name, blob.arch, configs):
        return False
    return not targets or blob.target in targets or blob.staged_name in targets


def blob_dest(project_root: Path, blob: BlobArtifact) -> Path:
    return (
        project_root
        / "python"
        / "picblobs"
        / "_blobs"
        / blob.os_name
        / blob.arch
        / f"{blob.staged_name}.so"
    )


def runner_dest(project_root: Path, runner: RunnerArtifact) -> Path:
    return (
        project_root
        / "python_cli"
        / "picblobs_cli"
        / "_runners"
        / runner.runner_type
        / runner.arch
        / "runner"
    )


def test_binary_dest(project_root: Path, test_binary: TestBinaryArtifact) -> Path:
    return (
        project_root
        / "python_cli"
        / "picblobs_cli"
        / "_test_binaries"
        / test_binary.fixture_type
        / test_binary.os_name
        / test_binary.arch
        / test_binary.name
    )


def test_binary_tag(test_binary: TestBinaryArtifact) -> str:
    target = f"{test_binary.fixture_type}/{test_binary.os_name}/{test_binary.arch}"
    return f"    {test_binary.name} -> {target}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", action="append", default=[], metavar="SPEC=PATH")
    parser.add_argument("--runner", action="append", default=[], metavar="SPEC=PATH")
    parser.add_argument(
        "--test-binary", action="append", default=[], metavar="SPEC=PATH"
    )
    parser.add_argument("--targets", nargs="*", default=None)
    parser.add_argument(
        "--configs", nargs="*", default=None, help="Platform configs as os:arch."
    )
    parser.add_argument("--no-runners", action="store_true")
    parser.add_argument("--no-extract", action="store_true")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def workspace_root() -> Path:
    return Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()


def selected(os_name: str, arch: str, configs: set[str]) -> bool:
    return not configs or f"{os_name}:{arch}" in configs


def parse_spec(raw: str, parts: int) -> tuple[list[str], Path]:
    if "=" not in raw:
        raise SystemExit(f"invalid staging argument {raw!r}; expected SPEC=PATH")
    spec, path = raw.split("=", 1)
    fields = spec.split(":")
    if len(fields) != parts:
        raise SystemExit(
            f"invalid staging spec {spec!r}; expected {parts} colon-separated fields"
        )
    return fields, Path(path)


def parse_blobs(raw_values: list[str]) -> list[BlobArtifact]:
    result = []
    for raw in raw_values:
        fields, path = parse_spec(raw, 4)
        result.append(BlobArtifact(fields[0], fields[1], fields[2], fields[3], path))
    return result


def parse_runners(raw_values: list[str]) -> list[RunnerArtifact]:
    result = []
    for raw in raw_values:
        fields, path = parse_spec(raw, 3)
        result.append(RunnerArtifact(fields[0], fields[1], fields[2], path))
    return result


def parse_test_binaries(raw_values: list[str]) -> list[TestBinaryArtifact]:
    result = []
    for raw in raw_values:
        fields, path = parse_spec(raw, 4)
        result.append(
            TestBinaryArtifact(fields[0], fields[1], fields[2], fields[3], path)
        )
    return result


def resolve_runfile(path: Path, workspace: Path) -> Path:
    if path.is_absolute():
        return path
    candidates = [workspace / path, Path.cwd() / path]
    for root in runfile_roots():
        candidates.extend(root / prefix / path for prefix in ("", "_main", "hovel"))
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0]


def runfile_roots() -> list[Path]:
    roots = [
        Path(value)
        for name in ("RUNFILES_DIR", "TEST_SRCDIR")
        if (value := os.environ.get(name))
    ]
    if executable := os.environ.get("PYTHON_BINARY"):
        roots.append(Path(executable).parent)
    roots.append(Path.cwd())
    return roots


def stage_file(src: Path, dest: Path, executable: bool = False) -> bool:
    if not src.exists():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.chmod(stat.S_IWUSR | stat.S_IRUSR)
        dest.unlink()
    shutil.copy2(src, dest)
    if executable:
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


if __name__ == "__main__":
    raise SystemExit(main())
