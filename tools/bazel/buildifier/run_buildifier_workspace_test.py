"""Tests for repository-wide buildifier file discovery."""

from pathlib import Path

from run_buildifier_workspace import collect_files, repository_files


def test_collect_files_ignores_repository_local_tool_cache(tmp_path: Path) -> None:
    source_build = tmp_path / "core" / "BUILD.bazel"
    cached_build = tmp_path / ".local" / "bazel" / "embedded_tools" / "BUILD"
    source_build.parent.mkdir(parents=True)
    cached_build.parent.mkdir(parents=True)
    source_build.write_text("", encoding="utf-8")
    cached_build.write_text("", encoding="utf-8")

    assert collect_files(tmp_path, []) == [source_build]


def test_collect_files_ignores_generated_bazel_links(tmp_path: Path) -> None:
    source_module = tmp_path / "MODULE.bazel"
    generated_build = tmp_path / "bazel-out" / "BUILD.bazel"
    source_module.write_text("", encoding="utf-8")
    generated_build.parent.mkdir(parents=True)
    generated_build.write_text("", encoding="utf-8")

    assert collect_files(tmp_path, []) == [source_module]


def test_repository_walk_prunes_local_tool_cache(tmp_path: Path) -> None:
    source = tmp_path / "core" / "source.go"
    cached = tmp_path / ".local" / "bazel" / "embedded_tools" / "source.go"
    source.parent.mkdir(parents=True)
    cached.parent.mkdir(parents=True)
    source.write_text("", encoding="utf-8")
    cached.write_text("", encoding="utf-8")

    assert repository_files(tmp_path, tmp_path) == [source]
