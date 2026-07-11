from __future__ import annotations

from pathlib import Path

import pytest

import checkout


def test_full_checkout_requirement_includes_repo_quality_slice() -> None:
    repo_slice = next(item for item in checkout.SLICES if item.name == "repo")

    for path in repo_slice.paths:
        assert path in checkout.FULL_CHECKOUT_PATHS


def test_docs_slice_uses_remote_compatible_check() -> None:
    docs_slice = next(item for item in checkout.SLICES if item.name == "docs")

    assert docs_slice.check_task == "docs:check"


def test_full_checkout_requirement_rejects_missing_repo_quality_inputs(tmp_path: Path) -> None:
    for path in ("core", "docs", "modules", "repo-tools", "sdk"):
        (tmp_path / path).mkdir(parents=True)

    assert checkout.require_paths(tmp_path, checkout.FULL_CHECKOUT_PATHS) == 2

    for path in ("BUILD.bazel", "OWNERS"):
        (tmp_path / path).touch()
    (tmp_path / "tools/bazel").mkdir(parents=True)

    assert checkout.require_paths(tmp_path, checkout.FULL_CHECKOUT_PATHS) == 0


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        (None, "task"),
        ("", "task"),
        ("  ", "task"),
        ("/declared/tools/task", "/declared/tools/task"),
        ("  /declared/tools/task  ", "/declared/tools/task"),
    ],
)
def test_task_executable_uses_parent_task_binary(
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
    expected: str,
) -> None:
    if configured is None:
        monkeypatch.delenv("TASK_EXE", raising=False)
    else:
        monkeypatch.setenv("TASK_EXE", configured)

    assert checkout.task_executable() == expected
