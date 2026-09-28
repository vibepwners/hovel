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

    assert docs_slice.check_scope == "docs"


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
        (None, "aspect"),
        ("", "aspect"),
        ("  ", "aspect"),
        ("/declared/tools/aspect", "/declared/tools/aspect"),
        ("  /declared/tools/aspect  ", "/declared/tools/aspect"),
    ],
)
def test_aspect_executable_uses_declared_binary(
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
    expected: str,
) -> None:
    if configured is None:
        monkeypatch.delenv("ASPECT_EXE", raising=False)
    else:
        monkeypatch.setenv("ASPECT_EXE", configured)

    assert checkout.aspect_executable() == expected


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
