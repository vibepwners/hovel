from __future__ import annotations

import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from update_python_locks import _replace_if_changed


def test_replace_if_changed_preserves_unchanged_file(tmp_path: Path) -> None:
    source = tmp_path / "source.lock"
    destination = tmp_path / "destination.lock"
    source.write_text("same\n", encoding="utf-8")
    destination.write_text("same\n", encoding="utf-8")
    before = destination.stat()

    _replace_if_changed(source, destination)

    after = destination.stat()
    assert after.st_ino == before.st_ino
    assert after.st_mtime_ns == before.st_mtime_ns


def test_replace_if_changed_preserves_existing_mode(tmp_path: Path) -> None:
    source = tmp_path / "source.lock"
    destination = tmp_path / "destination.lock"
    source.write_text("new\n", encoding="utf-8")
    destination.write_text("old\n", encoding="utf-8")
    custom_mode = 0o640
    destination.chmod(custom_mode)

    _replace_if_changed(source, destination)

    assert destination.read_text(encoding="utf-8") == "new\n"
    assert stat.S_IMODE(destination.stat().st_mode) == custom_mode


def test_replace_if_changed_uses_unique_temporary_files(tmp_path: Path) -> None:
    destination = tmp_path / "destination.lock"
    concurrent_writers = 8
    sources = []
    for index in range(concurrent_writers):
        source = tmp_path / f"source-{index}.lock"
        source.write_text(f"content-{index}\n", encoding="utf-8")
        sources.append(source)

    with ThreadPoolExecutor(max_workers=concurrent_writers) as executor:
        futures = [
            executor.submit(_replace_if_changed, source, destination)
            for source in sources
        ]
        for future in futures:
            future.result()

    assert destination.read_text(encoding="utf-8") in {
        source.read_text(encoding="utf-8") for source in sources
    }
    assert list(tmp_path.glob(".destination.lock.*.tmp")) == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
