from __future__ import annotations

from pathlib import Path

import pytest

from docs.tools.demo.materialize_demo_outputs import refresh_demo_assets


FAKE_DEMO_DURATION_SECONDS = 1.25


def write_source(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def fake_duration(path: Path) -> float:
    if not path.read_bytes().startswith(b"GIF"):
        raise ValueError("invalid gif")
    return FAKE_DEMO_DURATION_SECONDS


def test_refresh_validates_every_asset_before_mutating_destinations(tmp_path: Path) -> None:
    dest_root = tmp_path / "public" / "demos"
    dest_root.mkdir(parents=True)
    existing = dest_root / "first.gif"
    existing.write_bytes(b"GIF-existing")
    sources = [
        write_source(tmp_path / "first-source.gif", b"GIF-new"),
        write_source(tmp_path / "second-source.gif", b"invalid"),
    ]

    with pytest.raises(ValueError, match="invalid gif"):
        refresh_demo_assets(
            "docs",
            ["out/first.gif", "out/second.gif"],
            sources,
            dest_root,
            fake_duration,
        )

    assert existing.read_bytes() == b"GIF-existing"
    assert not (dest_root / "second.gif").exists()


def test_all_mode_replaces_assets_and_prunes_obsolete_gifs(tmp_path: Path) -> None:
    dest_root = tmp_path / "public" / "demos"
    dest_root.mkdir(parents=True)
    (dest_root / "current.gif").write_bytes(b"GIF-old")
    (dest_root / "obsolete.gif").write_bytes(b"GIF-obsolete")
    source = write_source(tmp_path / "current-source.gif", b"GIF-new")

    refreshed = refresh_demo_assets(
        "all",
        ["out/current.gif"],
        [source],
        dest_root,
        fake_duration,
    )

    assert refreshed == [
        (dest_root / "current.gif", FAKE_DEMO_DURATION_SECONDS)
    ]
    assert (dest_root / "current.gif").read_bytes() == b"GIF-new"
    assert not (dest_root / "obsolete.gif").exists()


def test_narrow_refresh_preserves_unselected_assets(tmp_path: Path) -> None:
    dest_root = tmp_path / "public" / "demos"
    dest_root.mkdir(parents=True)
    preserved = dest_root / "preserved.gif"
    preserved.write_bytes(b"GIF-preserved")
    source = write_source(tmp_path / "current-source.gif", b"GIF-new")

    refresh_demo_assets(
        "docs",
        ["out/current.gif"],
        [source],
        dest_root,
        fake_duration,
    )

    assert preserved.read_bytes() == b"GIF-preserved"


def test_refresh_rejects_duplicate_destination_names(tmp_path: Path) -> None:
    source = write_source(tmp_path / "source.gif", b"GIF-new")

    with pytest.raises(ValueError, match="duplicate asset names"):
        refresh_demo_assets(
            "all",
            ["first/same.gif", "second/same.gif"],
            [source, source],
            tmp_path / "demos",
            fake_duration,
        )


def test_refresh_rejects_empty_or_non_gif_manifests(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="manifest is empty"):
        refresh_demo_assets("all", [], [], tmp_path / "demos", fake_duration)

    source = write_source(tmp_path / "source.txt", b"GIF-new")
    with pytest.raises(ValueError, match="non-GIF"):
        refresh_demo_assets(
            "all",
            ["out/source.txt"],
            [source],
            tmp_path / "demos",
            fake_duration,
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
