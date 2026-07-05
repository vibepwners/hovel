"""Tests for picblobs._extractor module."""

from __future__ import annotations

from pathlib import Path

import pytest
from picblobs._extractor import BlobData, load_from_sidecar


class TestBlobData:
    """Test the BlobData dataclass."""

    def test_frozen(self) -> None:
        blob = BlobData(
            code=b"\x90",
            config_offset=1,
            entry_offset=0,
            blob_type="test",
            target_os="linux",
            target_arch="x86_64",
            sha256="abc",
            sections={},
        )
        with pytest.raises(AttributeError):
            blob.code = b"\x00"  # type: ignore[misc]

    def test_fields(self) -> None:
        blob = BlobData(
            code=b"\xcc\xcc",
            config_offset=2,
            entry_offset=0,
            blob_type="alloc_jump",
            target_os="linux",
            target_arch="aarch64",
            sha256="deadbeef",
            sections={".text": (0, 2)},
        )
        assert len(blob.code) == 2
        assert blob.config_offset == 2
        assert blob.blob_type == "alloc_jump"
        assert blob.target_os == "linux"
        assert blob.target_arch == "aarch64"
        assert ".text" in blob.sections


class TestSidecarLoad:
    """Tests for sidecar loading behavior not covered by release tests."""

    def test_missing_bin_file_raises(self, tmp_path: Path) -> None:
        json_path = tmp_path / "blob.json"
        json_path.write_text("{}")
        with pytest.raises(FileNotFoundError):
            load_from_sidecar(tmp_path / "nonexistent.bin", json_path)

    def test_missing_json_file_raises(self, tmp_path: Path) -> None:
        bin_path = tmp_path / "blob.bin"
        bin_path.write_bytes(b"\x90")
        with pytest.raises(FileNotFoundError):
            load_from_sidecar(bin_path, tmp_path / "nonexistent.json")
