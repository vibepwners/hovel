"""Tests for sidecar loading (load_from_sidecar + manifest-based list_blobs).

Covers:
- load_from_sidecar: valid load, SHA-256 mismatch, missing fields, malformed sections
- list_blobs: manifest-based listing
- get_blob: sidecar-only loading
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import picblobs
import pytest
from picblobs import BlobType, ConfigLayout
from picblobs._extractor import BlobData, load_from_sidecar

# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def sidecar_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Create a valid .bin + .json sidecar pair in tmp_path."""
    code = b"\xcc" * 64
    sha = hashlib.sha256(code).hexdigest()

    bin_path = tmp_path / "test.linux.x86_64.bin"
    bin_path.write_bytes(code)

    meta = {
        "type": "test",
        "os": "linux",
        "arch": "x86_64",
        "size": len(code),
        "entry_offset": 0,
        "config_offset": 48,
        "sha256": sha,
        "sections": {
            ".text": {"offset": 0, "size": 32, "perm": "rx"},
            ".rodata": {"offset": 32, "size": 16, "perm": "r"},
            ".config": {"offset": 48, "size": 0, "perm": "rw"},
        },
        "config": None,
    }
    json_path = tmp_path / "test.linux.x86_64.json"
    json_path.write_text(json.dumps(meta))

    return bin_path, json_path


# ============================================================
# load_from_sidecar
# ============================================================


class TestLoadFromSidecar:
    """Tests for load_from_sidecar()."""

    def test_valid_load(self, sidecar_pair: tuple[Path, Path]) -> None:
        bin_path, json_path = sidecar_pair
        blob = load_from_sidecar(bin_path, json_path)

        assert isinstance(blob, BlobData)
        assert len(blob.code) == 64
        assert blob.config_offset == 48
        assert blob.entry_offset == 0
        assert blob.blob_type == "test"
        assert blob.target_os == "linux"
        assert blob.target_arch == "x86_64"
        assert blob.sha256 == hashlib.sha256(b"\xcc" * 64).hexdigest()

    def test_sections_parsed(self, sidecar_pair: tuple[Path, Path]) -> None:
        bin_path, json_path = sidecar_pair
        blob = load_from_sidecar(bin_path, json_path)

        assert ".text" in blob.sections
        assert blob.sections[".text"] == (0, 32)
        assert ".rodata" in blob.sections
        assert blob.sections[".rodata"] == (32, 16)
        assert ".config" in blob.sections
        assert blob.sections[".config"] == (48, 0)

    def test_sha256_mismatch_raises(self, sidecar_pair: tuple[Path, Path]) -> None:
        bin_path, json_path = sidecar_pair

        # Corrupt the .bin file.
        bin_path.write_bytes(b"\x00" * 64)

        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            load_from_sidecar(bin_path, json_path)

    def test_missing_required_field_raises(self, tmp_path: Path) -> None:
        code = b"\x90"
        sha = hashlib.sha256(code).hexdigest()

        bin_path = tmp_path / "bad.bin"
        bin_path.write_bytes(code)

        # Missing "type" field.
        meta = {
            "os": "linux",
            "arch": "x86_64",
            "config_offset": 1,
            "sha256": sha,
            "sections": {},
        }
        json_path = tmp_path / "bad.json"
        json_path.write_text(json.dumps(meta))

        with pytest.raises(ValueError, match="missing required field"):
            load_from_sidecar(bin_path, json_path)

    def test_missing_bin_file_raises(self, tmp_path: Path) -> None:
        json_path = tmp_path / "missing.json"
        json_path.write_text("{}")

        with pytest.raises(FileNotFoundError):
            load_from_sidecar(tmp_path / "missing.bin", json_path)

    def test_missing_json_file_raises(self, tmp_path: Path) -> None:
        bin_path = tmp_path / "missing.bin"
        bin_path.write_bytes(b"\x90")

        with pytest.raises(FileNotFoundError):
            load_from_sidecar(bin_path, tmp_path / "missing.json")

    def test_sections_as_list_fallback(self, tmp_path: Path) -> None:
        """Test that section info as [offset, size] list is handled."""
        code = b"\xcc" * 16
        sha = hashlib.sha256(code).hexdigest()

        bin_path = tmp_path / "listfmt.bin"
        bin_path.write_bytes(code)

        meta = {
            "type": "test",
            "os": "linux",
            "arch": "x86_64",
            "config_offset": 16,
            "sha256": sha,
            "sections": {".text": [0, 16]},
        }
        json_path = tmp_path / "listfmt.json"
        json_path.write_text(json.dumps(meta))

        blob = load_from_sidecar(bin_path, json_path)
        assert blob.sections[".text"] == (0, 16)
        assert isinstance(blob.sections[".text"][0], int)
        assert isinstance(blob.sections[".text"][1], int)


# ============================================================
# list_blobs with manifest
# ============================================================


class TestListBlobsManifest:
    """Tests for manifest-based list_blobs()."""

    def test_manifest_listing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """list_blobs() returns entries from manifest.json catalog."""
        import picblobs

        manifest = {
            "schema_version": 1,
            "catalog": {
                "hello": {
                    "platforms": {
                        "linux": ["x86_64", "aarch64"],
                        "windows": ["x86_64"],
                    }
                },
                "ul_exec": {
                    "platforms": {
                        "linux": ["x86_64"],
                    }
                },
            },
        }
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))

        monkeypatch.setattr(picblobs, "_MANIFEST_PATH", manifest_path)
        # Clear cached manifest.
        if hasattr(picblobs._load_manifest, "_cache"):
            del picblobs._load_manifest._cache

        try:
            result = picblobs.list_blobs()
            assert ("hello", "linux", "aarch64") in result
            assert ("hello", "linux", "x86_64") in result
            assert ("hello", "windows", "x86_64") in result
            assert ("ul_exec", "linux", "x86_64") in result
            assert len(result) == 4
            # Should be sorted.
            assert result == sorted(result)
        finally:
            # Clean up cache.
            if hasattr(picblobs._load_manifest, "_cache"):
                del picblobs._load_manifest._cache

    def test_no_manifest_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Return [] when manifest, filesystem, and registry are all absent."""
        import picblobs

        monkeypatch.setattr(picblobs, "_MANIFEST_PATH", tmp_path / "nonexistent.json")
        monkeypatch.setattr(picblobs, "_BLOBS_DIR", tmp_path / "blobs")
        monkeypatch.setattr(picblobs, "_registry_list_blobs", list)

        if hasattr(picblobs._load_manifest, "_cache"):
            del picblobs._load_manifest._cache

        try:
            result = picblobs.list_blobs()
            assert result == []
        finally:
            if hasattr(picblobs._load_manifest, "_cache"):
                del picblobs._load_manifest._cache


# ============================================================
# get_blob sidecar loading
# ============================================================


class TestGetBlobLoading:
    """Tests for get_blob() sidecar loading."""

    def test_loads_from_sidecar(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """get_blob() loads from .bin+.json sidecars."""
        import picblobs

        code = b"\xcc" * 32
        sha = hashlib.sha256(code).hexdigest()

        blobs_dir = tmp_path / "blobs"
        blobs_dir.mkdir()
        bin_path = blobs_dir / "hello.linux.x86_64.bin"
        bin_path.write_bytes(code)
        meta = {
            "type": "hello",
            "os": "linux",
            "arch": "x86_64",
            "config_offset": 32,
            "sha256": sha,
            "sections": {},
        }
        json_path = blobs_dir / "hello.linux.x86_64.json"
        json_path.write_text(json.dumps(meta))

        monkeypatch.setattr(picblobs, "_BLOBS_DIR", blobs_dir)
        picblobs.clear_cache()

        try:
            blob = picblobs.get_blob("hello", "linux", "x86_64")
            assert blob.code == code
            assert blob.blob_type == "hello"
        finally:
            picblobs.clear_cache()

    def test_get_blob_does_not_consult_staged_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A staged .so without sidecars is not a runtime blob source."""
        so_dir = tmp_path / "_blobs" / "linux" / "x86_64"
        so_dir.mkdir(parents=True)
        (so_dir / "hello.so").write_bytes(b"not an elf")

        monkeypatch.setattr(picblobs, "_BLOBS_DIR", tmp_path / "blobs")
        picblobs.clear_cache()

        try:
            with pytest.raises(FileNotFoundError, match="sidecar artifacts"):
                picblobs.get_blob("hello", "linux", "x86_64")
        finally:
            picblobs.clear_cache()


class TestConfigLayoutSidecarFallback:
    def test_uses_shipped_sidecar_when_registry_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        blobs_dir = tmp_path / "blobs"
        blobs_dir.mkdir()
        sidecar = blobs_dir / "alloc_jump.linux.x86_64.json"
        sidecar.write_text(
            json.dumps(
                {
                    "type": "alloc_jump",
                    "os": "linux",
                    "arch": "x86_64",
                    "config": {
                        "endian": "little",
                        "fixed_size": 4,
                        "fields": [
                            {"name": "payload_size", "type": "u32", "offset": 0}
                        ],
                        "trailing_data": [
                            {"name": "payload_data", "length_field": "payload_size"}
                        ],
                    },
                }
            )
        )

        monkeypatch.setattr("picblobs._introspect._BLOBS_DIR", blobs_dir)
        monkeypatch.setattr("picblobs._introspect._registry_blob_types", lambda: None)
        monkeypatch.setattr(
            picblobs,
            "list_blobs",
            lambda: [("alloc_jump", "linux", "x86_64")],
        )

        layout = picblobs.config_layout("linux", "x86_64", "alloc_jump")
        assert isinstance(layout, ConfigLayout)
        assert layout.blob_type is BlobType.ALLOC_JUMP
        assert layout.total_fixed_size == 4
        assert layout["payload_size"].offset == 0
        assert layout["payload_data"].variable is True


class TestExtractReleaseCleanup:
    def test_relaxed_section_iteration_avoids_pyelftools_wrappers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools import extract_release as er

        class Header(dict):
            __getattr__ = dict.__getitem__

        class FakeElf:
            def num_sections(self) -> int:
                return 1

            def _get_section_header(self, index: int) -> Header:
                assert index == 0
                return Header(
                    sh_flags=0,
                    sh_size=0,
                    sh_addr=0,
                    sh_type="SHT_RELA",
                )

            def _get_section_name(self, header: Header) -> str:
                assert header["sh_type"] == "SHT_RELA"
                return ".rela.dyn"

            def iter_sections(self):  # pragma: no cover - regression guard
                raise AssertionError("iter_sections should not be used")

        created: list[tuple[str, str]] = []

        class FakeSection:
            def __init__(self, header: Header, name: str, elffile: FakeElf) -> None:
                del elffile
                created.append((header["sh_type"], name))
                self.header = header
                self.name = name

        monkeypatch.setattr(er, "Section", FakeSection)

        sections = list(er._iter_sections_relaxed(FakeElf()))

        assert len(sections) == 1
        assert created == [("SHT_RELA", ".rela.dyn")]

    def test_relaxed_section_lookup_avoids_full_section_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools import extract_release as er

        class Header(dict):
            __getattr__ = dict.__getitem__

        class FakeElf:
            def num_sections(self) -> int:
                return 2

            def _get_section_header(self, index: int) -> Header:
                if index == 0:
                    return Header(sh_type="SHT_RELA")
                if index == 1:
                    return Header(sh_type="SHT_SYMTAB")
                raise AssertionError(index)

            def _get_section_name(self, header: Header) -> str:
                if header["sh_type"] == "SHT_RELA":
                    return ".rela.dyn"
                return ".symtab"

            def _make_section(self, header: Header):
                return {"type": header["sh_type"]}

            def iter_sections(self):  # pragma: no cover - regression guard
                raise AssertionError("iter_sections should not be used")

        result = er._get_section_by_name_relaxed(FakeElf(), ".symtab")

        assert result == {"type": "SHT_SYMTAB"}

    def test_removes_stale_release_artifacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools.extract_release import extract_release

        so_dir = tmp_path / "_blobs"
        current_so = so_dir / "linux" / "x86_64" / "hello.so"
        current_so.parent.mkdir(parents=True)
        current_so.write_bytes(b"fake elf")

        out_dir = tmp_path / "out"
        blobs_dir = out_dir / "blobs"
        blobs_dir.mkdir(parents=True)
        stale_bin = blobs_dir / "old.linux.x86_64.bin"
        stale_json = blobs_dir / "old.linux.x86_64.json"
        stale_bin.write_bytes(b"old")
        stale_json.write_text("{}")

        monkeypatch.setattr(
            "tools.extract_release._extract_so",
            lambda path: {
                "code": b"\x90",
                "size": 1,
                "config_offset": 1,
                "entry_offset": 0,
                "sha256": hashlib.sha256(b"\x90").hexdigest(),
                "sections": {},
            },
        )
        monkeypatch.setattr("tools.extract_release._get_version", lambda: "0.1.6")

        extracted, errors = extract_release(so_dir, out_dir)
        assert (extracted, errors) == (1, 0)
        assert not stale_bin.exists()
        assert not stale_json.exists()
        assert (blobs_dir / "hello.linux.x86_64.bin").exists()
        assert (blobs_dir / "hello.linux.x86_64.json").exists()

    def test_not_found_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """get_blob() raises FileNotFoundError when no blob exists."""
        import picblobs

        monkeypatch.setattr(picblobs, "_BLOBS_DIR", tmp_path / "empty_blobs")
        picblobs.clear_cache()

        try:
            with pytest.raises(FileNotFoundError, match="No blob for"):
                picblobs.get_blob("nonexistent", "linux", "x86_64")
        finally:
            picblobs.clear_cache()
