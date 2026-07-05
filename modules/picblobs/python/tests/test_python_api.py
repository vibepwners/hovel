"""TEST-008: Python API and metadata verification.

Covers REQ-015 (builder) and REQ-016 (introspection). Wheel packaging
(REQ-017) and matrix completeness (REQ-018) tests that exercise a
produced wheel live elsewhere; this file verifies everything that can
be validated against the source tree.
"""

from __future__ import annotations

import hashlib
import socket
import struct

import picblobs
import pytest
from picblobs import (
    OS,
    Arch,
    Blob,
    BlobType,
    ConfigLayout,
    Target,
    ValidationError,
)

requires_blobs = pytest.mark.requires_blobs

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _blob_staged(blob_type: str, os_: str, arch: str) -> bool:
    try:
        picblobs.get_blob(blob_type, os_, arch)
    except FileNotFoundError:
        return False
    else:
        return True


# ---------------------------------------------------------------------------
# 8.1 Import and basic API
# ---------------------------------------------------------------------------


class TestImportAndBasicAPI:
    def test_module_imports(self) -> None:
        assert picblobs.__version__

    def test_enums_accessible(self) -> None:
        assert picblobs.OS.LINUX.value == "linux"
        assert picblobs.Arch.X86_64.value == "x86_64"
        assert picblobs.BlobType.ALLOC_JUMP.value == "alloc_jump"

    def test_blob_class_accessible(self) -> None:
        assert callable(picblobs.Blob)

    def test_public_symbols_in_all(self) -> None:
        for sym in [
            "Blob",
            "OS",
            "Arch",
            "BlobType",
            "ValidationError",
            "targets",
            "blob_types",
            "is_supported",
            "raw_blob",
            "wrap_elf",
            "config_layout",
            "djb2",
            "djb2_dll",
        ]:
            assert sym in picblobs.__all__, sym


# ---------------------------------------------------------------------------
# 8.2 Support matrix completeness
# ---------------------------------------------------------------------------


class TestSupportMatrix:
    def test_targets_nonempty_and_well_typed(self) -> None:
        ts = picblobs.targets()
        assert len(ts) > 0
        for t in ts:
            assert isinstance(t, Target)
            assert isinstance(t.os, OS)
            assert isinstance(t.arch, Arch)

    def test_targets_covers_expected_platforms(self) -> None:
        ts = {(t.os.value, t.arch.value) for t in picblobs.targets()}
        # Linux has the widest coverage.
        assert ("linux", "x86_64") in ts
        assert ("linux", "aarch64") in ts
        assert ("linux", "sparcv8") in ts
        assert ("linux", "powerpc") in ts
        assert ("linux", "s390x") in ts
        assert ("freebsd", "x86_64") in ts
        assert ("windows", "x86_64") in ts

    def test_blob_types_for_linux_x86_64(self) -> None:
        types = picblobs.blob_types("linux", "x86_64")
        names = {b.value for b in types}
        # A representative subset — everything unix staged.
        for expected in (
            "hello",
            "alloc_jump",
            "stager_tcp",
            "stager_fd",
            "stager_pipe",
            "stager_mmap",
            "ul_exec",
        ):
            assert expected in names, (expected, names)

    def test_blob_types_for_windows_x86_64(self) -> None:
        types = picblobs.blob_types("windows", "x86_64")
        names = {b.value for b in types}
        for expected in (
            "hello_windows",
            "alloc_jump",
            "stager_tcp",
            "stager_fd",
            "stager_pipe",
            "reflective_pe",
        ):
            assert expected in names, (expected, names)

    def test_is_supported_positive(self) -> None:
        assert picblobs.is_supported("linux", "x86_64", "hello")
        assert picblobs.is_supported("windows", "x86_64", "reflective_pe")
        assert picblobs.is_supported(OS.LINUX, Arch.AARCH64, BlobType.ALLOC_JUMP)

    def test_is_supported_negative(self) -> None:
        # reflective_pe is Windows-only.
        assert not picblobs.is_supported("linux", "x86_64", "reflective_pe")
        # hello_windows is Windows-only.
        assert not picblobs.is_supported("linux", "x86_64", "hello_windows")
        # Bogus blob type.
        assert not picblobs.is_supported("linux", "x86_64", "nonexistent")

    def test_is_supported_accepts_enums_and_strings(self) -> None:
        assert picblobs.is_supported(OS.LINUX, Arch.X86_64, BlobType.HELLO)
        assert picblobs.is_supported("linux", "x86_64", "hello")


# ---------------------------------------------------------------------------
# 8.3 Builder — alloc_jump
# ---------------------------------------------------------------------------


@requires_blobs
class TestBuilderAllocJump:
    def test_basic_build(self) -> None:
        out = Blob("linux", "x86_64").alloc_jump().payload(b"\xcc").build()
        assert isinstance(out, bytes)
        assert len(out) > 1

    def test_length_includes_payload(self) -> None:
        small = Blob("linux", "x86_64").alloc_jump().payload(b"A" * 8).build()
        large = Blob("linux", "x86_64").alloc_jump().payload(b"A" * 64).build()
        assert len(large) - len(small) == 56

    def test_payload_in_output(self) -> None:
        marker = b"PAYLOAD_MARKER_XYZ"
        out = Blob("linux", "x86_64").alloc_jump().payload(marker).build()
        assert marker in out

    def test_blob_runs_when_built(self) -> None:
        """End-to-end: build with test_pass as inner payload, exec, verify."""
        if not _blob_staged("test_pass", "linux", "x86_64"):
            pytest.skip("test_pass not staged")

        inner = picblobs.get_blob("test_pass", "linux", "x86_64").code
        final = Blob("linux", "x86_64").alloc_jump().payload(inner).build_elf()

        import tempfile
        from pathlib import Path

        from picblobs.runner import build_linux_elf_command

        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(final)
            path = Path(f.name)
        path.chmod(path.stat().st_mode | 0o700)
        try:
            import subprocess

            try:
                cmd = build_linux_elf_command(path, "x86_64")
            except FileNotFoundError:
                pytest.skip("qemu-x86_64-static not installed")
            r = subprocess.run(cmd, capture_output=True, check=False, timeout=10)
            assert r.returncode == 0, r.stderr
            assert r.stdout == b"PASS"
        finally:
            path.unlink()


# ---------------------------------------------------------------------------
# 8.4 Builder — stager_tcp
# ---------------------------------------------------------------------------


@requires_blobs
class TestBuilderStagerTcp:
    def test_basic_build(self) -> None:
        out = (
            Blob("linux", "aarch64").stager_tcp().address("10.0.0.1").port(4444).build()
        )
        assert isinstance(out, bytes)

    def test_config_encoding(self) -> None:
        """Config bytes at config_offset must match: af(1) + port_le(2) + ip(4)."""
        ip = "192.168.1.42"
        port = 5555
        out = Blob("linux", "x86_64").stager_tcp().address(ip).port(port).build()

        # Look up where the config starts.
        raw = picblobs.raw_blob("linux", "x86_64", "stager_tcp")
        cfg_off = len(raw)
        cfg = out[cfg_off : cfg_off + 7]
        expected = struct.pack("<BH", 2, port) + socket.inet_aton(ip)
        assert cfg == expected


# ---------------------------------------------------------------------------
# 8.5 Builder — reflective_pe
# ---------------------------------------------------------------------------


@requires_blobs
class TestBuilderReflectivePe:
    def test_basic_build(self) -> None:
        dummy = b"MZ" + b"\x00" * 126
        out = (
            Blob("windows", "x86_64")
            .reflective_pe()
            .pe(dummy)
            .call_dll_main(True)
            .build()
        )
        assert isinstance(out, bytes)

    def test_config_has_flag(self) -> None:
        dummy = b"MZ" + b"\x00" * 126
        out_a = Blob("windows", "x86_64").reflective_pe().pe(dummy).build()
        out_b = (
            Blob("windows", "x86_64")
            .reflective_pe()
            .pe(dummy)
            .call_dll_main(True)
            .build()
        )
        assert out_a != out_b  # differ by flag byte


# ---------------------------------------------------------------------------
# 8.6 Builder — validation errors
# ---------------------------------------------------------------------------


class TestBuilderValidation:
    def test_missing_payload(self) -> None:
        with pytest.raises(ValidationError, match="payload"):
            Blob("linux", "x86_64").alloc_jump().build()

    def test_missing_tcp_address(self) -> None:
        with pytest.raises(ValidationError, match="address"):
            Blob("linux", "x86_64").stager_tcp().port(4444).build()

    def test_missing_tcp_port(self) -> None:
        with pytest.raises(ValidationError, match="port"):
            Blob("linux", "x86_64").stager_tcp().address("10.0.0.1").build()

    def test_reflective_pe_windows_only(self) -> None:
        with pytest.raises(ValidationError, match="Windows-only"):
            Blob("linux", "x86_64").reflective_pe()

    def test_port_out_of_range(self) -> None:
        with pytest.raises(ValidationError, match="out of range"):
            Blob("linux", "x86_64").stager_tcp().port(99999)
        with pytest.raises(ValidationError, match="out of range"):
            Blob("linux", "x86_64").stager_tcp().port(0)

    def test_unsupported_os(self) -> None:
        with pytest.raises(ValidationError, match="Unsupported OS"):
            Blob("macos", "x86_64")

    def test_unsupported_arch(self) -> None:
        with pytest.raises(ValidationError, match="Unsupported arch"):
            Blob("linux", "not-a-real-arch")

    def test_bad_ip(self) -> None:
        with pytest.raises(ValidationError, match="IPv4"):
            Blob("linux", "x86_64").stager_tcp().address("not an ip")

    def test_empty_payload(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            Blob("linux", "x86_64").alloc_jump().payload(b"")

    def test_non_bytes_payload(self) -> None:
        with pytest.raises(ValidationError, match="bytes"):
            Blob("linux", "x86_64").alloc_jump().payload("not bytes")

    def test_pe_bad_magic(self) -> None:
        with pytest.raises(ValidationError, match="MZ"):
            Blob("windows", "x86_64").reflective_pe().pe(b"NOTAPE")

    def test_elf_bad_magic(self) -> None:
        with pytest.raises(ValidationError, match="ELF"):
            Blob("linux", "x86_64").ul_exec().elf(b"NOT_AN_ELF")

    def test_ul_exec_missing_elf(self) -> None:
        with pytest.raises(ValidationError, match="elf"):
            Blob("linux", "x86_64").ul_exec().argv(["x"]).build()

    def test_stager_pipe_missing_path(self) -> None:
        with pytest.raises(ValidationError, match="path"):
            Blob("linux", "x86_64").stager_pipe().build()

    def test_stager_mmap_missing_size(self) -> None:
        with pytest.raises(ValidationError, match="size"):
            Blob("linux", "x86_64").stager_mmap().path("/tmp/x").build()

    def test_unsupported_combo_lists_alternatives(self) -> None:
        """hello_windows on linux should tell the caller what IS available."""
        with pytest.raises(ValidationError) as exc:
            # Use a direct internal call — the public API routes through
            # ``Blob.hello_windows`` which doesn't exist, so go via the
            # HelloBuilder with a mangled type.
            from picblobs._builder import _check_supported

            _check_supported(BlobType.HELLO_WINDOWS, OS.LINUX, Arch.X86_64)
        assert "Available blob types" in str(exc.value)


# ---------------------------------------------------------------------------
# 8.7 Builder — immutability
# ---------------------------------------------------------------------------


class TestBuilderImmutability:
    @requires_blobs
    def test_partial_builder_reusable_as_template(self) -> None:
        template = Blob("linux", "x86_64").stager_tcp().port(4444)
        a = template.address("10.0.0.1").build()
        b = template.address("10.0.0.2").build()
        assert a != b

    @requires_blobs
    def test_template_not_mutated(self) -> None:
        template = Blob("linux", "x86_64").stager_tcp().port(4444)
        # Calling .address returns a new builder; template still missing address.
        template.address("10.0.0.1").build()
        with pytest.raises(ValidationError, match="address"):
            template.build()

    def test_top_level_blob_frozen(self) -> None:
        b = Blob("linux", "x86_64")
        with pytest.raises(dataclasses_error()):
            b.os = OS.WINDOWS  # type: ignore[misc]


def dataclasses_error() -> type[Exception]:
    import dataclasses

    return dataclasses.FrozenInstanceError


# ---------------------------------------------------------------------------
# 8.8 Builder — string and enum parity
# ---------------------------------------------------------------------------


@requires_blobs
class TestStringEnumParity:
    def test_alloc_jump_parity(self) -> None:
        a = Blob("linux", "x86_64").alloc_jump().payload(b"XYZ").build()
        b = Blob(OS.LINUX, Arch.X86_64).alloc_jump().payload(b"XYZ").build()
        assert a == b

    def test_stager_tcp_parity(self) -> None:
        a = Blob("linux", "aarch64").stager_tcp().address("10.0.0.1").port(4444).build()
        b = (
            Blob(OS.LINUX, Arch.AARCH64)
            .stager_tcp()
            .address("10.0.0.1")
            .port(4444)
            .build()
        )
        assert a == b

    def test_uppercase_strings_accepted(self) -> None:
        Blob("LINUX", "X86_64").alloc_jump().payload(b"x").build()


# ---------------------------------------------------------------------------
# 8.9 / 8.10 Metadata + raw blob
# ---------------------------------------------------------------------------


class TestMetadata:
    @requires_blobs
    def test_blob_size_matches_raw(self) -> None:
        raw = picblobs.raw_blob("linux", "x86_64", "alloc_jump")
        assert len(raw) == picblobs.blob_size("linux", "x86_64", "alloc_jump")

    @requires_blobs
    def test_build_hash_matches_sha256(self) -> None:
        raw = picblobs.raw_blob("linux", "x86_64", "alloc_jump")
        expected = hashlib.sha256(raw).hexdigest()
        assert picblobs.build_hash("linux", "x86_64", "alloc_jump") == expected

    def test_config_layout_alloc_jump(self) -> None:
        layout = picblobs.config_layout("linux", "x86_64", "alloc_jump")
        assert isinstance(layout, ConfigLayout)
        assert layout.blob_type is BlobType.ALLOC_JUMP
        assert layout.total_fixed_size == 4
        names = [f.name for f in layout]
        assert "payload_size" in names
        # Trailing variable data exposed too.
        assert "payload_data" in names

    def test_config_layout_field_lookup(self) -> None:
        layout = picblobs.config_layout("linux", "x86_64", "stager_tcp")
        port = layout["port"]
        assert port.type == "u16"
        assert port.size == 2
        assert port.offset == 1

    def test_config_layout_to_dict(self) -> None:
        layout = picblobs.config_layout("linux", "x86_64", "alloc_jump")
        d = layout.to_dict()
        assert d["blob_type"] == "alloc_jump"
        assert isinstance(d["fields"], list)
        assert all("name" in f and "type" in f for f in d["fields"])

    def test_config_layout_for_hello_raises(self) -> None:
        with pytest.raises(ValidationError):
            picblobs.config_layout("linux", "x86_64", "hello")

    def test_raw_blob_missing(self) -> None:
        with pytest.raises(ValidationError):
            picblobs.raw_blob("linux", "x86_64", "reflective_pe")


# ---------------------------------------------------------------------------
# 8.11 DJB2
# ---------------------------------------------------------------------------


class TestDjb2:
    def test_empty_string(self) -> None:
        assert picblobs.djb2("") == 5381

    def test_kernel32_dll_hash(self) -> None:
        # Known hardcoded value used by the Windows blobs.
        assert picblobs.djb2("kernel32.dll") == 0x7040EE75

    def test_ws2_32_dll_hash(self) -> None:
        assert picblobs.djb2("ws2_32.dll") == 0x9AD10B0F

    def test_virtual_alloc_hash(self) -> None:
        assert picblobs.djb2("VirtualAlloc") == 0x382C0F97

    def test_djb2_dll_is_lowercased(self) -> None:
        assert picblobs.djb2_dll("KERNEL32.DLL") == picblobs.djb2("kernel32.dll")
        assert picblobs.djb2_dll("Ws2_32.DLL") == picblobs.djb2("ws2_32.dll")


# ---------------------------------------------------------------------------
# 8.12 structural wheel checks against the source tree
# ---------------------------------------------------------------------------


class TestSourceStructure:
    def test_blobs_staged_per_target(self) -> None:
        """Every known target should expose at least one blob type."""
        for t in picblobs.targets():
            types = picblobs.blob_types(t.os, t.arch)
            assert len(types) > 0, t

    def test_hello_across_unix_targets(self) -> None:
        """hello should be staged for all linux + freebsd targets."""
        for t in picblobs.targets():
            if t.os in (OS.LINUX, OS.FREEBSD):
                assert picblobs.is_supported(t.os, t.arch, "hello"), t
