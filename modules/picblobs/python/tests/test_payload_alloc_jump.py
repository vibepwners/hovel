"""Payload tests for alloc_jump blob.

The alloc_jump blob allocates RWX memory, copies a payload into it, and
jumps to it.  Tests supply a small test payload (test_pass) that writes
"PASS" to stdout and exits 0.

See: spec/verification/TEST-011-payload-pytest-suite.md
     spec/verification/TEST-004-alloc-jump-verification.md
"""

from __future__ import annotations

import struct

import pytest
from payload_defs import (
    EXPECTATIONS,
    OPERATING_SYSTEMS,
    PAYLOAD_PLATFORMS,
    RUNNER_TYPE,
    runtime_test_arches,
)
from picblobs import get_blob
from picblobs.runner import is_arch_skip_rosetta, run_blob

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map alloc_jump's inner test payload type (uses Linux syscalls).
TEST_PAYLOAD_TYPE = "test_pass"


def _inner_payload_os(target_os: str) -> str:
    """Return the OS for alloc_jump's inner test payload."""
    return "freebsd" if target_os == "freebsd" else "linux"


def _alloc_jump_combos() -> list[tuple[str, str]]:
    """Return (os, arch) for alloc_jump."""
    combos = []
    for os_name in PAYLOAD_PLATFORMS.get("alloc_jump", []):
        os_entry = OPERATING_SYSTEMS.get(os_name)
        if os_entry is None:
            continue
        combos.extend((os_name, arch) for arch in runtime_test_arches(os_name))
    return sorted(combos)


def _blob_exists(blob_type: str, target_os: str, target_arch: str) -> bool:
    try:
        get_blob(blob_type, target_os, target_arch)
    except FileNotFoundError:
        return False
    else:
        return True


def _build_alloc_jump_config(
    payload_bytes: bytes,
    target_arch: str,
) -> bytes:
    """Build config struct for alloc_jump: payload_size (u32) + payload_data."""
    return struct.pack("<I", len(payload_bytes)) + payload_bytes


# ---------------------------------------------------------------------------
# Core execution tests
# ---------------------------------------------------------------------------


class TestAllocJumpPayload:
    """Run alloc_jump on every supported platform."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _alloc_jump_combos(),
        ids=[f"{os}:{arch}" for os, arch in _alloc_jump_combos()],
    )
    def test_alloc_jump_executes_inner_payload(
        self,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists("alloc_jump", target_os, target_arch):
            pytest.skip(f"alloc_jump not staged: {target_os}/{target_arch}")

        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        inner_os = _inner_payload_os(target_os)
        if not _blob_exists(TEST_PAYLOAD_TYPE, inner_os, target_arch):
            pytest.skip(
                f"Test payload not staged: {TEST_PAYLOAD_TYPE}/{inner_os}/{target_arch}"
            )

        runner_type = RUNNER_TYPE[target_os]
        if runner_type != "linux":
            try:
                from picblobs.runner import find_runner

                find_runner(runner_type, target_arch)
            except FileNotFoundError:
                pytest.skip(f"No {runner_type} runner for {target_arch}")

        exp = EXPECTATIONS["alloc_jump"]
        blob = get_blob("alloc_jump", target_os, target_arch)

        # Load the inner test payload's raw code.
        inner = get_blob(TEST_PAYLOAD_TYPE, inner_os, target_arch)
        config = _build_alloc_jump_config(inner.code, target_arch)

        result = run_blob(blob, config=config, timeout=exp.timeout)

        assert result.exit_code == exp.exit_code, (
            f"alloc_jump {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        if exp.stdout is not None:
            assert result.stdout == exp.stdout, (
                f"alloc_jump {target_os}:{target_arch}: "
                f"stdout={result.stdout!r}, expected={exp.stdout!r}"
            )


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestAllocJumpEdgeCases:
    """Error handling and size checks for alloc_jump."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_arch",
        OPERATING_SYSTEMS["linux"].architectures,
        ids=OPERATING_SYSTEMS["linux"].architectures,
    )
    def test_absurd_payload_size_exits_cleanly(
        self,
        target_arch: str,
    ) -> None:
        if not _blob_exists("alloc_jump", "linux", target_arch):
            pytest.skip(f"alloc_jump not staged: linux/{target_arch}")

        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        blob = get_blob("alloc_jump", "linux", target_arch)
        # Request an impossible allocation size.
        config = struct.pack("<I", 0xFFFFFFFF)
        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0, (
            f"alloc_jump linux:{target_arch}: should fail with absurd size"
        )

    @pytest.mark.parametrize(
        "target_os,target_arch",
        _alloc_jump_combos(),
        ids=[f"{os}:{arch}" for os, arch in _alloc_jump_combos()],
    )
    def test_alloc_jump_under_512_bytes(
        self,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists("alloc_jump", target_os, target_arch):
            pytest.skip(f"alloc_jump not staged: {target_os}/{target_arch}")

        blob = get_blob("alloc_jump", target_os, target_arch)
        # Windows blobs include the TEB/PEB/PE resolution chain (~400 bytes
        # on i686) so they need a higher limit than unix blobs.
        limit = 768 if target_os == "windows" else 512
        assert len(blob.code) <= limit, (
            f"alloc_jump {target_os}:{target_arch}: "
            f"code size {len(blob.code)} bytes exceeds {limit} byte limit"
        )
