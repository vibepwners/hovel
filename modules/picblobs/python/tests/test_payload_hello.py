"""Payload tests for hello and hello_windows blobs.

These tests exercise the simplest payloads: write "Hello, world!\n" to
stdout and exit 0.  They validate the full execution stack (extraction,
runner discovery, QEMU invocation, blob execution) for every platform
the blob supports.

See: spec/verification/TEST-011-payload-pytest-suite.md
"""

from __future__ import annotations

import pytest
from payload_defs import (
    EXPECTATIONS,
    OPERATING_SYSTEMS,
    PAYLOAD_PLATFORMS,
    RUNNER_TYPE,
    runtime_test_arches,
)
from picblobs import get_blob, list_blobs
from picblobs.runner import is_arch_skip_rosetta, run_blob

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hello_combos() -> list[tuple[str, str, str]]:
    """Return (blob_type, os, arch) for tested hello/hello_windows combos."""
    combos = []
    for bt in ("hello", "hello_windows"):
        for os_name in PAYLOAD_PLATFORMS.get(bt, []):
            if OPERATING_SYSTEMS.get(os_name) is None:
                continue
            combos.extend((bt, os_name, arch) for arch in runtime_test_arches(os_name))
    return sorted(combos)


def _blob_exists(blob_type: str, target_os: str, target_arch: str) -> bool:
    """Check if a blob is staged in the package."""
    try:
        get_blob(blob_type, target_os, target_arch)
    except FileNotFoundError:
        return False
    else:
        return True


# ---------------------------------------------------------------------------
# Core execution tests
# ---------------------------------------------------------------------------


class TestHelloPayload:
    """Run hello/hello_windows on every supported platform."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "blob_type,target_os,target_arch",
        _hello_combos(),
        ids=[f"{bt}:{os}:{arch}" for bt, os, arch in _hello_combos()],
    )
    def test_hello_produces_expected_output(
        self,
        blob_type: str,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists(blob_type, target_os, target_arch):
            pytest.skip(f"Blob not staged: {blob_type}/{target_os}/{target_arch}")

        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        runner_type = RUNNER_TYPE[target_os]
        if runner_type != "linux":
            try:
                from picblobs.runner import find_runner

                find_runner(runner_type, target_arch)
            except FileNotFoundError:
                pytest.skip(f"No {runner_type} runner for {target_arch}")

        exp = EXPECTATIONS[blob_type]
        blob = get_blob(blob_type, target_os, target_arch)
        result = run_blob(blob, timeout=exp.timeout)

        assert result.exit_code == exp.exit_code, (
            f"{blob_type} {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, expected={exp.exit_code}, "
            f"stderr={result.stderr!r}"
        )
        if exp.stdout is not None:
            assert result.stdout == exp.stdout, (
                f"{blob_type} {target_os}:{target_arch}: "
                f"stdout={result.stdout!r}, expected={exp.stdout!r}"
            )
        if exp.stdout_contains is not None:
            assert exp.stdout_contains in result.stdout, (
                f"{blob_type} {target_os}:{target_arch}: "
                f"stdout={result.stdout!r}, expected to contain {exp.stdout_contains!r}"
            )


# ---------------------------------------------------------------------------
# Structural tests (no QEMU needed)
# ---------------------------------------------------------------------------


class TestHelloBlobStructure:
    """Validate blob metadata without executing."""

    @pytest.mark.parametrize(
        "blob_type,target_os,target_arch",
        _hello_combos(),
        ids=[f"{bt}:{os}:{arch}" for bt, os, arch in _hello_combos()],
    )
    def test_blob_size_reasonable(
        self,
        blob_type: str,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists(blob_type, target_os, target_arch):
            pytest.skip(f"Blob not staged: {blob_type}/{target_os}/{target_arch}")

        blob = get_blob(blob_type, target_os, target_arch)
        # hello (Linux syscalls) should be small; hello_windows (PEB walk +
        # DJB2 + PE export parsing) is inherently larger.
        limit = 512 if blob_type == "hello" else 1024
        assert len(blob.code) < limit, (
            f"{blob_type} {target_os}:{target_arch}: "
            f"code size {len(blob.code)} bytes exceeds {limit} byte limit"
        )

    @pytest.mark.parametrize(
        "blob_type,target_os,target_arch",
        _hello_combos(),
        ids=[f"{bt}:{os}:{arch}" for bt, os, arch in _hello_combos()],
    )
    def test_blob_has_text_section(
        self,
        blob_type: str,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists(blob_type, target_os, target_arch):
            pytest.skip(f"Blob not staged: {blob_type}/{target_os}/{target_arch}")

        blob = get_blob(blob_type, target_os, target_arch)
        text_sections = [s for s in blob.sections if ".text" in s]
        assert len(text_sections) > 0, (
            f"{blob_type} {target_os}:{target_arch}: no .text sections found"
        )

    @pytest.mark.parametrize(
        "blob_type,target_os,target_arch",
        _hello_combos(),
        ids=[f"{bt}:{os}:{arch}" for bt, os, arch in _hello_combos()],
    )
    def test_blob_entry_offset_is_zero(
        self,
        blob_type: str,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists(blob_type, target_os, target_arch):
            pytest.skip(f"Blob not staged: {blob_type}/{target_os}/{target_arch}")

        blob = get_blob(blob_type, target_os, target_arch)
        assert blob.entry_offset == 0, (
            f"{blob_type} {target_os}:{target_arch}: "
            f"entry_offset={blob.entry_offset}, expected 0"
        )

    def test_hello_listed_in_package(self) -> None:
        """At least one hello blob should be discoverable."""
        blobs = list_blobs()
        hello_blobs = [(bt, o, a) for bt, o, a in blobs if bt == "hello"]
        assert len(hello_blobs) > 0, "No hello blobs found in package"
