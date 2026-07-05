"""Payload tests for reflective_pe blob.

reflective_pe loads a PE from memory and executes it (Windows).

See: spec/verification/TEST-011-payload-pytest-suite.md
     spec/verification/TEST-005-reflective-loader-verification.md
"""

from __future__ import annotations

import struct

import pytest
from payload_defs import EXPECTATIONS, OPERATING_SYSTEMS, PAYLOAD_PLATFORMS, RUNNER_TYPE
from picblobs import get_blob
from picblobs.runner import is_arch_skip_rosetta, run_blob

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reflective_pe_combos() -> list[tuple[str, str]]:
    combos = []
    for os_name in PAYLOAD_PLATFORMS.get("reflective_pe", []):
        os_entry = OPERATING_SYSTEMS.get(os_name)
        if os_entry is None:
            continue
        combos.extend((os_name, arch) for arch in os_entry.architectures)
    return sorted(combos)


def _blob_exists(blob_type: str, target_os: str, target_arch: str) -> bool:
    try:
        get_blob(blob_type, target_os, target_arch)
    except FileNotFoundError:
        return False
    else:
        return True


def _build_reflective_pe_config(pe_data: bytes, target_arch: str) -> bytes:
    """Build config struct: pe_size (u32) + flags (u32) + entry_type (u8) + pe_data."""
    flags = 0
    entry_type = 0  # DLL entry
    return struct.pack("<IIB", len(pe_data), flags, entry_type) + pe_data


# ---------------------------------------------------------------------------
# Reflective PE loader tests
# ---------------------------------------------------------------------------


class TestReflectivePePayload:
    """Run reflective_pe on every supported platform."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _reflective_pe_combos(),
        ids=[f"{os}:{arch}" for os, arch in _reflective_pe_combos()],
    )
    def test_reflective_pe_loads_and_executes(
        self,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists("reflective_pe", target_os, target_arch):
            pytest.skip(f"reflective_pe not staged: {target_os}/{target_arch}")

        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        runner_type = RUNNER_TYPE[target_os]
        try:
            from picblobs.runner import find_runner

            find_runner(runner_type, target_arch)
        except FileNotFoundError:
            pytest.skip(f"No {runner_type} runner for {target_arch}")

        exp = EXPECTATIONS["reflective_pe"]
        blob = get_blob("reflective_pe", target_os, target_arch)

        # For mock runner, use a dummy PE (the mock validates control flow).
        dummy_pe = b"MZ" + b"\x00" * 126
        config = _build_reflective_pe_config(dummy_pe, target_arch)

        result = run_blob(blob, config=config, timeout=exp.timeout)

        assert result.exit_code == exp.exit_code, (
            f"reflective_pe {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        if exp.stdout_contains is not None:
            assert exp.stdout_contains in result.stdout
