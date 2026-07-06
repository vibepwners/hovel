"""Registry sync enforcement tests.

These tests verify that platform/architecture data is consistent across
all locations in the codebase. They are designed to FAIL (not skip) when
a new architecture or OS is added to one place but not another.

Run after any change to platforms, architectures, or OS support:
    python -m pytest python/tests/test_sync.py -v
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

try:
    from ._test_env import PROJECT_ROOT, prepend_source_paths
except ImportError:  # pragma: no cover - supports direct module import
    from _test_env import PROJECT_ROOT, prepend_source_paths

prepend_source_paths()

from tools.registry import (  # noqa: E402, RUF100
    ARCHITECTURES,
    BLOB_TYPES,
    LINKER_SYMBOLS,
    MMAP_FLAGS,
    OPERATING_SYSTEMS,
    SYSCALL_DEFS,
    SYSCALL_NUMBERS,
    all_platforms,
    all_syscall_names,
    gcc_defines,
    qemu_binaries,
)

# ============================================================
# Helpers
# ============================================================


def _read_file(rel_path: str) -> str:
    return (PROJECT_ROOT / rel_path).read_text()


def _workspace_file(rel_path: str) -> str:
    hovel_root = PROJECT_ROOT.parents[1]
    path = hovel_root / rel_path
    if path.exists() and PROJECT_ROOT.parent.name == "modules":
        return path.read_text()
    return _read_file(rel_path)


# ============================================================
# Generated file freshness
# ============================================================


class TestGeneratedFreshness:
    """Verify generated files match what the generator would produce."""

    def test_generated_files_up_to_date(self) -> None:
        """tools/generate.py --check must pass."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "tools" / "generate.py"), "--check"],
            capture_output=True,
            check=False,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        assert result.returncode == 0, (
            f"Generated files are out of date. Run: python tools/generate.py\n"
            f"{result.stdout}"
        )


# ============================================================
# Python ↔ Registry sync
# ============================================================


class TestQemuSync:
    """Verify QEMU binary mappings are consistent."""

    def test_python_qemu_matches_registry(self) -> None:
        from picblobs._qemu import QEMU_BINARIES

        expected = qemu_binaries()
        assert expected == QEMU_BINARIES, (
            f"QEMU_BINARIES drift.\n"
            f"  Missing: {set(expected) - set(QEMU_BINARIES)}\n"
            f"  Extra:   {set(QEMU_BINARIES) - set(expected)}"
        )


class TestPlatformConfigSync:
    """Verify platform configs are consistent across all locations."""

    def test_freebsd_ul_exec_is_x86_64_only(self) -> None:
        assert BLOB_TYPES["ul_exec"].platforms["freebsd"] == ["x86_64"]
        manifest_path = PROJECT_ROOT / "python" / "picblobs" / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            assert manifest["catalog"]["ul_exec"]["platforms"]["freebsd"] == ["x86_64"]

    def test_stage_blobs_delegates_to_task(self) -> None:
        content = _read_file("tools/stage_blobs.py")
        assert '"task", "picblobs:stage"' in content
        assert '"bazel"' not in content

    def test_bazelrc_has_all_platforms(self) -> None:
        content = _workspace_file(".bazelrc")
        for os_name, arch_name in all_platforms():
            config_name = f"{os_name}_{arch_name}"
            assert f"build:{config_name}" in content, (
                f"Missing .bazelrc config '{config_name}'"
            )

    def test_platforms_build_has_all_platforms(self) -> None:
        content = _read_file("platforms/BUILD.bazel")
        for os_name, arch_name in all_platforms():
            platform_name = f"{os_name}_{arch_name}"
            assert f'name = "{platform_name}"' in content, (
                f"Missing platform '{platform_name}' in platforms/BUILD.bazel"
            )

    def test_platforms_build_has_standard_os_constraints(self) -> None:
        content = _read_file("platforms/BUILD.bazel")
        for os_def in OPERATING_SYSTEMS.values():
            assert os_def.bazel_os_constraint in content, (
                f"Missing standard OS constraint '{os_def.bazel_os_constraint}'"
            )

    def test_blob_targets_has_all_platforms(self) -> None:
        content = _read_file("bazel/platforms.bzl")
        for os_name, arch_name in all_platforms():
            key = f"{os_name}:{arch_name}"
            assert f'"{key}"' in content, (
                f"Platform '{key}' missing from platforms.bzl BLOB_TARGETS"
            )


class TestArchitectureRegistration:
    """Verify every architecture is registered in all required locations."""

    def test_all_arches_have_qemu(self) -> None:
        qemu = qemu_binaries()
        for arch_name in ARCHITECTURES:
            assert arch_name in qemu

    def test_all_arches_have_gcc_define(self) -> None:
        for name, arch in ARCHITECTURES.items():
            assert arch.gcc_define.startswith("__"), f"'{name}' gcc_define malformed"

    def test_all_arches_referenced_by_at_least_one_os(self) -> None:
        used = set()
        for os_def in OPERATING_SYSTEMS.values():
            used.update(os_def.architectures)
        for arch_name in ARCHITECTURES:
            assert arch_name in used, f"Orphan architecture: '{arch_name}'"

    def test_os_arches_all_exist(self) -> None:
        for os_name, os_def in OPERATING_SYSTEMS.items():
            for arch_name in os_def.architectures:
                assert arch_name in ARCHITECTURES, (
                    f"OS '{os_name}' references unknown arch '{arch_name}'"
                )


# ============================================================
# C header ↔ Registry sync
# ============================================================


class TestArchTraitsSync:
    """Verify C arch.h traits match registry.py traits."""

    def test_arch_h_has_all_gcc_defines(self) -> None:
        content = _read_file("src/include/picblobs/arch.h")
        for arch in ARCHITECTURES.values():
            assert arch.gcc_define in content, (
                f"arch.h missing block for {arch.gcc_define}"
            )

    def test_syscall_h_has_all_gcc_defines(self) -> None:
        content = _read_file("src/include/picblobs/syscall.h")
        for define in gcc_defines():
            assert define in content, f"syscall.h missing block for {define}"

    def test_mmap2_trait_consistency(self) -> None:
        for name, arch in ARCHITECTURES.items():
            if arch.uses_mmap2:
                assert arch.is_32bit, f"'{name}' uses mmap2 but is not 32-bit"

    def test_got_reloc_implies_trampoline(self) -> None:
        for name, arch in ARCHITECTURES.items():
            if arch.needs_got_reloc:
                assert arch.needs_trampoline or name == "powerpc", (
                    f"'{name}' needs GOT reloc but has no trampoline"
                )


# ============================================================
# Syscall consistency
# ============================================================


class TestSyscallConsistency:
    """Verify syscall tables and per-syscall headers are consistent."""

    def test_linux_all_arches_covered(self) -> None:
        """Every unique GCC define must have a syscall table."""
        for define in gcc_defines():
            assert define in SYSCALL_NUMBERS["linux"], (
                f"No Linux syscall table for {define}"
            )

    def test_linux_core_syscalls_present(self) -> None:
        """Every arch must define at minimum the core syscalls."""
        core = {
            "read",
            "write",
            "close",
            "mmap",
            "mprotect",
            "munmap",
            "exit",
            "exit_group",
        }
        for define, nrs in SYSCALL_NUMBERS["linux"].items():
            missing = core - set(nrs.keys())
            assert not missing, f"Linux/{define} missing core syscalls: {missing}"

    def test_linux_open_or_openat(self) -> None:
        """Every arch must define either 'open' or 'openat'."""
        for define, nrs in SYSCALL_NUMBERS["linux"].items():
            has_open = "open" in nrs or "openat" in nrs
            assert has_open, f"Linux/{define} has neither 'open' nor 'openat'"

    def test_32bit_arches_have_llseek(self) -> None:
        """32-bit arches should define llseek for >2GB support."""
        for name, arch in ARCHITECTURES.items():
            if arch.is_32bit and arch.gcc_define in SYSCALL_NUMBERS.get("linux", {}):
                nrs = SYSCALL_NUMBERS["linux"][arch.gcc_define]
                assert "llseek" in nrs, (
                    f"32-bit arch '{name}' ({arch.gcc_define}) missing llseek"
                )

    def test_openat_only_arches_have_openat_in_table(self) -> None:
        """Arches with openat_only trait must have openat in syscall table."""
        for name, arch in ARCHITECTURES.items():
            if arch.openat_only and arch.gcc_define in SYSCALL_NUMBERS.get("linux", {}):
                nrs = SYSCALL_NUMBERS["linux"][arch.gcc_define]
                assert "openat" in nrs, (
                    f"Arch '{name}' is openat_only but has no 'openat' in syscall table"
                )
                assert "open" not in nrs, (
                    f"Arch '{name}' is openat_only but still has 'open' "
                    "in syscall table"
                )

    def test_mmap_flags_all_have_defaults(self) -> None:
        """Every mmap flag must have a _default_ value."""
        for flag, values in MMAP_FLAGS.items():
            assert "_default_" in values, f"MMAP_FLAGS['{flag}'] has no _default_"

    def test_every_syscall_number_has_a_def(self) -> None:
        """Every syscall in SYSCALL_NUMBERS must have a SyscallDef entry."""
        all_names = all_syscall_names()
        # Some names are related (openat → open, llseek → lseek).
        related = {"openat": "open", "llseek": "lseek"}
        for name in all_names:
            canonical = related.get(name, name)
            assert canonical in SYSCALL_DEFS, (
                f"Syscall '{name}' in SYSCALL_NUMBERS has no SyscallDef "
                f"(expected '{canonical}' in SYSCALL_DEFS)"
            )

    def test_per_syscall_headers_exist(self) -> None:
        """Every SyscallDef should have a generated sys/{name}.h."""
        for name in SYSCALL_DEFS:
            path = PROJECT_ROOT / f"src/include/picblobs/sys/{name}.h"
            assert path.exists(), (
                f"Missing sys/{name}.h — run: python tools/generate.py"
            )

    def test_per_syscall_headers_have_os_guard(self) -> None:
        """Every generated sys/{name}.h must check PICBLOBS_OS_*."""
        for name in SYSCALL_DEFS:
            content = _read_file(f"src/include/picblobs/sys/{name}.h")
            assert "PICBLOBS_OS_" in content, (
                f"sys/{name}.h missing OS guard (PICBLOBS_OS_*)"
            )


# ============================================================
# Linker ↔ Extractor contract
# ============================================================


class TestLinkerExtractorContract:
    """Verify linker script symbols match what the extractor reads."""

    def test_linker_script_defines_all_symbols(self) -> None:
        content = _read_file("src/linker/blob.ld")
        for role, symbol in LINKER_SYMBOLS.items():
            assert symbol in content, (
                f"Linker script missing symbol '{symbol}' (role: {role})"
            )

    def test_extractor_reads_correct_symbols(self) -> None:
        content = _read_file("python/picblobs/_extractor.py")
        for role in ("blob_start", "blob_end", "config_start"):
            symbol = LINKER_SYMBOLS[role]
            assert symbol in content, (
                f"Extractor doesn't reference symbol '{symbol}' (role: {role})"
            )

    def test_reloc_h_uses_got_symbols(self) -> None:
        content = _read_file("src/include/picblobs/reloc.h")
        assert LINKER_SYMBOLS["got_start"] in content
        assert LINKER_SYMBOLS["got_end"] in content


# ============================================================
# Test runner ↔ Registry sync
# ============================================================


class TestRunnerSync:
    """Verify test runners cover all registered architectures."""

    def test_linux_runner_has_all_gcc_defines(self) -> None:
        content = _read_file("tests/runners/linux/runner.c")
        for define in gcc_defines():
            assert define in content, (
                f"tests/runners/linux/runner.c missing _start for {define}"
            )

    def test_runner_types_match_os(self) -> None:
        for os_name, os_def in OPERATING_SYSTEMS.items():
            runner_dir = PROJECT_ROOT / "tests" / "runners" / os_def.runner_type
            assert runner_dir.exists(), f"Missing runner dir for '{os_name}'"


# ============================================================
# Naming consistency
# ============================================================


class TestNamingConsistency:
    def test_arch_names_valid(self) -> None:
        for name in ARCHITECTURES:
            assert re.match(r"^[a-z0-9_]+$", name), f"Bad arch name: '{name}'"

    def test_os_names_valid(self) -> None:
        for name in OPERATING_SYSTEMS:
            assert re.match(r"^[a-z]+$", name), f"Bad OS name: '{name}'"


# ============================================================
# MODULE.bazel ↔ Registry sync
# ============================================================


class TestModuleBazelSync:
    """Verify MODULE.bazel toolchain definitions match the registry."""

    def test_all_bootlin_toolchains_registered(self) -> None:
        module_content = _read_file("MODULE.bazel")
        assert "picblobs_toolchains" in module_content

        content = _read_file("toolchains/repositories.bzl")
        # Every unique bootlin_arch should have a generated repository entry.
        seen = set()
        for arch in ARCHITECTURES.values():
            if arch.bootlin_arch not in seen:
                seen.add(arch.bootlin_arch)
                assert arch.bootlin_sha256, (
                    f"Registry missing bootlin_sha256 for '{arch.name}'"
                )
                assert f'arch = "{arch.bootlin_arch}"' in content, (
                    "toolchains/repositories.bzl missing toolchain for "
                    f"bootlin_arch='{arch.bootlin_arch}'"
                )
                assert f'triple = "{arch.gcc_triple}"' in content, (
                    f"toolchains/repositories.bzl missing triple='{arch.gcc_triple}'"
                )
                assert f'sha256 = "{arch.bootlin_sha256}"' in content, (
                    "toolchains/repositories.bzl missing "
                    f"sha256='{arch.bootlin_sha256}'"
                )
