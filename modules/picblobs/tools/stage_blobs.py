#!/usr/bin/env python3
"""Stage built .so blobs, test runners, and verifier fixtures.

Builds blob targets and non-Linux runner targets for all platform configs
via Bazel, then copies outputs into:
  python/picblobs/_blobs/{os}/{arch}/{name}.so
  python_cli/picblobs_cli/_runners/{os}/{arch}/runner
  python_cli/picblobs_cli/_test_binaries/ul_exec/{os}/{arch}/hello_et_exec

Usage:
    python tools/stage_blobs.py                       # build + stage all
    python tools/stage_blobs.py --targets hello        # one blob type
    python tools/stage_blobs.py --configs linux:x86_64 # one platform
    python tools/stage_blobs.py --no-runners           # blobs only
"""

from __future__ import annotations

import argparse
import logging
import re
import shutil
import stat
import subprocess
import sys
import sys as _sys
from pathlib import Path

_sys.path.insert(0, str(Path(__file__).resolve().parent))
from registry import BLOB_TYPES, platform_configs

_sys.path.pop(0)

log = logging.getLogger("picblobs.stage")

# Derived from the canonical registry (tools/registry.py).
PLATFORM_CONFIGS = platform_configs()

# Bazel label templates.
BLOB_LABEL_TEMPLATE = "//modules/picblobs/src/payload:{name}"
RUNNER_LABEL = "//modules/picblobs/tests/runners/{runner_type}:runner"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PROJECT_ROOT.parents[1]
PYTHON_ROOT = PROJECT_ROOT / "python"
BLOB_DIR = PROJECT_ROOT / "python" / "picblobs" / "_blobs"
RUNNER_DIR = PROJECT_ROOT / "python_cli" / "picblobs_cli" / "_runners"
TEST_BINARY_DIR = PROJECT_ROOT / "python_cli" / "picblobs_cli" / "_test_binaries"
DEBUG_BLOB_DIR = PROJECT_ROOT / "debug"
UL_EXEC_TEST_BINARY_NAME = "hello_et_exec"

if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def discover_blob_targets() -> list[str]:
    """Discover blob target names from src/payload/BUILD.bazel."""
    build_file = PROJECT_ROOT / "src" / "payload" / "BUILD.bazel"
    if not build_file.exists():
        return ["hello"]
    targets = [
        match.group(1)
        for match in re.finditer(
            r'pic_blob\(\s*name\s*=\s*"([^"]+)"', build_file.read_text()
        )
    ]
    return targets or ["hello"]


def bazel_build(configs: list[str], labels: list[str]) -> bool:
    """Run bazel build for configs+labels. Returns True on success."""
    cmd = ["bazel", "build"] + [f"--config={c}" for c in configs] + labels
    result = subprocess.run(cmd, capture_output=True, check=False, cwd=REPO_ROOT)
    if result.returncode != 0:
        for line in result.stderr.decode().splitlines():
            if "error" in line.lower():
                log.error("    %s", line.strip())
        return False
    return True


def stage_file(src: Path, dest: Path, executable: bool = False) -> bool:
    """Copy a file, handling read-only destinations."""
    if not src.exists():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.chmod(stat.S_IWUSR | stat.S_IRUSR)
        dest.unlink()
    shutil.copy2(src, dest)
    if executable:
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


def stage_bytes(data: bytes, dest: Path, executable: bool = False) -> None:
    """Write a generated artifact, handling read-only destinations."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.chmod(stat.S_IWUSR | stat.S_IRUSR)
        dest.unlink()
    dest.write_bytes(data)
    if executable:
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# Substrings from `file -b` output for architecture validation.
_ELF_MACHINES = {
    "x86_64": "x86-64",
    "i686": "Intel",  # matches "Intel 80386" and "Intel i386"
    "aarch64": "aarch64",
    "armv5_arm": "ARM",
    "armv5_thumb": "ARM",
    "armv7_thumb": "ARM",
    "s390x": "S/390",
    "mipsel32": "MIPS",
    "mipsbe32": "MIPS",
    "sparcv8": "SPARC",
    "powerpc": "PowerPC",
    "ppc64le": "64-bit PowerPC",
    "riscv64": "RISC-V",
}


def verify_elf_arch(so_path: Path, expected_arch: str) -> bool:
    """Verify a staged .so has the expected ELF machine type.

    Catches the bug where bazel-bin symlink points to wrong-platform output.
    """
    expected = _ELF_MACHINES.get(expected_arch)
    if expected is None:
        return True  # unknown arch, skip check
    try:
        result = subprocess.run(
            ["file", "-b", str(so_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return True  # can't check, don't block
    else:
        return expected in result.stdout


def find_bazel_output(label: str, extension: str) -> Path:
    """Convert a Bazel label to its output path in bazel-bin/."""
    pkg, name = label.lstrip("/").split(":")
    return REPO_ROOT / "bazel-bin" / pkg / f"{name}{extension}"


def _is_registry_platform(blob_name: str, os_name: str, arch_name: str) -> bool | None:
    """Return registry platform support, or None for unknown blob targets."""
    bt = BLOB_TYPES.get(blob_name)
    if bt is None:
        return None
    return arch_name in bt.platforms.get(os_name, [])


def _os_compatible_targets(
    targets: list[str],
    os_name: str,
    arch_name: str,
) -> list[str]:
    """Filter blob targets to those compatible with one OS/architecture."""
    os_targets = []
    for blob_name in targets:
        supported = _is_registry_platform(blob_name, os_name, arch_name)
        if supported is not None:
            if supported:
                os_targets.append(blob_name)
            continue

        parts = blob_name.rsplit("_", 1)
        if len(parts) == 2 and parts[1] in ("linux", "freebsd", "windows"):
            if parts[1] != os_name:
                continue
        elif os_name == "windows":
            continue
        os_targets.append(blob_name)
    return os_targets


def _blob_labels(targets: list[str]) -> list[str]:
    """Return Bazel labels for blob targets."""
    return [BLOB_LABEL_TEMPLATE.format(name=blob_name) for blob_name in targets]


def _runner_build_config(
    os_name: str,
    arch_name: str,
    bazel_configs: list[str],
) -> list[str]:
    """Return the Bazel configs used to build the test runner."""
    if os_name in ("windows", "freebsd"):
        return [f"linux_{arch_name}"]
    return list(bazel_configs)


def _staged_blob_name(blob_name: str) -> str:
    """Return the staged filename stem for a registry blob."""
    bt = BLOB_TYPES.get(blob_name)
    return bt.staged_name if bt and bt.staged_name else blob_name


def _stage_blob_outputs(
    os_targets: list[str],
    os_name: str,
    arch_name: str,
    output_dir: Path,
    blob_labels_built: bool,
) -> tuple[int, int]:
    """Stage built blob .so files for one platform."""
    total = 0
    passed = 0
    for blob_name in os_targets:
        total += 1
        if not blob_labels_built:
            continue
        label = BLOB_LABEL_TEMPLATE.format(name=blob_name)
        src = find_bazel_output(label, ".so")
        staged_name = _staged_blob_name(blob_name)
        dest = output_dir / os_name / arch_name / f"{staged_name}.so"
        tag = f"    {staged_name}.so -> {os_name}/{arch_name}"
        if stage_file(src, dest):
            if not verify_elf_arch(dest, arch_name):
                log.error("%-50s ARCH MISMATCH (expected %s)", tag, arch_name)
            else:
                log.info("%-50s OK", tag)
                passed += 1
        else:
            log.error("%-50s NOT FOUND: %s", tag, src)
    return passed, total


def _stage_runner_output(
    runner_label: str,
    runner_type: str,
    arch_name: str,
) -> bool:
    """Stage one built runner binary."""
    src = find_bazel_output(runner_label, ".bin")
    dest = RUNNER_DIR / runner_type / arch_name / "runner"
    tag = f"    runner -> {runner_type}/{arch_name}"
    if stage_file(src, dest, executable=True):
        log.info("%-50s OK", tag)
        return True
    log.error("%-50s NOT FOUND: %s", tag, src)
    return False


def _stage_ul_exec_test_binary(
    os_targets: list[str],
    os_name: str,
    arch_name: str,
    no_runners: bool,
    debug: bool,
) -> tuple[int, int]:
    """Build and stage the verifier ELF consumed by ``ul_exec`` tests."""
    if debug or no_runners or os_name != "linux" or "ul_exec" not in os_targets:
        return 0, 0

    from picblobs._cross_compile import compile_hello_et_exec

    tag = f"    {UL_EXEC_TEST_BINARY_NAME} -> ul_exec/{os_name}/{arch_name}"
    elf_data = compile_hello_et_exec(arch_name)
    if elf_data is None:
        log.error("%-50s BUILD FAIL", tag)
        return 0, 1

    dest = TEST_BINARY_DIR / "ul_exec" / os_name / arch_name / UL_EXEC_TEST_BINARY_NAME
    stage_bytes(elf_data, dest, executable=True)
    log.info("%-50s OK", tag)
    return 1, 1


def _platform_config(config_key: str) -> tuple[str, str, str, str] | None:
    """Return (bazel_config, runner_type, os_name, arch_name) for a key."""
    if config_key not in PLATFORM_CONFIGS:
        log.error("Unknown config: %s", config_key)
        return None
    bazel_config, runner_type = PLATFORM_CONFIGS[config_key]
    os_name, arch_name = config_key.split(":")
    return bazel_config, runner_type, os_name, arch_name


def _build_blob_set(
    config_key: str,
    mode: str,
    bazel_configs: list[str],
    blob_labels: list[str],
) -> bool:
    """Build one platform's blob outputs."""
    if not blob_labels:
        return False
    log.info("  [%s] (%s) building blobs... ", config_key, mode)
    if not bazel_build(bazel_configs, blob_labels):
        log.error("  [%s] BLOB BUILD FAIL", config_key)
        return False
    log.info("  [%s] blobs OK", config_key)
    return True


def _build_runner(
    config_key: str,
    mode: str,
    runner_label: str,
    runner_configs: list[str],
) -> bool:
    """Build one platform's runner output."""
    if not runner_label:
        return False
    log.info("  [%s] (%s) building runner... ", config_key, mode)
    if not bazel_build(runner_configs, [runner_label]):
        log.error("  [%s] RUNNER BUILD FAIL", config_key)
        return False
    log.info("  [%s] runner OK", config_key)
    return True


def _runner_label_for(
    runner_type: str,
    os_name: str,
    no_runners: bool,
    debug: bool,
) -> str:
    """Return the runner label to build for a platform, or empty string."""
    if no_runners or debug or os_name == "linux":
        return ""
    return RUNNER_LABEL.format(runner_type=runner_type)


def _stage_runner_if_built(
    config_key: str,
    mode: str,
    runner_label: str,
    runner_type: str,
    arch_name: str,
    runner_configs: list[str],
) -> tuple[int, int]:
    """Build and stage one runner if requested; return (passed, total)."""
    if not _build_runner(config_key, mode, runner_label, runner_configs):
        return 0, 0
    if _stage_runner_output(runner_label, runner_type, arch_name):
        return 1, 1
    return 0, 1


def _stage_platform(
    config_key: str,
    targets: list[str],
    output_dir: Path,
    no_runners: bool,
    debug: bool,
) -> tuple[int, int]:
    """Build and stage blobs/runners for one platform config."""
    platform = _platform_config(config_key)
    if platform is None:
        return 0, 0
    bazel_config, runner_type, os_name, arch_name = platform
    bazel_configs = [bazel_config]
    if debug:
        bazel_configs.append("debug")

    os_targets = _os_compatible_targets(targets, os_name, arch_name)
    blob_labels = _blob_labels(os_targets)
    runner_label = _runner_label_for(runner_type, os_name, no_runners, debug)
    if not blob_labels and not runner_label:
        return 0, 0

    mode = "debug" if debug else "release"
    built_blobs = _build_blob_set(config_key, mode, bazel_configs, blob_labels)
    passed, total = _stage_blob_outputs(
        os_targets,
        os_name,
        arch_name,
        output_dir,
        built_blobs,
    )

    runner_passed, runner_total = _stage_runner_if_built(
        config_key,
        mode,
        runner_label,
        runner_type,
        arch_name,
        _runner_build_config(os_name, arch_name, bazel_configs),
    )
    passed += runner_passed
    total += runner_total

    test_passed, test_total = _stage_ul_exec_test_binary(
        os_targets,
        os_name,
        arch_name,
        no_runners,
        debug,
    )
    passed += test_passed
    total += test_total
    return passed, total


def build_and_stage(
    targets: list[str],
    configs: list[str],
    no_runners: bool = False,
    debug: bool = False,
) -> tuple[int, int]:
    """Build and stage blobs+runners. Returns (passed, total).

    If debug=True, builds with _debug configs and stages to debug/ instead
    of the Python package tree. Runners are not built in debug mode.
    """
    total = 0
    passed = 0
    output_dir = DEBUG_BLOB_DIR if debug else BLOB_DIR

    for config_key in configs:
        cfg_passed, cfg_total = _stage_platform(
            config_key,
            targets,
            output_dir,
            no_runners,
            debug,
        )
        passed += cfg_passed
        total += cfg_total

    return passed, total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage blobs and runners into package tree"
    )
    parser.add_argument(
        "--targets",
        nargs="*",
        default=None,
        help="Blob target names (default: auto-discovered from BUILD.bazel)",
    )
    _default_configs = [
        k for k in PLATFORM_CONFIGS if k.startswith(("linux:", "windows:", "freebsd:"))
    ]
    parser.add_argument(
        "--configs",
        nargs="*",
        default=_default_configs,
        help="Platform configs as os:arch (default: linux + windows)",
    )
    parser.add_argument(
        "--no-runners",
        action="store_true",
        help="Skip building/staging test runners",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Build debug variants (with -g and PIC_LOG) staged to debug/",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

    if args.targets is None:
        args.targets = discover_blob_targets()

    passed, total = build_and_stage(
        args.targets, args.configs, args.no_runners, args.debug
    )

    log.info("%d/%d staged", passed, total)
    if passed < total:
        return 1

    # Auto-regenerate pre-extracted release blobs so get_blob() sees
    # the freshly-staged .so files immediately. Without this step,
    # get_blob() reads stale .bin files from blobs/ and changes appear
    # to have no effect — a common source of debugging confusion.
    if not args.debug and passed > 0:
        log.info("  extracting release blobs...")
        from extract_release import extract_release

        so_dir = BLOB_DIR
        out_dir = PROJECT_ROOT / "python" / "picblobs"
        extracted, errors = extract_release(so_dir, out_dir)
        log.info("  %d blobs extracted (%d errors)", extracted, errors)
        if errors:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
