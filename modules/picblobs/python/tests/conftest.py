"""pytest configuration and shared fixtures for picblobs tests."""

from __future__ import annotations

import ctypes
import os
import platform
import signal
import socket
from pathlib import Path

import pytest

from ._test_env import PROJECT_ROOT, prepend_source_paths

prepend_source_paths()

from payload_defs import all_payload_combos

from tools.registry import ARCHITECTURES, OPERATING_SYSTEMS, all_platforms

REPO_ROOT = PROJECT_ROOT.parents[1]
BAZEL_BIN = REPO_ROOT / "bazel-bin" / "modules" / "picblobs"
_PACKAGE_RUNNERS = PROJECT_ROOT / "python_cli" / "picblobs_cli" / "_runners"
_BAZEL_RUNNER_PATHS = (
    BAZEL_BIN / "tests" / "runners" / "linux" / "runner.bin",
    BAZEL_BIN / "tests" / "runners" / "linux" / "runner",
)


def _runners_exist() -> bool:
    if any(_PACKAGE_RUNNERS.rglob("runner")):
        return True
    return any(p.exists() for p in _BAZEL_RUNNER_PATHS)


def _blobs_exist() -> bool:
    package_root = PROJECT_ROOT / "python" / "picblobs"
    manifest = package_root / "manifest.json"
    release_blobs = package_root / "blobs"

    return (
        manifest.exists()
        and release_blobs.exists()
        and any(release_blobs.glob("*.bin"))
    )


def _has_qemu() -> bool:
    """True if a qemu-user interpreter for the host arch is on PATH.

    The requires_qemu marker gates tests that need an actual QEMU binary --
    notably find_qemu() discovery -- so this checks for the interpreter
    itself, not merely whether blobs can run (a native host executes blobs
    with no QEMU at all, and binfmt_misc handlers route through QEMU without
    a discoverable interpreter). Per-arch runtime coverage is gated separately
    by can_run() in _apply_capability_skips, which credits native and
    binfmt_misc execution too.
    """
    from picblobs.runner import find_qemu

    try:
        find_qemu(platform.machine())
    except (FileNotFoundError, ValueError):
        return False
    return True


def _can_bind_localhost() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
    except OSError:
        return False
    else:
        return True


def _has_any_cross_compiler() -> bool:
    try:
        from picblobs._cross_compile import find_gcc
    except ImportError:
        return False
    return any(find_gcc(arch) is not None for arch in ARCHITECTURES)


def _can_ptrace_traceme() -> bool:
    """Return True if this environment permits a basic PTRACE_TRACEME flow."""
    libc = ctypes.CDLL(None, use_errno=True)
    ptrace = getattr(libc, "ptrace", None)
    if ptrace is None:
        return False
    ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_long
    PTRACE_TRACEME = 0
    PTRACE_CONT = 7

    pid = os.fork()
    if pid == 0:
        try:
            ret = ptrace(PTRACE_TRACEME, 0, None, None)
            if ret != 0:
                os._exit(1)
            os.kill(os.getpid(), signal.SIGSTOP)
            os._exit(0)
        except BaseException:
            os._exit(1)

    try:
        child_pid, status = os.waitpid(pid, 0)
        if child_pid != pid or not os.WIFSTOPPED(status):
            return False
        if ptrace(PTRACE_CONT, pid, None, None) != 0:
            return False
        os.waitpid(pid, 0)
    except OSError:
        return False
    else:
        return True


# --- Environment-based filters (set by `picblobs test --os/--arch/--type`) ---


def _env_filter(key: str) -> str:
    return os.environ.get(f"PICBLOBS_TEST_{key.upper()}", "")


# ============================================================
# Registry-driven fixtures for cross-arch parametrization
# ============================================================


def _all_arch_ids() -> list[str]:
    """Return all architecture names from the registry."""
    return list(ARCHITECTURES.keys())


def _all_platform_ids() -> list[tuple[str, str]]:
    """Return all (os, arch) pairs from the registry."""
    return all_platforms()


def _linux_arch_ids() -> list[str]:
    """Return Linux architecture names from the registry."""
    return OPERATING_SYSTEMS["linux"].architectures


@pytest.fixture(params=_all_arch_ids())
def target_arch(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture: yields each registered architecture name."""
    return request.param


@pytest.fixture(params=_linux_arch_ids())
def linux_arch(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture: yields each Linux architecture name."""
    return request.param


@pytest.fixture(
    params=_all_platform_ids(),
    ids=[f"{os}:{arch}" for os, arch in _all_platform_ids()],
)
def platform_pair(request: pytest.FixtureRequest) -> tuple[str, str]:
    """Parametrized fixture: yields each (os, arch) pair."""
    return request.param


# ============================================================
# Payload test fixtures (TEST-011)
# ============================================================


@pytest.fixture(
    params=all_payload_combos(),
    ids=[f"{bt}:{os}:{arch}" for bt, os, arch in all_payload_combos()],
)
def payload_combo(request: pytest.FixtureRequest) -> tuple[str, str, str]:
    """Parametrized fixture: yields (blob_type, target_os, target_arch)."""
    return request.param


# ============================================================
# Standard fixtures
# ============================================================


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def blob_dir() -> Path:
    """Path to staged .so blob files (populated by ``task stage``)."""
    return PROJECT_ROOT / "python" / "picblobs" / "_blobs"


@pytest.fixture(scope="session")
def runner_dir() -> Path:
    """Path to built test runner binaries."""
    return BAZEL_BIN / "tests" / "runners"


@pytest.fixture(scope="session")
def runners_available() -> bool:
    """True if test runners have been built."""
    return _runners_exist()


@pytest.fixture(scope="session")
def qemu_available() -> bool:
    """True if qemu-x86_64-static is on PATH."""
    return _has_qemu()


@pytest.fixture(scope="session")
def localhost_tcp_available() -> bool:
    """True if tests may bind localhost TCP sockets in this environment."""
    return _can_bind_localhost()


@pytest.fixture(scope="session")
def cross_compile_available() -> bool:
    """True if at least one Bootlin cross-compiler is discoverable."""
    return _has_any_cross_compiler()


# ============================================================
# Markers
# ============================================================


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "requires_runners: test needs compiled C test runners"
    )
    config.addinivalue_line("markers", "requires_qemu: test needs QEMU user-static")
    config.addinivalue_line("markers", "requires_blobs: test needs built .so blobs")
    config.addinivalue_line(
        "markers",
        "requires_local_tcp: test needs permission to bind localhost TCP sockets",
    )
    config.addinivalue_line(
        "markers", "requires_cross_compile: test needs a discoverable cross-compiler"
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Auto-skip tests based on available infrastructure."""
    _apply_capability_skips(items, _capability_state())
    _apply_env_filters(items, _collection_filters())


def _capability_state() -> dict[str, bool]:
    """Return the environment capabilities relevant to pytest skips."""
    return {
        "requires_blobs": _blobs_exist(),
        "requires_runners": _runners_exist(),
        "requires_qemu": _has_qemu(),
        "requires_local_tcp": _can_bind_localhost(),
        "requires_cross_compile": _has_any_cross_compiler(),
        "ptrace": _can_ptrace_traceme(),
    }


def _collection_filters() -> dict[str, str]:
    """Return active env-driven collection filters."""
    return {
        "os": _env_filter("os"),
        "arch": _env_filter("arch"),
        "type": _env_filter("type"),
    }


def _skip_marker_reason(keyword: str) -> str:
    """Return the human-facing skip reason for one capability marker."""
    reasons = {
        "requires_blobs": (
            "Blob assets are not staged. Run: python tools/stage_blobs.py"
        ),
        "requires_runners": (
            "Test runners not built. Run: bazel build "
            "//modules/picblobs/tests/runners/..."
        ),
        "requires_qemu": "No qemu-user interpreter on PATH.",
        "requires_local_tcp": "Local TCP sockets are unavailable in this environment.",
        "requires_cross_compile": "No Bootlin cross-compiler is discoverable.",
    }
    return reasons[keyword]


def _apply_capability_skips(
    items: list[pytest.Item],
    capabilities: dict[str, bool],
) -> None:
    """Skip tests whose declared infrastructure requirements are unavailable."""
    for item in items:
        _skip_for_missing_capabilities(item, capabilities)
        _skip_for_unrunnable_arch(item)
        if not capabilities["ptrace"]:
            _skip_freebsd_without_ptrace(item)


def _skip_for_missing_capabilities(
    item: pytest.Item,
    capabilities: dict[str, bool],
) -> None:
    """Skip an item whose declared capability markers are unavailable."""
    for keyword, available in capabilities.items():
        if keyword == "ptrace":
            continue
        if keyword in item.keywords and not available:
            item.add_marker(pytest.mark.skip(reason=_skip_marker_reason(keyword)))


def _skip_for_unrunnable_arch(item: pytest.Item) -> None:
    """Skip a runtime test for an arch this host cannot execute at all.

    Per-arch precision: a target this host can neither run natively, via
    binfmt_misc, nor under qemu-user is skipped (not failed). The coarse
    requires_qemu gate only proves the host arch runs.
    """
    from picblobs.runner import can_run

    _, _, param_arch = _item_filter_params(item)
    if "requires_qemu" in item.keywords and param_arch and not can_run(param_arch):
        item.add_marker(
            pytest.mark.skip(reason=f"No way to execute {param_arch} blobs here.")
        )


def _skip_freebsd_without_ptrace(item: pytest.Item) -> None:
    """Skip FreeBSD runtime tests when this environment lacks ptrace."""
    _, param_os, _ = _item_filter_params(item)
    if param_os == "freebsd" and "requires_qemu" in item.keywords:
        item.add_marker(
            pytest.mark.skip(
                reason=(
                    "FreeBSD runtime tests require ptrace, which is "
                    "unavailable in this environment."
                )
            )
        )


def _item_filter_params(item: pytest.Item) -> tuple[str, str, str]:
    """Extract (type, os, arch) parameters from a collected item."""
    params = getattr(item, "callspec", None)
    if not params:
        return "", "", ""
    p = params.params
    param_os = p.get("target_os", "")
    param_arch = p.get("target_arch", "")
    param_type = p.get("blob_type", "")
    combo = p.get("payload_combo")
    if combo is not None:
        param_type, param_os, param_arch = combo
    return param_type, param_os, param_arch


def _apply_env_filters(items: list[pytest.Item], filters: dict[str, str]) -> None:
    """Skip parametrized items that do not match env-driven filters."""
    if not any(filters.values()):
        return
    for item in items:
        param_type, param_os, param_arch = _item_filter_params(item)
        for key, actual in (
            ("os", param_os),
            ("arch", param_arch),
            ("type", param_type),
        ):
            expected = filters[key]
            if expected and actual and actual != expected:
                item.add_marker(pytest.mark.skip(reason=f"Filtered: {key}!={expected}"))
