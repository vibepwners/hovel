"""Blob execution orchestration.

Manages the lifecycle of running a PIC blob:
  1. Prepare a pre-extracted flat blob (code + config)
  2. For Linux, wrap it as a temporary ELF and run it directly/QEMU
  3. For non-Linux, invoke the appropriate C test runner under QEMU
  4. Capture and return stdout, stderr, exit code
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import functools
import logging
import platform
import selectors
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

from picblobs._elf import wrap_elf
from picblobs._qemu import QEMU_BINARIES

if TYPE_CHECKING:
    from picblobs._extractor import BlobData

log = logging.getLogger(__name__)

# Fallback: Bazel build tree.
_BAZEL_RUNNER_SEARCH = [
    Path("bazel-bin/tests/runners"),
    Path("../bazel-bin/tests/runners"),
    Path("bazel-bin/modules/picblobs/tests/runners"),
    Path("../bazel-bin/modules/picblobs/tests/runners"),
    Path("../../bazel-bin/modules/picblobs/tests/runners"),
    Path("../../../bazel-bin/modules/picblobs/tests/runners"),
]


def _picblobs_cli_runner_dir() -> Path | None:
    """Return the on-disk path to the picblobs_cli bundled runners, or None.

    Companion package ``picblobs-cli`` ships the cross-compiled test
    runners under ``picblobs_cli/_runners``. When installed alongside
    picblobs it provides the primary source of runner binaries; if the
    package isn't importable we fall back to the Bazel build tree.
    """
    try:
        import importlib
        import importlib.resources

        mod = importlib.import_module("picblobs_cli")
    except ImportError:
        return None
    try:
        return Path(str(importlib.resources.files(mod) / "_runners"))
    except (AttributeError, ModuleNotFoundError, TypeError):
        return None


@dataclasses.dataclass(frozen=True)
class RunResult:
    """Result of running a blob under QEMU."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    duration_s: float
    command: list[str]
    blob_file: str = ""


@dataclasses.dataclass(frozen=True)
class PairRunResult:
    """Result of running a server/client blob pair."""

    server_stdout: bytes
    server_stderr: bytes
    server_exit: int
    client_stdout: bytes
    client_stderr: bytes
    client_exit: int


def find_qemu(arch: str) -> Path:
    """Locate a qemu-user interpreter for an architecture on PATH.

    Prefers the ``-static`` build (``qemu-aarch64-static``) but also accepts
    the dynamically-linked ``qemu-aarch64`` name shipped by the ``qemu-user``
    package, since newer distros (e.g. Ubuntu 26.04) drop the standalone
    static binaries.

    Raises:
        ValueError: If *arch* is unknown.
        FileNotFoundError: If no qemu-user interpreter is found on PATH.
    """
    name = QEMU_BINARIES.get(arch)
    if name is None:
        raise ValueError(f"Unknown architecture: {arch}")

    for candidate in _qemu_binary_candidates(name):
        path = shutil.which(candidate)
        if path is not None:
            return Path(path)
    looked = ", ".join(_qemu_binary_candidates(name))
    raise FileNotFoundError(
        f"No qemu-user interpreter for {arch} on PATH (looked for {looked}). "
        f"Install qemu-user-static, or register binfmt_misc handlers via "
        f"qemu-user-binfmt so the binary can be exec'd directly."
    )


def _qemu_binary_candidates(name: str) -> list[str]:
    """Return qemu binary names to try, static name first.

    ``qemu-arm-static`` -> ``[qemu-arm-static, qemu-arm]``.
    """
    if name.endswith("-static"):
        return [name, name.removesuffix("-static")]
    return [name]


# binfmt_misc lets the kernel route a foreign-arch binary through QEMU on
# exec (the qemu-user-binfmt package registers these handlers). When present
# we can launch blobs directly with no explicit interpreter prefix.
_BINFMT_MISC_DIR = Path("/proc/sys/fs/binfmt_misc")

# Per-arch launcher prefixes discovered this session. Empty tuple = the
# binary runs directly (host-native or via a binfmt_misc handler); a
# non-empty tuple is the qemu-user interpreter to prepend. The runtime
# fallback in _retry_under_qemu writes here when a direct exec turns out to
# need QEMU after all.
_LAUNCHER_CACHE: dict[str, tuple[str, ...]] = {}


def _qemu_binfmt_name(arch: str) -> str | None:
    """Map *arch* to its qemu-user binfmt_misc entry name (e.g. ``qemu-arm``).

    The binfmt entry is named after the interpreter: ``qemu-arm-static`` ->
    ``qemu-arm``.
    """
    name = QEMU_BINARIES.get(arch)
    if not name:
        return None
    return name.removesuffix("-static")


@functools.cache
def _binfmt_handler_enabled(arch: str) -> bool:
    """Return True if binfmt_misc has an *enabled* qemu-user handler for *arch*.

    Reads ``/proc/sys/fs/binfmt_misc/qemu-<arch>``; the first line is
    ``enabled`` or ``disabled``. Any read error (not Linux, not mounted,
    no entry) means no handler.
    """
    name = _qemu_binfmt_name(arch)
    if not name:
        return False
    try:
        first = (_BINFMT_MISC_DIR / name).read_text().splitlines()[0].strip()
    except (OSError, IndexError):
        return False
    return first == "enabled"


def qemu_launcher(arch: str) -> list[str]:
    """Return the command prefix needed to launch an *arch* binary.

    An empty list means the binary can be exec'd directly — it targets the
    host architecture, or a binfmt_misc handler (qemu-user-binfmt) routes it
    through QEMU automatically. Otherwise the result is a single-element list
    holding the path to a qemu-user interpreter to prepend.

    Resolution mirrors "just run the binary, fall back to QEMU":
      1. host-native arch        -> direct exec
      2. binfmt_misc handler     -> direct exec
      3. qemu-user on PATH       -> explicit launcher
      4. none of the above       -> direct exec is still attempted; an
         exec-format failure then triggers the fallback in _retry_under_qemu.
    """
    if _is_native_arch(arch) or _binfmt_handler_enabled(arch):
        return []
    if arch not in _LAUNCHER_CACHE:
        try:
            _LAUNCHER_CACHE[arch] = (str(find_qemu(arch)),)
        except (FileNotFoundError, ValueError):
            _LAUNCHER_CACHE[arch] = ()
    return list(_LAUNCHER_CACHE[arch])


def can_run(arch: str) -> bool:
    """Return True if blobs for *arch* can be executed on this host.

    True when the arch is host-native, a binfmt_misc qemu-user handler is
    registered, or a qemu-user interpreter is on PATH.
    """
    if _is_native_arch(arch) or _binfmt_handler_enabled(arch):
        return True
    try:
        find_qemu(arch)
    except (FileNotFoundError, ValueError):
        return False
    return True


def _find_embedded_runner(runner_type: str, arch: str) -> Path | None:
    """Return a bundled picblobs-cli runner if one is installed."""
    cli_dir = _picblobs_cli_runner_dir()
    if not cli_dir or not arch:
        return None
    embedded = cli_dir / runner_type / arch / "runner"
    if embedded.exists():
        return embedded
    return None


def _runner_candidates(base: Path, runner_type: str, arch: str) -> list[Path]:
    """Return candidate runner paths under one search root."""
    candidates: list[Path] = []
    if arch:
        candidates.extend(
            [
                base / runner_type / arch / "runner",
                base / runner_type / arch / "runner.bin",
            ]
        )
    candidates.extend(
        [
            base / runner_type / "runner.bin",
            base / runner_type / "runner",
        ]
    )
    return candidates


def _find_runner_in_paths(
    runner_type: str,
    arch: str,
    search_paths: list[Path],
) -> Path | None:
    """Return the first runner found in the supplied search roots."""
    for base in search_paths:
        for runner in _runner_candidates(base, runner_type, arch):
            if runner.exists():
                return runner
    return None


def find_runner(
    runner_type: str,
    arch: str = "",
    search_paths: list[Path] | None = None,
) -> Path:
    """Locate a compiled C test runner binary.

    Search order:
      1. ``picblobs-cli`` package: ``picblobs_cli/_runners/{runner_type}/{arch}/runner``
      2. Bazel build tree: ``bazel-bin/tests/runners/{runner_type}/{arch}/runner[.bin]``
      3. Caller-supplied ``search_paths``

    Args:
        runner_type: One of "linux", "freebsd", "windows".
        arch: Target architecture (e.g., "x86_64", "aarch64").
        search_paths: Override search directories.

    Raises:
        FileNotFoundError: If runner binary is not found. Non-Linux errors
            mention ``picblobs-cli`` so installation guidance is visible.
    """
    if runner_type == "linux":
        raise FileNotFoundError(
            "Linux test runner not found: Linux blobs run via direct ELF "
            "wrapping now. Use picblobs.wrap_elf() or run_blob(); pass "
            "runner_path explicitly if you need a custom legacy runner."
        )

    embedded = _find_embedded_runner(runner_type, arch)
    if embedded is not None:
        return embedded

    runner = _find_runner_in_paths(
        runner_type, arch, search_paths or _BAZEL_RUNNER_SEARCH
    )
    if runner is not None:
        return runner

    raise FileNotFoundError(
        f"Test runner not found for {runner_type}/{arch}. "
        f"Install picblobs-cli (pip install picblobs-cli) or run "
        f"tools/stage_blobs.py from a source checkout."
    )


def prepare_blob(
    blob: BlobData,
    config: bytes = b"",
    output_dir: Path | None = None,
) -> Path:
    """Write blob code + config to a temp file.

    Args:
        blob: Extracted blob data.
        config: Serialized config struct to append at config_offset.
        output_dir: Directory for the temp file. Uses system temp if None.

    Returns:
        Path to the prepared blob binary file.
    """
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="picblobs_"))

    output_dir.mkdir(parents=True, exist_ok=True)
    blob_file = output_dir / _blob_filename(blob)
    blob_file.write_bytes(_blob_bytes(blob, config))
    return blob_file


def prepare_linux_elf(
    blob: BlobData,
    config: bytes = b"",
    output_dir: Path | None = None,
) -> Path:
    """Write blob code + config as a minimal executable Linux ELF."""
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="picblobs_"))

    output_dir.mkdir(parents=True, exist_ok=True)
    elf_file = output_dir / _linux_elf_filename(blob)
    elf_file.write_bytes(
        wrap_elf(
            _blob_bytes(blob, config),
            blob.target_os,
            blob.target_arch,
            entry_offset=blob.entry_offset,
        )
    )
    elf_file.chmod(elf_file.stat().st_mode | 0o700)
    return elf_file


def _blob_bytes(blob: BlobData, config: bytes = b"") -> bytes:
    """Return finalized flat blob bytes with config patched in."""
    data = bytearray(blob.code)
    if config:
        if blob.config_offset > len(data):
            data.extend(b"\x00" * (blob.config_offset - len(data)))
        data[blob.config_offset : blob.config_offset + len(config)] = config
    return bytes(data)


def _blob_filename(blob: BlobData) -> str:
    """Return the standard on-disk filename for a prepared blob."""
    return f"{blob.blob_type}_{blob.target_os}_{blob.target_arch}.bin"


def _linux_elf_filename(blob: BlobData) -> str:
    """Return the standard filename for a Linux ELF-wrapped blob."""
    return f"{blob.blob_type}_{blob.target_os}_{blob.target_arch}.elf"


# Architectures whose PIC blobs write to the GOT at runtime.
# QEMU's self-modifying-code detection for these targets crashes under
# Rosetta 2 (Apple Silicon Docker Desktop) because the GOT lives on the
# same page as executable code.
_QEMU_MIPS_ARCHES: frozenset[str] = frozenset({"mipsel32", "mipsbe32"})


@functools.cache
def is_rosetta() -> bool:
    """Detect Rosetta 2 x86_64 emulation (e.g. Docker Desktop on Apple Silicon).

    Under Rosetta, /proc/cpuinfo reports ``vendor_id : VirtualApple``,
    whereas real x86_64 hardware reports GenuineIntel or AuthenticAMD.
    """
    if platform.machine() != "x86_64":
        return False
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
    except (FileNotFoundError, OSError):
        return False
    return "VirtualApple" in cpuinfo


def is_arch_skip_rosetta(arch: str) -> bool:
    """Return True if *arch* should be skipped under Rosetta.

    QEMU MIPS user-static crashes when running PIC blobs that perform GOT
    self-relocation on the same page as executable code.  This is a known
    QEMU/Rosetta incompatibility — the blobs work on native x86_64 hosts.
    """
    return arch in _QEMU_MIPS_ARCHES and is_rosetta()


def _is_native_arch(arch: str) -> bool:
    """Check if the given blob architecture can run natively on this host."""
    host = platform.machine()
    # Map our arch names to platform.machine() values.
    # Only 64-bit arches get native execution; 32-bit compat (e.g., i686
    # on x86_64) requires the runner to be compiled for that arch which
    # still needs the cross-compiled runner binary, so use QEMU.
    native_map: dict[str, str] = {
        "x86_64": "x86_64",
        "aarch64": "aarch64",
    }
    return native_map.get(arch, "") == host


def _build_command(
    runner_path: Path,
    blob_file: Path,
    arch: str,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build the QEMU + runner command line."""
    args = [str(blob_file), *(extra_args or [])]
    return [*qemu_launcher(arch), str(runner_path), *args]


def build_linux_elf_command(
    elf_file: Path,
    arch: str,
) -> list[str]:
    """Build the native/QEMU command line for a Linux ELF-wrapped blob."""
    return [*qemu_launcher(arch), str(elf_file)]


def build_blob_command(
    blob: BlobData,
    runner_path: Path,
    blob_file: Path,
    runner_type: str = "",
) -> list[str]:
    """Build the full execution command for a prepared blob file.

    This centralizes runner-specific command shaping, including the
    FreeBSD runner's optional ``text_end`` bound used to keep syscall
    patching scoped to executable code.
    """
    if not runner_type:
        runner_type = blob.target_os

    extra: list[str] = []
    if runner_type == "freebsd":
        t_end = _text_end(blob)
        if t_end > 0:
            extra = [f"{t_end:#x}"]

    return _build_command(runner_path, blob_file, blob.target_arch, extra)


def _text_end(blob: BlobData) -> int:
    """Return the largest offset covered by a .text* section, or 0 if none."""
    end = 0
    for name, (off, size) in blob.sections.items():
        if name.startswith(".text"):
            end = max(end, off + size)
    return end


def _cleanup_blob_file(blob_file: Path) -> None:
    """Remove a temp blob file and its parent directory."""
    blob_file.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        blob_file.parent.rmdir()


def wait_for_stdout_marker(
    proc: subprocess.Popen[bytes],
    marker: bytes,
    timeout: float,
) -> bytes:
    """Read from ``proc.stdout`` until ``marker`` appears or timeout expires.

    Returns all bytes consumed while waiting. Callers should prepend this to
    the eventual ``communicate()`` stdout if they need the full output.
    """
    if proc.stdout is None:
        return b""

    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as sel:
        sel.register(proc.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            events = sel.select(remaining)
            if not events:
                break
            chunk = proc.stdout.read1(4096)
            if not chunk:
                break
            chunks.append(chunk)
            data = b"".join(chunks)
            if marker in data:
                return data
            if proc.poll() is not None:
                break
    return b"".join(chunks)


def reserve_tcp_port(host: str = "127.0.0.1") -> int:
    """Reserve an ephemeral TCP port number for a short-lived local test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _pair_commands(
    server_blob: BlobData,
    client_blob: BlobData,
    runner_path: Path | None,
    runner_type: str,
    server_config: bytes,
    client_config: bytes,
) -> tuple[Path, Path, list[str], list[str]]:
    """Prepare pair temp files and commands."""
    if runner_type == "linux" and runner_path is None:
        server_bin = prepare_linux_elf(server_blob, config=server_config)
        client_bin = prepare_linux_elf(client_blob, config=client_config)
        return (
            server_bin,
            client_bin,
            build_linux_elf_command(server_bin, server_blob.target_arch),
            build_linux_elf_command(client_bin, client_blob.target_arch),
        )

    if runner_path is None:
        runner_path = find_runner(runner_type, server_blob.target_arch)

    server_bin = prepare_blob(server_blob, config=server_config)
    client_bin = prepare_blob(client_blob, config=client_config)
    return (
        server_bin,
        client_bin,
        build_blob_command(server_blob, runner_path, server_bin, runner_type),
        build_blob_command(client_blob, runner_path, client_bin, runner_type),
    )


def _terminate_proc(proc: subprocess.Popen[bytes] | None) -> None:
    """Kill a running subprocess and wait for it to exit."""
    if proc is None or proc.poll() is not None:
        return
    proc.kill()
    proc.wait()


def _pair_run_attempt(
    server_cmd: list[str],
    client_cmd: list[str],
    ready_marker: bytes,
    startup_timeout: float,
    timeout: float,
) -> tuple[PairRunResult | None, str]:
    """Run one server/client attempt and return (result, error_message)."""
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    client_proc: subprocess.Popen[bytes] | None = None
    try:
        server_prefix = wait_for_stdout_marker(
            server_proc, ready_marker, startup_timeout
        )
        if ready_marker not in server_prefix:
            server_proc.kill()
            server_stdout, server_stderr = server_proc.communicate()
            return None, (
                "server did not reach listening state: "
                f"stdout={(server_prefix + server_stdout)!r} "
                f"stderr={server_stderr!r}"
            )

        client_proc = subprocess.Popen(
            client_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            client_stdout, client_stderr = client_proc.communicate(timeout=timeout)
            server_stdout, server_stderr = server_proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_proc(server_proc)
            _terminate_proc(client_proc)
            return None, "pair timed out"
        else:
            result = PairRunResult(
                server_stdout=server_prefix + server_stdout,
                server_stderr=server_stderr,
                server_exit=server_proc.returncode,
                client_stdout=client_stdout,
                client_stderr=client_stderr,
                client_exit=client_proc.returncode,
            )
            if result.server_exit == 0 and result.client_exit == 0:
                return result, ""
            detail = (
                f"server exit={result.server_exit} stderr={result.server_stderr!r}; "
                f"client exit={result.client_exit} stderr={result.client_stderr!r}"
            )
            return None, detail
    except subprocess.TimeoutExpired:
        _terminate_proc(server_proc)
        _terminate_proc(client_proc)
        return None, "pair timed out"
    finally:
        _terminate_proc(server_proc)
        _terminate_proc(client_proc)


def run_blob_pair(
    server_blob: BlobData,
    client_blob: BlobData,
    runner_path: Path | None = None,
    runner_type: str = "",
    *,
    server_config: bytes = b"",
    client_config: bytes = b"",
    timeout: float = 30.0,
    ready_marker: bytes = b"[server] listening\n",
    startup_timeout: float = 5.0,
    attempts: int = 3,
    retry_delay: float = 0.25,
) -> PairRunResult:
    """Run a server/client blob pair with bounded retries for startup flakiness."""
    if not runner_type:
        runner_type = server_blob.target_os

    server_bin, client_bin, server_cmd, client_cmd = _pair_commands(
        server_blob,
        client_blob,
        runner_path,
        runner_type,
        server_config,
        client_config,
    )
    try:
        last_error = "pair did not run"
        for attempt in range(attempts):
            result, last_error = _pair_run_attempt(
                server_cmd,
                client_cmd,
                ready_marker,
                startup_timeout,
                timeout,
            )
            if result is not None:
                return result
            if attempt + 1 < attempts:
                time.sleep(retry_delay)
        raise RuntimeError(last_error)
    finally:
        _cleanup_blob_file(server_bin)
        _cleanup_blob_file(client_bin)


def run_blob(
    blob: BlobData,
    config: bytes = b"",
    runner_type: str = "",
    runner_path: Path | None = None,
    timeout: float = 30.0,
    debug: bool = False,
    dry_run: bool = False,
    stdin_data: bytes = b"",
    interactive: bool = False,
) -> RunResult:
    """Prepare and execute a blob under QEMU.

    Args:
        blob: Extracted blob data.
        config: Serialized config struct.
        runner_type: Test runner type ("linux", "freebsd", "windows").
            Defaults to blob.target_os.
        runner_path: Explicit path to the runner binary. Auto-discovered if None.
        timeout: Execution timeout in seconds.
        debug: Print verbose info (paths, command, timing). Keep temp files.
        dry_run: Build command but don't execute. Returns RunResult with command only.
        stdin_data: Bytes to feed to the blob's stdin — used by stager_fd
            tests so the blob can read a length-prefixed payload from fd 0.
        interactive: Inherit the terminal (TTY) instead of capturing output, so
            an interactive guest (e.g. a shell loaded by ul_exec) can be driven
            from the keyboard. Disables stdin_data and the timeout; the returned
            RunResult has empty stdout/stderr (output went straight to the tty).

    Returns:
        RunResult with stdout, stderr, exit code, and duration.

    Raises:
        FileNotFoundError: If QEMU or runner binary not found.
        subprocess.TimeoutExpired: If execution exceeds timeout.
    """
    if not runner_type:
        runner_type = blob.target_os

    if runner_type == "linux" and runner_path is None:
        return _run_linux_elf_blob(
            blob,
            config,
            timeout,
            debug,
            dry_run,
            stdin_data,
            interactive,
        )

    return _run_blob_with_runner(
        blob,
        config,
        runner_type,
        runner_path,
        timeout,
        debug,
        dry_run,
        stdin_data,
        interactive,
    )


def _run_blob_with_runner(
    blob: BlobData,
    config: bytes,
    runner_type: str,
    runner_path: Path | None,
    timeout: float,
    debug: bool,
    dry_run: bool,
    stdin_data: bytes,
    interactive: bool = False,
) -> RunResult:
    """Prepare and execute a blob through a C runner binary."""
    if runner_path is None:
        runner_path = find_runner(runner_type, blob.target_arch)

    if dry_run:
        return _run_blob_dry(blob, config, runner_type, runner_path, debug)

    blob_file = prepare_blob(blob, config)

    if debug:
        _log_run_blob_start(blob, config, runner_path, blob_file)

    cmd = build_blob_command(blob, runner_path, blob_file, runner_type)

    if debug:
        log.debug("command:    %s", " ".join(cmd))

    try:
        return _execute_blob_command(
            cmd, blob_file, timeout, debug, stdin_data, blob.target_arch, interactive
        )
    except subprocess.TimeoutExpired:
        if not debug:
            _cleanup_blob_file(blob_file)
        raise
    finally:
        if not debug:
            _cleanup_blob_file(blob_file)


def _log_run_blob_start(
    blob: BlobData,
    config: bytes,
    runner_path: Path | None,
    blob_file: Path,
) -> None:
    """Emit debug logging before executing a blob."""
    log.debug("blob:       %s %s:%s", blob.blob_type, blob.target_os, blob.target_arch)
    log.debug("code size:  %d bytes", len(blob.code))
    log.debug("config:     %d bytes at offset %d", len(config), blob.config_offset)
    if runner_path is None:
        log.debug("runner:     direct Linux ELF")
    else:
        log.debug("runner:     %s", runner_path)
    log.debug("blob file:  %s", blob_file)


def _run_linux_elf_blob(
    blob: BlobData,
    config: bytes,
    timeout: float,
    debug: bool,
    dry_run: bool,
    stdin_data: bytes,
    interactive: bool = False,
) -> RunResult:
    """Prepare and execute a Linux blob as a temporary ELF executable."""
    if dry_run:
        return _run_linux_elf_blob_dry(blob, config, debug)

    blob_file = prepare_linux_elf(blob, config)

    if debug:
        _log_run_blob_start(blob, config, None, blob_file)

    cmd = build_linux_elf_command(blob_file, blob.target_arch)

    if debug:
        log.debug("command:    %s", " ".join(cmd))

    try:
        return _execute_blob_command(
            cmd, blob_file, timeout, debug, stdin_data, blob.target_arch, interactive
        )
    except subprocess.TimeoutExpired:
        if not debug:
            _cleanup_blob_file(blob_file)
        raise
    finally:
        if not debug:
            _cleanup_blob_file(blob_file)


def _run_linux_elf_blob_dry(
    blob: BlobData,
    config: bytes,
    debug: bool,
) -> RunResult:
    """Build a Linux ELF dry-run command without creating temp files."""
    blob_file = Path(_linux_elf_filename(blob))
    cmd = build_linux_elf_command(blob_file, blob.target_arch)
    if debug:
        _log_run_blob_start(blob, config, None, blob_file)
        log.debug("blob file:  %s (dry-run placeholder)", blob_file)
        log.debug("command:    %s", " ".join(cmd))
        log.debug("dry run — not executing")
    return RunResult(
        stdout=b"",
        stderr=b"",
        exit_code=0,
        duration_s=0.0,
        command=cmd,
        blob_file=str(blob_file),
    )


def _run_blob_dry(
    blob: BlobData,
    config: bytes,
    runner_type: str,
    runner_path: Path,
    debug: bool,
) -> RunResult:
    """Build a dry-run command without creating temp files."""
    blob_file = Path(_blob_filename(blob))
    cmd = build_blob_command(blob, runner_path, blob_file, runner_type)
    if debug:
        _log_run_blob_start(blob, config, runner_path, blob_file)
        log.debug("blob file:  %s (dry-run placeholder)", blob_file)
        log.debug("command:    %s", " ".join(cmd))
        log.debug("dry run — not executing")
    return RunResult(
        stdout=b"",
        stderr=b"",
        exit_code=0,
        duration_s=0.0,
        command=cmd,
        blob_file=str(blob_file),
    )


def _spawn(
    cmd: list[str],
    stdin_data: bytes,
    timeout: float | None,
    interactive: bool,
) -> subprocess.CompletedProcess[bytes]:
    """Run *cmd*, capturing output or inheriting the terminal when interactive.

    In interactive mode the child inherits this process's stdin/stdout/stderr so
    a guest that drives a terminal (e.g. a shell loaded by ul_exec) gets a real
    TTY. Output is therefore not captured (``proc.stdout``/``stderr`` are None),
    no stdin is fed, and no timeout is applied — the session runs until it exits.
    """
    if interactive:
        return subprocess.run(cmd, check=False)
    return subprocess.run(
        cmd,
        capture_output=True,
        check=False,
        input=stdin_data or None,
        timeout=timeout,
    )


def exec_command(
    cmd: list[str],
    arch: str,
    *,
    stdin_data: bytes = b"",
    timeout: float | None = None,
    interactive: bool = False,
) -> tuple[subprocess.CompletedProcess[bytes], list[str]]:
    """Run *cmd*, retrying under a qemu-user interpreter on exec failure.

    The first attempt runs *cmd* as built (no interpreter prefix for a binary
    the host can run directly — native or via binfmt_misc). If the kernel
    can't exec it (``ENOEXEC``) and we weren't already using QEMU, locate a
    qemu-user interpreter and retry once.

    Returns the completed process and the argv that actually ran (which gains
    a qemu prefix if the fallback fired). With ``interactive=True`` the child
    inherits the terminal (see :func:`_spawn`).

    Raises:
        FileNotFoundError: Direct exec failed and no qemu-user interpreter is
            available for *arch*.
        subprocess.TimeoutExpired: If execution exceeds *timeout*.
    """
    try:
        proc = _spawn(cmd, stdin_data, timeout, interactive)
    except OSError as exc:
        return _retry_under_qemu(cmd, arch, exc, stdin_data, timeout, interactive)
    return proc, cmd


def _is_exec_format_error(exc: OSError) -> bool:
    """True if an exec failed because the kernel could not run the binary."""
    return exc.errno == errno.ENOEXEC


def _retry_under_qemu(
    cmd: list[str],
    arch: str,
    exc: OSError,
    stdin_data: bytes,
    timeout: float | None,
    interactive: bool = False,
) -> tuple[subprocess.CompletedProcess[bytes], list[str]]:
    """Recover a failed direct exec by prepending a qemu-user launcher.

    Only handles the "kernel can't run this binary" case where we weren't
    already using QEMU; anything else is re-raised unchanged.
    """
    if not _is_exec_format_error(exc) or qemu_launcher(arch):
        raise exc
    try:
        qemu = find_qemu(arch)
    except (FileNotFoundError, ValueError) as missing:
        raise FileNotFoundError(
            f"Cannot execute {arch} binary: the kernel has no handler for it "
            f"(no native support and no binfmt_misc qemu-user entry) and no "
            f"qemu-user interpreter is installed. {missing}"
        ) from exc
    _LAUNCHER_CACHE[arch] = (str(qemu),)
    new_cmd = [str(qemu), *cmd]
    proc = _spawn(new_cmd, stdin_data, timeout, interactive)
    return proc, new_cmd


def _execute_blob_command(
    cmd: list[str],
    blob_file: Path,
    timeout: float,
    debug: bool,
    stdin_data: bytes,
    arch: str,
    interactive: bool = False,
) -> RunResult:
    """Execute a prepared blob command and return the captured result.

    In interactive mode the child inherits the terminal, so no output is
    captured (stdout/stderr come back empty) and the timeout is not applied.
    """
    start = time.monotonic()
    proc, cmd = exec_command(
        cmd,
        arch,
        stdin_data=stdin_data,
        timeout=None if interactive else timeout,
        interactive=interactive,
    )
    duration = time.monotonic() - start
    if debug:
        log.debug("exit code:  %d", proc.returncode)
        log.debug("duration:   %.3fs", duration)
        log.debug("temp dir:   %s (preserved)", blob_file.parent)
    return RunResult(
        stdout=proc.stdout or b"",
        stderr=proc.stderr or b"",
        exit_code=proc.returncode,
        duration_s=duration,
        command=cmd,
        blob_file=str(blob_file),
    )


def run_so(*_args, **_kwargs) -> RunResult:
    """Fail explicitly: runtime .so extraction is not supported."""
    raise RuntimeError(
        "Runtime .so extraction is not supported. Generate sidecar artifacts "
        "with tools/stage_blobs.py or tools/extract_release.py, then load blobs "
        "through picblobs.get_blob()."
    )
