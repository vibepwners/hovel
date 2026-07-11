"""picblobs-cli click command tree.

Implements REQ-020: ``run``, ``verify``, ``build``, ``list-runners``,
``info``. Each command delegates to ``picblobs`` for data access and to
``picblobs.runner`` for QEMU orchestration.
"""

from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import os as _os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import click
import picblobs
from picblobs import (
    OS,
    Arch,
    Blob,
    BlobType,
    ValidationError,
)
from picblobs.runner import (
    can_run,
    exec_command,
    find_runner,
    run_blob,
)

from picblobs_cli import (
    __version__ as cli_version,
)
from picblobs_cli import (
    runners_dir,
    ul_exec_test_binary,
)

DEFAULT_TARGET = "linux:x86_64"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise click.BadParameter(
            f"Invalid target {target!r} (expected os:arch, e.g. linux:x86_64)"
        )
    os_name, arch = target.split(":", 1)
    # Validate against the enums but keep the string form so downstream
    # code (picblobs.get_blob, run_blob) sees canonical lowercase strings.
    OS.parse(os_name)
    Arch.parse(arch)
    return os_name.lower(), arch.lower()


def _fail(message: str) -> None:
    click.echo(f"error: {message}", err=True)
    sys.exit(1)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _release_blob_dir() -> Path:
    return Path(picblobs.__file__).resolve().parent / "_blobs"


def _debug_blob_dir() -> Path:
    return _project_root() / "debug"


def _length_prefixed(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def _load_blob_data(
    blob_type: str | None,
    target: str,
):
    os_name, arch = _parse_target(target)
    try:
        if blob_type is None:
            _fail("a blob type is required")
        return picblobs.get_blob(blob_type, os_name, arch)
    except (FileNotFoundError, ValueError) as e:
        _fail(str(e))


def _write_blob_output(
    blob,
    output_path: Path,
    config_hex: str | None,
) -> None:
    data = bytearray(blob.code)
    if config_hex:
        try:
            config = bytes.fromhex(config_hex)
        except ValueError as e:
            _fail(f"invalid --config-hex: {e}")
        if blob.config_offset > len(data):
            data.extend(b"\x00" * (blob.config_offset - len(data)))
        data[blob.config_offset : blob.config_offset + len(config)] = config
    output_path.write_bytes(bytes(data))
    click.echo(f"wrote {len(data)} bytes to {output_path}")


def _resolve_staged_so_path(
    blob_type: str,
    os_name: str,
    arch: str,
    *,
    prefer_debug: bool,
    allow_release_fallback: bool,
) -> Path | None:
    roots: list[Path] = []
    if prefer_debug:
        roots.append(_debug_blob_dir())
    if allow_release_fallback:
        roots.append(_release_blob_dir())
    if not prefer_debug:
        roots.reverse()

    for root in roots:
        candidate = root / os_name / arch / f"{blob_type}.so"
        if candidate.exists():
            return candidate
    return None


def _resolve_disasm_so_path(
    blob_type: str | None,
    target: str,
    so_path: Path | None,
    *,
    prefer_debug: bool,
    allow_release_fallback: bool,
) -> Path:
    if so_path is not None:
        if not so_path.exists():
            _fail(f"file not found: {so_path}")
        return so_path
    if blob_type is None:
        _fail("a blob type or --so path is required")
    os_name, arch = _parse_target(target)
    resolved = _resolve_staged_so_path(
        blob_type,
        os_name,
        arch,
        prefer_debug=prefer_debug,
        allow_release_fallback=allow_release_fallback,
    )
    if resolved is None:
        if prefer_debug:
            _fail(
                f"no debug .so found for {blob_type} {os_name}:{arch}; "
                "stage with: task picblobs:stage -- --debug"
            )
        _fail(
            f"no .so found for {blob_type} {os_name}:{arch}; "
            "stage with: task picblobs:stage"
        )
    return resolved


def _find_objdump_or_fail(arch: str) -> str:
    from picblobs._objdump import find_objdump

    try:
        return find_objdump(arch)
    except FileNotFoundError as e:
        _fail(str(e))


def _pytest_env(
    os_name: str | None,
    arch: str | None,
    blob_type: str | None,
) -> dict[str, str]:
    env = _os.environ.copy()
    if os_name:
        env["PICBLOBS_TEST_OS"] = os_name
    if arch:
        env["PICBLOBS_TEST_ARCH"] = arch
    if blob_type:
        env["PICBLOBS_TEST_TYPE"] = blob_type
    return env


def _can_bind_localhost() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
    except OSError:
        return False
    else:
        return True


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

    pid = _os.fork()
    if pid == 0:
        try:
            ret = ptrace(PTRACE_TRACEME, 0, None, None)
            if ret != 0:
                _os._exit(1)
            _os.kill(_os.getpid(), signal.SIGSTOP)
            _os._exit(0)
        except BaseException:
            _os._exit(1)

    try:
        child_pid, status = _os.waitpid(pid, 0)
        if child_pid != pid or not _os.WIFSTOPPED(status):
            return False
        if ptrace(PTRACE_CONT, pid, None, None) != 0:
            return False
        _os.waitpid(pid, 0)
    except OSError:
        return False
    else:
        return True


def _verify_group_skip_reason(os_name: str, blob_type: str) -> str | None:
    if os_name == "freebsd" and not _can_ptrace_traceme():
        return "FreeBSD verify requires ptrace, which is unavailable"
    if blob_type == "stager_tcp" and not _can_bind_localhost():
        return "Local TCP sockets are unavailable"
    return None


def _is_local_tcp_verify_error(exc: OSError) -> bool:
    return exc.errno in {1, 13}


def _iter_runner_binaries(
    root: Path,
    os_filter: str | None,
    arch_filter: str | None,
):
    """Yield bundled runner tuples as (runner_type, arch, runner_path)."""
    for runner_type_dir in sorted(root.iterdir()):
        if not runner_type_dir.is_dir():
            continue
        if os_filter and runner_type_dir.name != os_filter:
            continue
        for arch_dir in sorted(runner_type_dir.iterdir()):
            if not arch_dir.is_dir():
                continue
            if arch_filter and arch_dir.name != arch_filter:
                continue
            runner = arch_dir / "runner"
            if runner.exists():
                yield runner_type_dir.name, arch_dir.name, runner


def _check_allowed_options(
    blob: BlobType,
    allowed: set[str],
    provided: dict[str, bool],
) -> None:
    """Fail if unsupported options were supplied for a blob type."""
    bad = [
        name for name, supplied in provided.items() if supplied and name not in allowed
    ]
    if bad:
        _fail(
            f"{blob.value}: options {sorted(bad)} are not valid for this "
            f"blob type (allowed: {sorted(allowed)})"
        )


@dataclasses.dataclass(frozen=True)
class _BuildOpts:
    """Builder options collected from the ``build`` / ``debug`` CLI flags.

    Field order matches the positional contract of the per-blob builders in
    ``_BUILDERS`` (see ``_build_blob_bytes``).
    """

    payload_file: Path | None = None
    address: str | None = None
    port: int | None = None
    fd: int | None = None
    stage_path: str | None = None
    offset: int = 0
    size: int | None = None
    pe_file: Path | None = None
    call_dll_main: bool = False
    elf_file: Path | None = None
    argv: tuple[str, ...] = ()
    envp: tuple[str, ...] = ()


def _provided_build_options(opts: _BuildOpts) -> dict[str, bool]:
    """Return a normalized map of supplied build options."""
    return {
        "payload": opts.payload_file is not None,
        "address": opts.address is not None,
        "port": opts.port is not None,
        "fd": opts.fd is not None,
        "path": opts.stage_path is not None,
        "offset": opts.offset != 0,
        "size": opts.size is not None,
        "pe": opts.pe_file is not None,
        "call-dll-main": opts.call_dll_main,
        "elf": opts.elf_file is not None,
        "argv": len(opts.argv) > 0,
        "envp": len(opts.envp) > 0,
    }


def _build_blob_bytes(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    opts: _BuildOpts,
) -> bytes:
    """Build bytes for one blob type from collected CLI options."""
    build_fn = _BUILDERS.get(blob)
    if build_fn is None:
        _fail(f"{blob.value}: not buildable via this CLI")
    return build_fn(
        base,
        blob,
        provided,
        opts.payload_file,
        opts.address,
        opts.port,
        opts.fd,
        opts.stage_path,
        opts.offset,
        opts.size,
        opts.pe_file,
        opts.call_dll_main,
        opts.elf_file,
        opts.argv,
        opts.envp,
    )


def _assemble_blob_image(
    blob_type: str,
    os_name: str,
    arch: str,
    opts: _BuildOpts,
) -> bytes:
    """Parse a blob type and assemble its full configured bytes.

    Shared by ``build`` and ``debug``. Enforces per-blob config requirements
    (e.g. ``ul_exec`` requires ``--elf``) via the builder dispatch, so a blob
    is never assembled with an empty config region that would trip its own
    runtime validation.
    """
    try:
        blob = BlobType.parse(blob_type)
    except ValidationError as e:
        _fail(str(e))
    provided = _provided_build_options(opts)
    try:
        return _build_blob_bytes(Blob(os_name, arch), blob, provided, opts)
    except ValidationError as e:
        _fail(str(e))


def _build_hello(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    *_args,
) -> bytes:
    _check_allowed_options(blob, set(), provided)
    return base.hello().build()


def _build_hello_windows(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    *_args,
) -> bytes:
    _check_allowed_options(blob, set(), provided)
    return base.hello_windows().build()


def _build_alloc_jump(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    payload_file: Path | None,
    *_args,
) -> bytes:
    _check_allowed_options(blob, {"payload"}, provided)
    if payload_file is None:
        _fail("alloc_jump requires --payload FILE")
    return base.alloc_jump().payload(payload_file.read_bytes()).build()


def _build_stager_tcp(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    _payload_file: Path | None,
    address: str | None,
    port: int | None,
    *_args,
) -> bytes:
    _check_allowed_options(blob, {"address", "port"}, provided)
    if address is None or port is None:
        _fail("stager_tcp requires --address and --port")
    return base.stager_tcp().address(address).port(port).build()


def _build_stager_fd(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    _payload_file: Path | None,
    _address: str | None,
    _port: int | None,
    fd: int | None,
    *_args,
) -> bytes:
    _check_allowed_options(blob, {"fd"}, provided)
    return base.stager_fd().fd(fd if fd is not None else 0).build()


def _build_stager_pipe(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    _payload_file: Path | None,
    _address: str | None,
    _port: int | None,
    _fd: int | None,
    stage_path: str | None,
    *_args,
) -> bytes:
    _check_allowed_options(blob, {"path"}, provided)
    if stage_path is None:
        _fail("stager_pipe requires --path")
    return base.stager_pipe().path(stage_path).build()


def _build_stager_mmap(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    _payload_file: Path | None,
    _address: str | None,
    _port: int | None,
    _fd: int | None,
    stage_path: str | None,
    offset: int,
    size: int | None,
    *_args,
) -> bytes:
    _check_allowed_options(blob, {"path", "offset", "size"}, provided)
    if stage_path is None or size is None:
        _fail("stager_mmap requires --path and --size")
    builder = base.stager_mmap().path(stage_path).size(size)
    if offset:
        builder = builder.offset(offset)
    return builder.build()


def _build_reflective_pe(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    _payload_file: Path | None,
    _address: str | None,
    _port: int | None,
    _fd: int | None,
    _stage_path: str | None,
    _offset: int,
    _size: int | None,
    pe_file: Path | None,
    call_dll_main: bool,
    *_args,
) -> bytes:
    _check_allowed_options(blob, {"pe", "call-dll-main"}, provided)
    if pe_file is None:
        _fail("reflective_pe requires --pe FILE")
    builder = base.reflective_pe().pe(pe_file.read_bytes())
    if call_dll_main:
        builder = builder.call_dll_main(True)
    return builder.build()


def _build_ul_exec(
    base: Blob,
    blob: BlobType,
    provided: dict[str, bool],
    _payload_file: Path | None,
    _address: str | None,
    _port: int | None,
    _fd: int | None,
    _stage_path: str | None,
    _offset: int,
    _size: int | None,
    _pe_file: Path | None,
    _call_dll_main: bool,
    elf_file: Path | None,
    argv: tuple[str, ...],
    envp: tuple[str, ...],
) -> bytes:
    _check_allowed_options(blob, {"elf", "argv", "envp"}, provided)
    if elf_file is None:
        _fail("ul_exec requires --elf FILE")
    builder = base.ul_exec().elf(elf_file.read_bytes())
    if argv:
        builder = builder.argv(list(argv))
    if envp:
        builder = builder.envp(list(envp))
    return builder.build()


_BUILDERS = {
    BlobType.HELLO: _build_hello,
    BlobType.HELLO_WINDOWS: _build_hello_windows,
    BlobType.ALLOC_JUMP: _build_alloc_jump,
    BlobType.STAGER_TCP: _build_stager_tcp,
    BlobType.STAGER_FD: _build_stager_fd,
    BlobType.STAGER_PIPE: _build_stager_pipe,
    BlobType.STAGER_MMAP: _build_stager_mmap,
    BlobType.REFLECTIVE_PE: _build_reflective_pe,
    BlobType.UL_EXEC: _build_ul_exec,
}


# ---------------------------------------------------------------------------
# Root command
# ---------------------------------------------------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=cli_version, prog_name="picblobs-cli")
def main() -> None:
    """picblobs-cli — inspect, build, run, and verify PIC blobs."""


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@main.command("list")
def list_cmd() -> None:
    """List every staged blob in the package."""
    blobs = picblobs.list_blobs()
    if not blobs:
        click.echo("No blobs found in package.")
        return

    fmt = "{:<20s} {:<10s} {:<15s}"
    click.echo(fmt.format("BLOB TYPE", "OS", "ARCH"))
    click.echo(fmt.format("-" * 20, "-" * 10, "-" * 15))
    for blob_type, os_name, arch in blobs:
        click.echo(fmt.format(blob_type, os_name, arch))
    click.echo(f"{len(blobs)} blob(s)")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def _emit_package_info() -> None:
    click.echo(f"picblobs:     {picblobs.__version__}")
    click.echo(f"picblobs-cli: {cli_version}")
    click.echo(f"runner bundle: {runners_dir()}")

    # Execution capability: native exec, a binfmt_misc qemu-user handler, or
    # a qemu-user interpreter on PATH — any of which lets a blob run.
    from picblobs._qemu import QEMU_BINARIES

    runnable: list[str] = []
    blocked: list[str] = []
    for arch in sorted(QEMU_BINARIES):
        (runnable if can_run(arch) else blocked).append(arch)
    click.echo(f"runnable:      {', '.join(runnable) or '<none>'}")
    if blocked:
        click.echo(f"not runnable:  {', '.join(blocked)}")

    click.echo("")
    click.echo("Targets:")
    for t in picblobs.targets():
        types = picblobs.blob_types(t.os, t.arch)
        click.echo(f"  {t}  ({len(types)} blob types)")


def _emit_blob_info(blob) -> None:
    click.echo(f"Blob:           {blob.blob_type}")
    click.echo(f"OS:             {blob.target_os}")
    click.echo(f"Arch:           {blob.target_arch}")
    click.echo(f"Code size:      {len(blob.code)} bytes")
    click.echo(f"Config offset:  {blob.config_offset}")
    click.echo(f"Entry offset:   {blob.entry_offset}")
    click.echo(f"SHA-256:        {blob.sha256}")
    click.echo("Sections:")
    for name, (offset, size) in sorted(blob.sections.items()):
        click.echo(f"  {name:<20} offset={offset:#06x}  size={size:#06x}")


@main.command()
@click.argument("blob_type", required=False)
@click.argument("target", required=False, default=DEFAULT_TARGET)
def info(
    blob_type: str | None,
    target: str,
) -> None:
    """Show package info, or blob metadata when TYPE is given."""
    if blob_type is None:
        _emit_package_info()
        return
    _emit_blob_info(_load_blob_data(blob_type, target))


# ---------------------------------------------------------------------------
# list-runners
# ---------------------------------------------------------------------------


@main.command("list-runners")
@click.option("--os", "os_filter", help="Filter to a single runner OS")
@click.option("--arch", "arch_filter", help="Filter to a single arch")
def list_runners(os_filter: str | None, arch_filter: str | None) -> None:
    """List every bundled (runner_type, arch) runner binary."""
    root = runners_dir()
    if not root.exists():
        _fail(f"runner bundle not found at {root}. Run task picblobs:stage first.")

    fmt = "{:<10s} {:<15s} {}"
    click.echo(fmt.format("RUNNER", "ARCH", "PATH"))
    click.echo(fmt.format("-" * 10, "-" * 15, "-" * 40))

    found = False
    for runner_type, arch, runner in _iter_runner_binaries(
        root, os_filter, arch_filter
    ):
        found = True
        click.echo(fmt.format(runner_type, arch, str(runner)))

    if not found:
        _fail("no runners found (check --os / --arch filters)")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


@main.command()
@click.argument("blob_type")
@click.argument("target")
@click.option(
    "-o",
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output file (written as raw bytes)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["raw", "elf"]),
    default="raw",
    show_default=True,
    help="Output container format. ELF is Linux-only.",
)
@click.option(
    "--wrap-elf",
    "wrap_elf_output",
    is_flag=True,
    help="Wrap output as a minimal Linux ELF executable.",
)
@click.option(
    "--payload",
    "payload_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Payload bytes (alloc_jump)",
)
@click.option("--address", help="IPv4 address (stager_tcp)")
@click.option("--port", type=int, help="TCP port (stager_tcp)")
@click.option("--fd", type=int, help="File descriptor (stager_fd)")
@click.option(
    "--path",
    "stage_path",
    help="FIFO or file path (stager_pipe, stager_mmap)",
)
@click.option("--offset", type=int, default=0, help="File offset (stager_mmap)")
@click.option("--size", type=int, help="Byte count to map (stager_mmap)")
@click.option(
    "--pe",
    "pe_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="PE image (reflective_pe)",
)
@click.option("--call-dll-main", is_flag=True, help="Call DllMain (reflective_pe)")
@click.option(
    "--elf",
    "elf_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="ELF image (ul_exec)",
)
@click.option("--argv", multiple=True, help="argv entry (ul_exec, repeatable)")
@click.option("--envp", multiple=True, help="envp entry (ul_exec, repeatable)")
def build(
    blob_type: str,
    target: str,
    output_path: Path,
    output_format: str,
    wrap_elf_output: bool,
    payload_file: Path | None,
    address: str | None,
    port: int | None,
    fd: int | None,
    stage_path: str | None,
    offset: int,
    size: int | None,
    pe_file: Path | None,
    call_dll_main: bool,
    elf_file: Path | None,
    argv: tuple[str, ...],
    envp: tuple[str, ...],
) -> None:
    """Assemble a blob via the builder API and write it to OUTPUT."""
    os_name, arch = _parse_target(target)
    opts = _BuildOpts(
        payload_file=payload_file,
        address=address,
        port=port,
        fd=fd,
        stage_path=stage_path,
        offset=offset,
        size=size,
        pe_file=pe_file,
        call_dll_main=call_dll_main,
        elf_file=elf_file,
        argv=argv,
        envp=envp,
    )
    out = _assemble_blob_image(blob_type, os_name, arch, opts)

    if wrap_elf_output:
        output_format = "elf"

    if output_format == "elf":
        try:
            out = picblobs.wrap_elf(out, os_name, arch)
        except ValidationError as e:
            _fail(str(e))

    output_path.write_bytes(out)
    if output_format == "elf":
        output_path.chmod(output_path.stat().st_mode | 0o111)
    click.echo(f"wrote {len(out)} bytes to {output_path}")


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------


@main.command()
@click.argument("blob_type", required=False)
@click.argument("target", required=False, default=DEFAULT_TARGET)
@click.option(
    "-o",
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output file path",
)
@click.option("--config-hex", help="Config bytes as hex, patched into the output")
def extract(
    blob_type: str | None,
    target: str,
    output_path: Path,
    config_hex: str | None,
) -> None:
    """Extract a flat blob image to OUTPUT."""
    blob = _load_blob_data(blob_type, target)
    _write_blob_output(blob, output_path, config_hex)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _run_file(
    blob_file: Path,
    runner_type: str,
    arch: str,
    stdin_data: bytes,
    timeout: float,
    debug: bool,
    dry_run: bool,
    runner_path: Path | None,
    interactive: bool = False,
) -> None:
    """Execute an already-assembled blob file under the correct runner.

    Unlike the registry path, we don't construct a ``BlobData`` or
    append a config — the file is assumed to be a complete blob image
    and is passed straight to the runner binary. Linux file-mode blobs
    are wrapped into a temporary ELF when no explicit runner is supplied.
    """
    from picblobs.runner import _build_command

    if runner_type == "linux" and runner_path is None:
        _run_linux_file(
            blob_file, arch, stdin_data, timeout, debug, dry_run, interactive
        )
        return

    resolved_runner = runner_path
    if resolved_runner is None:
        try:
            resolved_runner = find_runner(runner_type, arch)
        except FileNotFoundError as e:
            _fail(str(e))

    cmd = _build_command(resolved_runner, blob_file, arch)

    if debug:
        click.echo(f"runner:    {resolved_runner}", err=True)
        click.echo(f"blob file: {blob_file} ({blob_file.stat().st_size} B)", err=True)
        click.echo(f"command:   {' '.join(cmd)}", err=True)

    if dry_run:
        click.echo(" ".join(cmd))
        sys.exit(0)

    try:
        result, _ = exec_command(
            cmd,
            arch,
            stdin_data=stdin_data,
            timeout=None if interactive else timeout,
            interactive=interactive,
        )
    except subprocess.TimeoutExpired:
        _fail(f"blob timed out after {timeout}s")
    except FileNotFoundError as e:
        _fail(str(e))

    _emit_exec_result(result, interactive)


def _emit_exec_result(
    result: subprocess.CompletedProcess[bytes], interactive: bool
) -> None:
    """Forward a completed-process result to stdio and exit with its code.

    In interactive mode output already went to the terminal, so there is
    nothing (and possibly nothing captured) to replay.
    """
    if not interactive:
        sys.stdout.buffer.write(result.stdout or b"")
        sys.stderr.buffer.write(result.stderr or b"")
        sys.stdout.flush()
        sys.stderr.flush()
    sys.exit(result.returncode)


def _run_linux_file(
    blob_file: Path,
    arch: str,
    stdin_data: bytes,
    timeout: float,
    debug: bool,
    dry_run: bool,
    interactive: bool = False,
) -> None:
    """Run a raw or ELF Linux payload file without a packaged C runner."""
    if dry_run:
        _run_linux_file_dry(blob_file, arch, debug)
        return
    _run_linux_file_exec(blob_file, arch, stdin_data, timeout, debug, interactive)


def _run_linux_file_dry(blob_file: Path, arch: str, debug: bool) -> None:
    """Print the direct Linux ELF file-mode command without executing."""
    from picblobs.runner import build_linux_elf_command

    try:
        cmd = build_linux_elf_command(_linux_file_placeholder(blob_file), arch)
    except FileNotFoundError as e:
        _fail(str(e))
    if debug:
        click.echo("runner:    direct Linux ELF", err=True)
        click.echo(
            f"blob file: {blob_file} ({blob_file.stat().st_size} B)",
            err=True,
        )
        click.echo(f"command:   {' '.join(cmd)}", err=True)
    click.echo(" ".join(cmd))
    sys.exit(0)


def _run_linux_file_exec(
    blob_file: Path,
    arch: str,
    stdin_data: bytes,
    timeout: float,
    debug: bool,
    interactive: bool = False,
) -> None:
    """Prepare and execute Linux file-mode payload bytes as an ELF."""
    from picblobs.runner import build_linux_elf_command

    exec_file: Path | None = None
    try:
        exec_file = _prepare_linux_file(blob_file, arch)
        cmd = build_linux_elf_command(exec_file, arch)
    except (FileNotFoundError, ValidationError) as e:
        if exec_file is not None:
            _cleanup_prepared_linux_file(exec_file)
        _fail(str(e))

    if debug:
        click.echo("runner:    direct Linux ELF", err=True)
        click.echo(f"blob file: {exec_file} ({exec_file.stat().st_size} B)", err=True)
        click.echo(f"command:   {' '.join(cmd)}", err=True)

    try:
        result, _ = exec_command(
            cmd,
            arch,
            stdin_data=stdin_data,
            timeout=None if interactive else timeout,
            interactive=interactive,
        )
    except subprocess.TimeoutExpired:
        _fail(f"blob timed out after {timeout}s")
    except FileNotFoundError as e:
        _fail(str(e))
    finally:
        if exec_file is not None:
            _cleanup_prepared_linux_file(exec_file)

    _emit_exec_result(result, interactive)


def _linux_file_placeholder(blob_file: Path) -> Path:
    """Return a dry-run placeholder for Linux file-mode execution."""
    if _file_is_elf(blob_file):
        return Path(blob_file.name)
    return Path(f"{blob_file.stem}.elf")


def _prepare_linux_file(blob_file: Path, arch: str) -> Path:
    """Copy or wrap a Linux file-mode payload into an executable temp ELF."""
    data = blob_file.read_bytes()
    temp_dir = Path(tempfile.mkdtemp(prefix="picblobs_"))
    if data.startswith(b"\x7fELF"):
        exec_file = temp_dir / blob_file.name
        exec_file.write_bytes(data)
    else:
        exec_file = temp_dir / f"{blob_file.stem}.elf"
        exec_file.write_bytes(picblobs.wrap_elf(data, "linux", arch))
    exec_file.chmod(exec_file.stat().st_mode | 0o700)
    return exec_file


def _file_is_elf(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(4) == b"\x7fELF"


def _cleanup_prepared_linux_file(path: Path) -> None:
    path.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        path.parent.rmdir()


def _parse_run_mode(
    positional: tuple[str, ...],
    blob_file: Path | None,
) -> tuple[str | None, str]:
    """Return (blob_type, target) for file or registry run modes."""
    if blob_file is not None:
        if len(positional) != 1:
            _fail(
                "with --file, supply exactly one positional: TARGET "
                "(got: " + " ".join(repr(p) for p in positional) + ")"
            )
        return None, positional[0]
    if len(positional) != 2:
        _fail(
            "registry mode expects two positionals: "
            "picblobs-cli run <blob_type> <target>"
        )
    return positional[0], positional[1]


def _registry_run_config(
    config_hex: str | None,
    payload_file: Path | None,
) -> bytes:
    """Return registry-mode config bytes."""
    if config_hex:
        try:
            return bytes.fromhex(config_hex)
        except ValueError as e:
            _fail(f"invalid --config-hex: {e}")
    if payload_file:
        return payload_file.read_bytes()
    return b""


def _emit_run_result(stdout: bytes, stderr: bytes, exit_code: int) -> None:
    """Write subprocess output to stdio and exit with the given code."""
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    sys.exit(exit_code)


def _run_registry_blob(
    blob_type: str | None,
    os_name: str,
    arch: str,
    config: bytes,
    timeout: float,
    debug: bool,
    stdin_data: bytes,
    runner_type: str,
    runner_path: Path | None,
    dry_run: bool,
    interactive: bool = False,
) -> None:
    """Run a staged blob looked up through picblobs."""
    try:
        if blob_type is None:
            _fail("blob type is required when --file is not used")
        blob_data = picblobs.get_blob(blob_type, os_name, arch)
    except FileNotFoundError as e:
        _fail(str(e))
    except ValueError as e:
        _fail(str(e))

    try:
        result = run_blob(
            blob_data,
            config=config,
            timeout=timeout,
            debug=debug,
            stdin_data=stdin_data,
            runner_type=runner_type,
            runner_path=runner_path,
            dry_run=dry_run,
            interactive=interactive,
        )
    except FileNotFoundError as e:
        _fail(str(e))
    except subprocess.TimeoutExpired:
        _fail(f"blob timed out after {timeout}s")

    if dry_run:
        click.echo(" ".join(result.command))
        sys.exit(0)
    if interactive:
        sys.exit(result.exit_code)
    _emit_run_result(result.stdout, result.stderr, result.exit_code)


@main.command()
@click.argument("positional", nargs=-1)
@click.option(
    "-f",
    "--file",
    "blob_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Run an already-assembled blob file instead of "
    "looking up by blob type. Bypasses config assembly; "
    "the file is handed to the runner as-is.",
)
@click.option("--config-hex", help="Config bytes as hex (registry mode only)")
@click.option(
    "--payload",
    "payload_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Read config from a file (registry mode only)",
)
@click.option(
    "--stdin",
    "stdin_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Pipe file contents to the blob's stdin",
)
@click.option("--timeout", type=float, default=30.0, show_default=True)
@click.option("--runner-type", help="Runner type override")
@click.option(
    "--runner-path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Explicit runner binary path",
)
@click.option(
    "-i",
    "--interactive",
    is_flag=True,
    help="Attach the blob to your terminal (TTY) so interactive guests work "
    "(e.g. a shell loaded by ul_exec). Disables output capture, stdin feed, "
    "and the timeout.",
)
@click.option("--debug", is_flag=True, help="Verbose output, keep temp files")
@click.option("--dry-run", is_flag=True, help="Print the command without executing")
def run(
    positional: tuple[str, ...],
    blob_file: Path | None,
    config_hex: str | None,
    payload_file: Path | None,
    stdin_file: Path | None,
    timeout: float,
    runner_type: str | None,
    runner_path: Path | None,
    interactive: bool,
    debug: bool,
    dry_run: bool,
) -> None:
    """Run a PIC blob under the bundled runner and QEMU.

    Two modes:

    \b
      picblobs-cli run <blob_type> <target>      # registry lookup
      picblobs-cli run --file FILE <target>      # already-assembled blob

    File mode is what you want after ``picblobs-cli build ... -o out.bin``
    or any other flow that produces a complete (code+config) blob.

    Use ``-i/--interactive`` for blobs that drive a terminal — e.g.
    ``picblobs-cli run --file bash.bin linux:x86_64 -i`` after building an
    ul_exec blob around an interactive program.
    """
    blob_type, target = _parse_run_mode(positional, blob_file)
    os_name, arch = _parse_target(target)
    if interactive and stdin_file:
        _fail("--interactive and --stdin are mutually exclusive")
    if interactive and dry_run:
        _fail("--interactive and --dry-run are mutually exclusive")
    stdin_data = stdin_file.read_bytes() if stdin_file else b""
    selected_runner_type = runner_type or os_name

    if blob_file is not None:
        if config_hex or payload_file:
            _fail(
                "--config-hex / --payload have no effect with --file; "
                "assemble the blob first via 'picblobs-cli build ... -o FILE'"
            )
        _run_file(
            blob_file,
            selected_runner_type,
            arch,
            stdin_data,
            timeout,
            debug,
            dry_run,
            runner_path,
            interactive,
        )
        return

    _run_registry_blob(
        blob_type,
        os_name,
        arch,
        _registry_run_config(config_hex, payload_file),
        timeout,
        debug,
        stdin_data,
        selected_runner_type,
        runner_path,
        dry_run,
        interactive,
    )


# ---------------------------------------------------------------------------
# debug
# ---------------------------------------------------------------------------

# qemu-user opens its gdbstub socket at process start, before executing any
# guest code, so a short settle is enough for gdb's `target remote` to land.
# We deliberately do not pre-connect to probe readiness — the stub accepts a
# single client, and a probe would consume gdb's slot.
_GDBSTUB_SETTLE_S = 0.5


def _write_temp_elf(elf_bytes: bytes) -> Path:
    """Write ELF bytes to an executable temp file and return its path."""
    temp_dir = Path(tempfile.mkdtemp(prefix="picblobs_"))
    elf_file = temp_dir / "blob.elf"
    elf_file.write_bytes(elf_bytes)
    elf_file.chmod(elf_file.stat().st_mode | 0o700)
    return elf_file


def _debug_prepare_elf(
    blob_type: str | None,
    os_name: str,
    arch: str,
    blob_file: Path | None,
    opts: _BuildOpts,
) -> tuple[Path, Path | None]:
    """Return ``(elf_path, symbol_so)`` for a debug session.

    Registry mode assembles a fully configured blob via the builder API (so
    e.g. ``ul_exec`` gets its embedded ELF and does not abort at its own config
    check), wraps it into a temporary executable ELF, and returns its debug
    ``.so`` (if staged) for symbol/source loading. File mode wraps/copies the
    already-assembled file into a temp ELF with no symbols.
    """
    if blob_file is not None:
        return _prepare_linux_file(blob_file, arch), None

    if blob_type is None:
        _fail("a blob type is required when --file is not used")

    out = _assemble_blob_image(blob_type, os_name, arch, opts)
    try:
        elf_bytes = picblobs.wrap_elf(out, os_name, arch)
    except ValidationError as e:
        _fail(str(e))

    elf_path = _write_temp_elf(elf_bytes)
    symbol_so = _resolve_staged_so_path(
        blob_type,
        os_name,
        arch,
        prefer_debug=True,
        allow_release_fallback=True,
    )
    return elf_path, symbol_so


def _write_gdb_script(
    elf_path: Path,
    base_vaddr: int,
    entry_pc: int,
    symbol_so: Path | None,
    *,
    remote_port: int | None,
) -> Path:
    """Write the gdb command script and return its path.

    The script loads symbols from the debug ``.so`` (offset to the ELF load
    base), then stops on the blob's first instruction: ``starti`` for a native
    inferior, or ``target remote`` for a qemu gdbstub (which halts at the entry
    point before connecting).
    """
    lines = ["set pagination off", "set confirm off"]
    if symbol_so is not None:
        lines.append(f"add-symbol-file {symbol_so} -o {base_vaddr:#x}")
    if remote_port is not None:
        lines.append(f"target remote :{remote_port}")
    else:
        lines.append("starti")
    lines.append("set confirm on")
    lines.append(
        f"echo \\n[picblobs] stopped at first instruction (entry {entry_pc:#x})\\n"
    )

    fd, name = tempfile.mkstemp(prefix="picblobs_gdb_", suffix=".gdb")
    script = Path(name)
    with _os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return script


def _debug_validate(
    positional: tuple[str, ...],
    blob_file: Path | None,
    opts: _BuildOpts,
) -> tuple[str | None, str, str]:
    """Validate debug args and return ``(blob_type, os_name, arch)``."""
    blob_type, target = _parse_run_mode(positional, blob_file)
    os_name, arch = _parse_target(target)
    if os_name != "linux":
        _fail("debug currently supports linux targets only")
    if blob_file is not None and any(_provided_build_options(opts).values()):
        _fail(
            "build options have no effect with --file; assemble the blob first "
            "via 'picblobs-cli build ... -o FILE'"
        )
    return blob_type, os_name, arch


def _debug_resolve_gdb(
    arch: str,
    gdb_path: str | None,
    native: bool,
    elf_path: Path,
) -> str:
    """Resolve the gdb binary, warning if a host-only gdb is used cross-arch.

    Called after the blob ELF is prepared, so a missing gdb cleans up the temp
    ELF before failing.
    """
    from picblobs._gdb import find_gdb

    try:
        gdb_bin = gdb_path or find_gdb(arch, native=native)
    except FileNotFoundError as e:
        _cleanup_prepared_linux_file(elf_path)
        _fail(str(e))
    if not native and Path(gdb_bin).name == "gdb":
        click.echo(
            f"warning: using plain '{gdb_bin}' for cross target {arch}; it may "
            "not decode this architecture. Install gdb-multiarch or an "
            f"{arch}-specific gdb for full register/disassembly support.",
            err=True,
        )
    return gdb_bin


def _debug_qemu_cmd(arch: str, port: int, elf_path: Path) -> list[str]:
    """Build the qemu-user gdbstub command, cleaning up the ELF on failure."""
    from picblobs.runner import find_qemu

    try:
        qemu_bin = find_qemu(arch)
    except (FileNotFoundError, ValueError) as e:
        _cleanup_prepared_linux_file(elf_path)
        _fail(str(e))
    return [str(qemu_bin), "-g", str(port), str(elf_path)]


def _debug_dry_run(
    gdb_cmd: list[str],
    qemu_cmd: list[str] | None,
    elf_path: Path,
    script: Path,
) -> None:
    """Print the would-be commands, clean up temp artifacts, and exit."""
    if qemu_cmd is not None:
        click.echo(" ".join(qemu_cmd))
    click.echo(" ".join(gdb_cmd))
    _cleanup_prepared_linux_file(elf_path)
    script.unlink(missing_ok=True)
    sys.exit(0)


def _debug_launch(
    gdb_cmd: list[str],
    qemu_cmd: list[str] | None,
) -> int:
    """Launch gdb (and a backing qemu gdbstub, if any); return gdb's exit code."""
    qemu_proc: subprocess.Popen[bytes] | None = None
    if qemu_cmd is not None:
        # Blob stdout/stderr share the terminal so prints are visible; stdin is
        # detached so qemu does not fight gdb for the controlling tty.
        qemu_proc = subprocess.Popen(qemu_cmd, stdin=subprocess.DEVNULL)
        time.sleep(_GDBSTUB_SETTLE_S)
    try:
        return subprocess.run(gdb_cmd, check=False).returncode
    finally:
        if qemu_proc is not None and qemu_proc.poll() is None:
            qemu_proc.kill()
            qemu_proc.wait()


@main.command()
@click.argument("positional", nargs=-1)
@click.option(
    "-f",
    "--file",
    "blob_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Debug an already-assembled blob file instead of a registry lookup.",
)
@click.option(
    "--payload",
    "payload_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Payload bytes (alloc_jump)",
)
@click.option("--address", help="IPv4 address (stager_tcp)")
@click.option("--port", type=int, help="TCP port (stager_tcp)")
@click.option("--fd", type=int, help="File descriptor (stager_fd)")
@click.option(
    "--path",
    "stage_path",
    help="FIFO or file path (stager_pipe, stager_mmap)",
)
@click.option("--offset", type=int, default=0, help="File offset (stager_mmap)")
@click.option("--size", type=int, help="Byte count to map (stager_mmap)")
@click.option(
    "--pe",
    "pe_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="PE image (reflective_pe)",
)
@click.option("--call-dll-main", is_flag=True, help="Call DllMain (reflective_pe)")
@click.option(
    "--elf",
    "elf_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="ELF image (ul_exec)",
)
@click.option("--argv", multiple=True, help="argv entry (ul_exec, repeatable)")
@click.option("--envp", multiple=True, help="envp entry (ul_exec, repeatable)")
@click.option(
    "--gdb-port",
    "gdb_port",
    type=int,
    default=1234,
    show_default=True,
    help="TCP port for the qemu gdbstub (cross-arch / --qemu)",
)
@click.option("--gdb", "gdb_path", help="Explicit gdb binary to use")
@click.option(
    "--qemu",
    "force_qemu",
    is_flag=True,
    help="Use a qemu gdbstub even for a host-native architecture",
)
@click.option(
    "--symbols/--no-symbols",
    "load_symbols",
    default=True,
    show_default=True,
    help="Load source/symbols from the staged debug .so when available",
)
@click.option("--dry-run", is_flag=True, help="Print the commands without launching")
def debug(
    positional: tuple[str, ...],
    blob_file: Path | None,
    payload_file: Path | None,
    address: str | None,
    port: int | None,
    fd: int | None,
    stage_path: str | None,
    offset: int,
    size: int | None,
    pe_file: Path | None,
    call_dll_main: bool,
    elf_file: Path | None,
    argv: tuple[str, ...],
    envp: tuple[str, ...],
    gdb_port: int,
    gdb_path: str | None,
    force_qemu: bool,
    load_symbols: bool,
    dry_run: bool,
) -> None:
    """Launch a blob under gdb, stopped on its first instruction.

    \b
      picblobs-cli debug <blob_type> <target>    # registry lookup
      picblobs-cli debug --file FILE <target>    # already-assembled blob

    Registry mode assembles a fully configured blob with the same builder
    options as ``build`` (e.g. ``ul_exec`` requires ``--elf``), so the blob
    enters with a valid config instead of aborting at its own config check.

    Host-native targets run under gdb directly (``starti``). Cross targets run
    under a qemu-user gdbstub that halts at the entry point; gdb attaches over
    the local ``--gdb-port``. When a debug ``.so`` is staged its symbols and
    source are loaded automatically (disable with ``--no-symbols``).
    """
    from picblobs._elf import linux_elf_entry
    from picblobs.runner import _is_native_arch

    opts = _BuildOpts(
        payload_file=payload_file,
        address=address,
        port=port,
        fd=fd,
        stage_path=stage_path,
        offset=offset,
        size=size,
        pe_file=pe_file,
        call_dll_main=call_dll_main,
        elf_file=elf_file,
        argv=argv,
        envp=envp,
    )
    blob_type, os_name, arch = _debug_validate(positional, blob_file, opts)
    try:
        base_vaddr, entry_pc = linux_elf_entry(arch)
    except ValidationError as e:
        _fail(str(e))

    native = _is_native_arch(arch) and not force_qemu

    # Assemble and validate the blob before resolving the debugger, so input
    # errors (e.g. ul_exec missing --elf) surface independently of whether gdb
    # is installed on this host.
    elf_path, symbol_so = _debug_prepare_elf(blob_type, os_name, arch, blob_file, opts)
    if not load_symbols:
        symbol_so = None

    gdb_bin = _debug_resolve_gdb(arch, gdb_path, native, elf_path)
    qemu_cmd = None if native else _debug_qemu_cmd(arch, gdb_port, elf_path)
    script = _write_gdb_script(
        elf_path,
        base_vaddr,
        entry_pc,
        symbol_so,
        remote_port=None if native else gdb_port,
    )
    gdb_cmd = [gdb_bin, str(elf_path), "-x", str(script)]

    if dry_run:
        _debug_dry_run(gdb_cmd, qemu_cmd, elf_path, script)

    try:
        code = _debug_launch(gdb_cmd, qemu_cmd)
    finally:
        _cleanup_prepared_linux_file(elf_path)
        script.unlink(missing_ok=True)
    sys.exit(code)


# ---------------------------------------------------------------------------
# disasm / listing
# ---------------------------------------------------------------------------


@main.command()
@click.argument("blob_type", required=False)
@click.argument("target", required=False, default=DEFAULT_TARGET)
@click.option(
    "-f",
    "--function",
    "function_name",
    default="",
    help="Function name to disassemble; when omitted, list function symbols",
)
@click.option(
    "--so",
    "so_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Disassemble a direct .so path",
)
def disasm(
    blob_type: str | None,
    target: str,
    function_name: str,
    so_path: Path | None,
) -> None:
    """Disassemble a blob function or list function symbols."""
    from picblobs._objdump import (
        disassemble_function,
        has_debug_info,
        list_symbols,
    )

    resolved = _resolve_disasm_so_path(
        blob_type,
        target,
        so_path,
        prefer_debug=True,
        allow_release_fallback=False,
    )
    _, arch = _parse_target(target)
    objdump = _find_objdump_or_fail(arch)

    if not function_name:
        try:
            symbols = list_symbols(str(resolved), objdump)
        except RuntimeError as e:
            _fail(str(e))
        if not symbols:
            click.echo(f"No function symbols found in {resolved.name}")
            return
        fmt = "  {:<16s} {:<10s} {}"
        click.echo(f"Functions in {resolved.name}:")
        click.echo(fmt.format("ADDRESS", "SIZE", "NAME"))
        for addr, size, name in symbols:
            click.echo(fmt.format(addr, size, name))
        return

    if not has_debug_info(str(resolved), objdump):
        _fail(
            f"no DWARF debug info in {resolved}; "
            "stage with: task picblobs:stage -- --debug"
        )
    try:
        output = disassemble_function(
            str(resolved),
            objdump,
            function_name,
            source=True,
        )
    except RuntimeError as e:
        _fail(str(e))
    sys.stdout.write(output)


@main.command()
@click.argument("blob_type", required=False)
@click.argument("target", required=False, default=DEFAULT_TARGET)
@click.option(
    "--so",
    "so_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Disassemble a direct .so path",
)
def listing(
    blob_type: str | None,
    target: str,
    so_path: Path | None,
) -> None:
    """Print a full disassembly listing, preferring debug .so files."""
    from picblobs._objdump import disassemble_full, has_debug_info

    resolved = _resolve_disasm_so_path(
        blob_type,
        target,
        so_path,
        prefer_debug=True,
        allow_release_fallback=True,
    )
    _, arch = _parse_target(target)
    objdump = _find_objdump_or_fail(arch)
    try:
        output = disassemble_full(
            str(resolved),
            objdump,
            source=has_debug_info(str(resolved), objdump),
        )
    except RuntimeError as e:
        _fail(str(e))
    sys.stdout.write(output)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@main.command(context_settings={"ignore_unknown_options": True})
@click.option("--os", "os_name", help="Filter by OS")
@click.option("--arch", help="Filter by architecture")
@click.option("--type", "blob_type", help="Filter by blob type")
@click.option("-k", "pytest_filter", help="pytest -k expression")
@click.option("-v", "--verbose", is_flag=True, help="Pass -v to pytest")
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
def test(
    os_name: str | None,
    arch: str | None,
    blob_type: str | None,
    pytest_filter: str | None,
    verbose: bool,
    pytest_args: tuple[str, ...],
) -> None:
    """Run the pytest suite with optional picblobs environment filters."""
    cmd = [sys.executable, "-m", "pytest"]
    if verbose:
        cmd.append("-v")
    if pytest_filter:
        cmd.extend(["-k", pytest_filter])
    cmd.extend(pytest_args)

    result = subprocess.run(
        cmd,
        check=False,
        env=_pytest_env(os_name, arch, blob_type),
    )
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _verify_one(blob_type: str, os_name: str, arch: str, timeout: float):
    """Dispatcher that mirrors the fixture logic from the legacy CLI."""
    blob = picblobs.get_blob(blob_type, os_name, arch)

    if blob_type == "stager_tcp":
        return _verify_stager_tcp(os_name, arch, timeout)
    if blob_type == "stager_fd":
        return _verify_stager_fd(os_name, arch, timeout)
    if blob_type == "stager_pipe":
        return _verify_stager_pipe(os_name, arch, timeout)
    if blob_type == "stager_mmap":
        return _verify_stager_mmap(os_name, arch, timeout)
    if blob_type == "alloc_jump":
        return _verify_alloc_jump(os_name, arch, timeout)
    if blob_type == "reflective_pe":
        return _verify_reflective_pe(os_name, arch, timeout)
    if blob_type == "ul_exec":
        return _verify_ul_exec(os_name, arch, timeout)

    return run_blob(blob, runner_type=os_name, timeout=timeout)


class _VerifySummary:
    """Mutable counters and output helpers for the click verify command."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.errors: list[str] = []

    def ok(self, label: str, detail: str) -> None:
        click.echo(f"  {label:<20}  OK   {detail}")
        self.passed += 1

    def skip(self, label: str, reason: str) -> None:
        click.echo(f"  {label:<20}  SKIP ({reason})")
        self.skipped += 1

    def fail(self, blob_type: str, label: str, detail: str) -> None:
        click.echo(f"  {label:<20}  {detail}", err=True)
        self.failed += 1
        self.errors.append(f"{blob_type}/{label}")

    def emit(self) -> None:
        total = self.passed + self.failed + self.skipped
        click.echo("")
        parts = [f"{self.passed}/{total} passed"]
        if self.skipped:
            parts.append(f"{self.skipped} skipped")
        if self.errors:
            parts.append(f"failed: {', '.join(self.errors)}")
        click.echo("  ".join(parts))


def _filter_verify_combos(
    combos: list[tuple[str, str, str]],
    os_filter: tuple[str, ...],
    arch_filter: tuple[str, ...],
    type_filter: tuple[str, ...],
) -> list[tuple[str, str, str]]:
    """Apply click verify filters to staged blob triples."""
    filters = (
        (set(os_filter) if os_filter else None, 1),
        (set(arch_filter) if arch_filter else None, 2),
        (set(type_filter) if type_filter else None, 0),
    )
    for allowed, index in filters:
        if allowed:
            combos = [entry for entry in combos if entry[index] in allowed]
    return [
        entry
        for entry in combos
        if _is_verify_target_supported(entry[0], entry[1], entry[2])
    ]


def _is_verify_target_supported(blob_type: str, os_name: str, arch: str) -> bool:
    if os_name != "freebsd":
        return True
    if arch != "x86_64":
        return False
    return blob_type != "ul_exec"


def _group_verify_combos(
    combos: list[tuple[str, str, str]],
) -> dict[tuple[str, str], list[str]]:
    """Group verify triples by (os, blob_type)."""
    groups: dict[tuple[str, str], list[str]] = {}
    for bt, os_name, arch in combos:
        groups.setdefault((os_name, bt), []).append(arch)
    return groups


def _nacl_pair_arches(
    groups: dict[tuple[str, str], list[str]],
) -> dict[str, list[str]]:
    """Return arches where both NaCl pair blobs are staged."""
    pairs: dict[str, list[str]] = {}
    for (os_name, blob_type), arches in groups.items():
        if blob_type != "nacl_client":
            continue
        server = set(groups.get((os_name, "nacl_server"), []))
        common = sorted(set(arches) & server)
        if common:
            pairs[os_name] = common
    return pairs


def _skip_verify_blob(blob_type: str) -> bool:
    """Return True for non-standalone verify blobs."""
    return blob_type in {
        "nacl_client",
        "nacl_server",
        "nacl_client_hosted",
        "nacl_server_hosted",
    }


def _record_verify_result(
    blob_type: str,
    os_name: str,
    arch: str,
    result,
    summary: _VerifySummary,
) -> None:
    """Record one single-blob verify result."""
    label = f"{os_name}:{arch}"
    out = result.stdout.decode(errors="replace").strip()
    if result.exit_code == 0:
        summary.ok(label, repr(out))
        return
    summary.fail(blob_type, label, f"FAIL exit={result.exit_code:<4d} {out!r}")


def _skip_verify_arches(
    summary: _VerifySummary,
    os_name: str,
    arches: list[str],
    reason: str,
) -> None:
    for arch in sorted(arches):
        summary.skip(f"{os_name}:{arch}", reason)


def _record_nacl_verify_oserror(
    summary: _VerifySummary,
    label: str,
    error: OSError,
) -> bool:
    if _is_local_tcp_verify_error(error):
        summary.skip(label, "Local TCP runtime is unavailable")
        return True
    summary.fail("nacl_e2e", label, f"FAIL {error}")
    return False


def _run_verify_group(
    os_name: str,
    blob_type: str,
    arches: list[str],
    timeout: float,
    summary: _VerifySummary,
) -> None:
    """Run one grouped verify section for a single blob type."""
    click.echo(f"[{os_name}] {blob_type}")
    skip_reason = _verify_group_skip_reason(os_name, blob_type)
    if skip_reason is not None:
        _skip_verify_arches(summary, os_name, arches, skip_reason)
        return
    for arch in sorted(arches):
        label = f"{os_name}:{arch}"
        try:
            result = _verify_one(blob_type, os_name, arch, timeout)
            _record_verify_result(blob_type, os_name, arch, result, summary)
        except _Skip as e:
            summary.skip(label, str(e))
        except OSError as e:
            if blob_type == "stager_tcp" and _is_local_tcp_verify_error(e):
                summary.skip(label, "Local TCP runtime is unavailable")
                continue
            summary.fail(blob_type, label, f"ERROR {e}")
        except Exception as e:
            summary.fail(blob_type, label, f"ERROR {e}")


def _nacl_verify_group_skip_reason(os_name: str) -> str | None:
    if os_name == "freebsd" and not _can_ptrace_traceme():
        return "FreeBSD verify requires ptrace, which is unavailable"
    if not _can_bind_localhost():
        return "Local TCP sockets are unavailable"
    return None


def _run_nacl_verify_group(
    os_name: str,
    arches: list[str],
    timeout: float,
    slow: bool,
    summary: _VerifySummary,
) -> None:
    """Run one grouped NaCl pair verify section."""
    click.echo(f"[{os_name}] nacl e2e")
    skip_reason = _nacl_verify_group_skip_reason(os_name)
    if skip_reason is not None:
        _skip_verify_arches(summary, os_name, arches, skip_reason)
        return
    for arch in sorted(arches):
        label = f"{os_name}:{arch}"
        try:
            detail = _verify_nacl_e2e(
                os_name,
                arch,
                max(timeout, 600.0) if slow else timeout,
                force_slow=slow,
            )
            summary.ok(label, detail)
        except _Skip as e:
            summary.skip(label, str(e))
        except OSError as e:
            if _record_nacl_verify_oserror(summary, label, e):
                continue
        except Exception as e:
            summary.fail("nacl_e2e", label, f"FAIL {e}")


def _verify_inner_os(os_name: str) -> str:
    if os_name in {"windows", "freebsd"}:
        return os_name
    return "linux"


def _verify_inner_blob_type(os_name: str, blob_type: str) -> str:
    if os_name == "windows":
        return "hello_windows"
    mapping = {
        "alloc_jump": "test_pass",
        "stager_fd": "test_fd_ok",
        "stager_pipe": "test_pipe_ok",
        "stager_mmap": "test_mmap_ok",
        "stager_tcp": "test_tcp_ok",
    }
    return mapping[blob_type]


def _verify_stager_tcp(os_name: str, arch: str, timeout: float):
    inner = picblobs.get_blob(
        _verify_inner_blob_type(os_name, "stager_tcp"),
        _verify_inner_os(os_name),
        arch,
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        host, port = srv.getsockname()
        payload = _length_prefixed(inner.code)

        def _serve():
            try:
                srv.settimeout(max(timeout, 1.0))
                conn, _ = srv.accept()
                try:
                    conn.sendall(payload)
                finally:
                    conn.close()
            except OSError:
                pass

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        try:
            cfg = struct.pack("<BH", 2, port) + socket.inet_aton(host)
            blob = picblobs.get_blob("stager_tcp", os_name, arch)
            return run_blob(blob, config=cfg, runner_type=os_name, timeout=timeout)
        finally:
            t.join(timeout=5.0)
    finally:
        srv.close()


def _verify_stager_fd(os_name: str, arch: str, timeout: float):
    inner = picblobs.get_blob(
        _verify_inner_blob_type(os_name, "stager_fd"),
        _verify_inner_os(os_name),
        arch,
    )
    cfg = struct.pack("<I", 0)
    blob = picblobs.get_blob("stager_fd", os_name, arch)
    return run_blob(
        blob,
        config=cfg,
        runner_type=os_name,
        timeout=timeout,
        stdin_data=_length_prefixed(inner.code),
    )


def _verify_stager_pipe(os_name: str, arch: str, timeout: float):
    inner = picblobs.get_blob(
        _verify_inner_blob_type(os_name, "stager_pipe"),
        _verify_inner_os(os_name),
        arch,
    )
    tmp = Path(tempfile.mkdtemp(prefix="picblobs_pipe_"))
    fifo = tmp / "payload.fifo"
    _os.mkfifo(str(fifo))
    payload = _length_prefixed(inner.code)

    def _writer():
        try:
            with fifo.open("wb") as f:
                f.write(payload)
        except OSError:
            pass

    t = threading.Thread(target=_writer, daemon=True)
    t.start()
    try:
        path_bytes = str(fifo).encode()
        cfg = struct.pack("<H", len(path_bytes)) + path_bytes
        blob = picblobs.get_blob("stager_pipe", os_name, arch)
        return run_blob(blob, config=cfg, runner_type=os_name, timeout=timeout)
    finally:
        t.join(timeout=5.0)
        try:
            fifo.unlink()
            tmp.rmdir()
        except OSError:
            pass


def _verify_stager_mmap(os_name: str, arch: str, timeout: float):
    inner = picblobs.get_blob(
        _verify_inner_blob_type(os_name, "stager_mmap"),
        _verify_inner_os(os_name),
        arch,
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(inner.code)
        fpath = f.name
    try:
        path_bytes = fpath.encode()
        cfg = (
            struct.pack("<H", len(path_bytes))
            + path_bytes
            + struct.pack("<QQ", 0, len(inner.code))
        )
        blob = picblobs.get_blob("stager_mmap", os_name, arch)
        return run_blob(blob, config=cfg, runner_type=os_name, timeout=timeout)
    finally:
        with contextlib.suppress(OSError):
            Path(fpath).unlink()


def _verify_alloc_jump(os_name: str, arch: str, timeout: float):
    inner = picblobs.get_blob(
        _verify_inner_blob_type(os_name, "alloc_jump"),
        _verify_inner_os(os_name),
        arch,
    )
    cfg = struct.pack("<I", len(inner.code)) + inner.code
    blob = picblobs.get_blob("alloc_jump", os_name, arch)
    return run_blob(blob, config=cfg, runner_type=os_name, timeout=timeout)


def _verify_reflective_pe(os_name: str, arch: str, timeout: float):
    dummy = b"MZ" + b"\x00" * 126
    cfg = struct.pack("<IIB", len(dummy), 0, 0) + dummy
    blob = picblobs.get_blob("reflective_pe", os_name, arch)
    return run_blob(blob, config=cfg, runner_type=os_name, timeout=timeout)


def _verify_ul_exec(os_name: str, arch: str, timeout: float):
    from picblobs._cross_compile import build_ul_exec_config

    elf_data = ul_exec_test_binary(os_name, arch)
    if elf_data is None:
        raise _Skip(f"no staged ul_exec test binary for {os_name}:{arch}")
    cfg = build_ul_exec_config(elf_data, arch, argv=["verify"])
    blob = picblobs.get_blob("ul_exec", os_name, arch)
    return run_blob(blob, config=cfg, runner_type=os_name, timeout=timeout)


_NACL_E2E_SLOW_ARCHES: frozenset[str] = frozenset()

# Shared 32-byte handshake auth key injected into both nacl blobs during
# verify. Authenticates the ephemeral X25519 exchange; not a secret here.
_NACL_VERIFY_AUTH_KEY = bytes(range(1, 33))


def _check_nacl_e2e_speed(arch: str, force_slow: bool) -> None:
    if arch not in _NACL_E2E_SLOW_ARCHES or force_slow:
        return
    raise _Skip(
        f"QEMU {arch} too slow for crypto handshake; use --slow to force (timeout=600s)"
    )


def _verify_nacl_e2e(
    os_name: str,
    arch: str,
    timeout: float,
    *,
    force_slow: bool = False,
) -> str:
    """Run nacl_server + nacl_client as a paired handshake, return summary."""
    from picblobs.runner import (
        reserve_tcp_port,
        run_blob_pair,
    )

    _check_nacl_e2e_speed(arch, force_slow)
    runner_path = None if os_name == "linux" else find_runner(os_name, arch)
    server_blob = picblobs.get_blob("nacl_server", os_name, arch)
    client_blob = picblobs.get_blob("nacl_client", os_name, arch)
    port = reserve_tcp_port()
    # Server config is port + key. Client config also carries the peer IPv4.
    # Both blobs need the same key to authenticate the ephemeral X25519
    # exchange; a fixed value is appropriate only for this local verifier.
    server_config = struct.pack("<H", port) + _NACL_VERIFY_AUTH_KEY
    client_config = (
        struct.pack("<H", port) + socket.inet_aton("127.0.0.1") + _NACL_VERIFY_AUTH_KEY
    )
    result = run_blob_pair(
        server_blob,
        client_blob,
        runner_path,
        os_name,
        server_config=server_config,
        client_config=client_config,
        timeout=timeout,
    )
    _require_nacl_pair_success(result)
    return _nacl_pair_detail(result.server_stdout, result.client_stdout)


def _require_nacl_pair_success(result) -> None:
    """Raise with context if a NaCl e2e pair did not complete correctly."""
    server_out = result.server_stdout
    client_out = result.client_stdout
    if result.server_exit != 0:
        raise RuntimeError(
            f"server exit={result.server_exit} stderr={result.server_stderr!r}"
        )
    if result.client_exit != 0:
        raise RuntimeError(
            f"client exit={result.client_exit} stderr={result.client_stderr!r}"
        )

    if b"Hello from NaCl PIC blob!" not in server_out:
        raise RuntimeError(f"server did not decrypt expected plaintext: {server_out!r}")
    if b"secure channel OK" not in server_out or b"secure channel OK" not in client_out:
        raise RuntimeError("peers did not confirm channel")


def _nacl_pair_detail(server_out: bytes, client_out: bytes) -> str:
    """Return a compact success summary from NaCl pair stdout."""
    decrypted = _line_suffix(server_out, "decrypted:")
    ack = _line_suffix(client_out, "decrypted ACK:")
    return f"encrypt->send->decrypt {decrypted!r}, ACK {ack!r}"


def _line_suffix(output: bytes, marker: str) -> str:
    """Return the stripped suffix after marker in decoded line output."""
    for line in output.decode(errors="replace").splitlines():
        if marker in line:
            return line.split(marker, 1)[1].strip()
    return ""


class _Skip(Exception):
    pass


@main.command()
@click.option("--os", "os_filter", multiple=True, help="Filter by OS")
@click.option("--arch", "arch_filter", multiple=True, help="Filter by arch")
@click.option("--type", "type_filter", multiple=True, help="Filter by blob type")
@click.option("--timeout", type=float, default=30.0, show_default=True)
@click.option(
    "--slow",
    is_flag=True,
    help="Run slow tests that are skipped by default",
)
def verify(
    os_filter: tuple[str, ...],
    arch_filter: tuple[str, ...],
    type_filter: tuple[str, ...],
    timeout: float,
    slow: bool,
) -> None:
    """Run every staged blob end-to-end (mirrors legacy ``picblobs verify``)."""
    combos = _filter_verify_combos(
        picblobs.list_blobs(),
        os_filter,
        arch_filter,
        type_filter,
    )

    if not combos:
        _fail("no blobs match the given filters")

    summary = _VerifySummary()
    groups = _group_verify_combos(combos)
    nacl_pair_arches = _nacl_pair_arches(groups)

    for (os_name, blob_type), arches in sorted(groups.items()):
        if _skip_verify_blob(blob_type):
            continue
        _run_verify_group(os_name, blob_type, arches, timeout, summary)

    # NaCl e2e handshake runs.
    type_set = set(type_filter)
    if (
        not type_filter
        or "nacl_e2e" in type_set
        or "nacl_client" in type_set
        or "nacl_server" in type_set
    ):
        for os_name, arches in sorted(nacl_pair_arches.items()):
            _run_nacl_verify_group(os_name, arches, timeout, slow, summary)

    summary.emit()
    sys.exit(1 if summary.failed else 0)
