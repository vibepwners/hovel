"""Payload tests for stager blobs (tcp, fd, pipe, mmap).

Each stager establishes a data channel, reads a next-stage payload,
allocates executable memory, and transfers execution.  Tests provide
infrastructure fixtures (TCP listener, FIFO writer, temp file) and
verify the stager delivers and executes the inner payload correctly.

See: spec/verification/TEST-011-payload-pytest-suite.md
     spec/verification/TEST-006-bootstrap-stager-verification.md
"""

from __future__ import annotations

import contextlib
import os
import socket
import struct
import threading
from pathlib import Path

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


def _blob_exists(blob_type: str, target_os: str, target_arch: str) -> bool:
    try:
        get_blob(blob_type, target_os, target_arch)
    except FileNotFoundError:
        return False
    else:
        return True


def _stager_combos(stager_type: str) -> list[tuple[str, str]]:
    combos = []
    for os_name in PAYLOAD_PLATFORMS.get(stager_type, []):
        os_entry = OPERATING_SYSTEMS.get(os_name)
        if os_entry is None:
            continue
        combos.extend((os_name, arch) for arch in runtime_test_arches(os_name))
    return sorted(combos)


def _inner_payload_os(target_os: str) -> str:
    """Return the OS for stager inner test payloads."""
    return "freebsd" if target_os == "freebsd" else "linux"


def _check_skip(
    blob_type: str,
    target_os: str,
    target_arch: str,
    test_payload: str = "test_pass",
) -> None:
    """Skip if blob, runner, or test payload are missing."""
    if not _blob_exists(blob_type, target_os, target_arch):
        pytest.skip(f"{blob_type} not staged: {target_os}/{target_arch}")

    if is_arch_skip_rosetta(target_arch):
        pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

    inner_os = _inner_payload_os(target_os)
    if test_payload and not _blob_exists(test_payload, inner_os, target_arch):
        pytest.skip(f"Test payload not staged: {test_payload}/{inner_os}/{target_arch}")

    runner_type = RUNNER_TYPE[target_os]
    if runner_type != "linux":
        try:
            from picblobs.runner import find_runner

            find_runner(runner_type, target_arch)
        except FileNotFoundError:
            pytest.skip(f"No {runner_type} runner for {target_arch}")


def _length_prefixed_payload(payload_bytes: bytes) -> bytes:
    """4-byte LE length prefix + payload bytes."""
    return struct.pack("<I", len(payload_bytes)) + payload_bytes


# ---------------------------------------------------------------------------
# Infrastructure fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tcp_payload_server():
    """Start a TCP server that serves a length-prefixed payload.

    Returns a factory: call it with payload_bytes to get (host, port).
    The server accepts one connection, sends the data, then closes.
    """
    servers = []

    def _start(payload_bytes: bytes) -> tuple[str, int]:
        data = _length_prefixed_payload(payload_bytes)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        host, port = srv.getsockname()
        servers.append(srv)

        def _serve() -> None:
            try:
                conn, _ = srv.accept()
                conn.sendall(data)
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return host, port

    yield _start

    for srv in servers:
        with contextlib.suppress(OSError):
            srv.close()


@pytest.fixture
def payload_file(tmp_path: Path):
    """Write payload bytes to a temp file, return the path.

    Returns a factory: call with payload_bytes to get file path.
    """

    def _write(payload_bytes: bytes) -> Path:
        p = tmp_path / "payload.bin"
        p.write_bytes(payload_bytes)
        return p

    return _write


# ---------------------------------------------------------------------------
# TCP stager tests
# ---------------------------------------------------------------------------


class TestStagerTcp:
    """TCP connect-back stager."""

    @pytest.mark.requires_qemu
    @pytest.mark.requires_local_tcp
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _stager_combos("stager_tcp"),
        ids=[f"{os}:{arch}" for os, arch in _stager_combos("stager_tcp")],
    )
    def test_tcp_stager_receives_and_executes(
        self,
        target_os: str,
        target_arch: str,
        tcp_payload_server,
    ) -> None:
        _check_skip("stager_tcp", target_os, target_arch, "test_tcp_ok")

        exp = EXPECTATIONS["stager_tcp"]
        blob = get_blob("stager_tcp", target_os, target_arch)

        inner = get_blob("test_tcp_ok", _inner_payload_os(target_os), target_arch)
        host, port = tcp_payload_server(inner.code)

        # Config: address family (u8) + port (u16) + ip (4 bytes).
        ip_bytes = socket.inet_aton(host)
        config = struct.pack("<BH", 2, port) + ip_bytes  # AF_INET=2

        result = run_blob(blob, config=config, timeout=exp.timeout)

        assert result.exit_code == exp.exit_code, (
            f"stager_tcp {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        if exp.stdout is not None:
            assert result.stdout == exp.stdout

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_arch",
        OPERATING_SYSTEMS["linux"].architectures,
        ids=OPERATING_SYSTEMS["linux"].architectures,
    )
    def test_connection_refused_exits_cleanly(self, target_arch: str) -> None:
        _check_skip("stager_tcp", "linux", target_arch, test_payload="")

        blob = get_blob("stager_tcp", "linux", target_arch)
        # Point at port 1 where nothing is listening.
        ip_bytes = socket.inet_aton("127.0.0.1")
        config = struct.pack("<BH", 2, 1) + ip_bytes

        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# FD stager tests
# ---------------------------------------------------------------------------


class TestStagerFd:
    """File descriptor (stdin) stager."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _stager_combos("stager_fd"),
        ids=[f"{os}:{arch}" for os, arch in _stager_combos("stager_fd")],
    )
    def test_fd_stager_reads_and_executes(
        self,
        target_os: str,
        target_arch: str,
    ) -> None:
        _check_skip("stager_fd", target_os, target_arch, "test_fd_ok")

        exp = EXPECTATIONS["stager_fd"]
        blob = get_blob("stager_fd", target_os, target_arch)

        inner = get_blob("test_fd_ok", _inner_payload_os(target_os), target_arch)

        # Config: fd number (u32). stdin=0.
        config = struct.pack("<I", 0)

        # Pipe the length-prefixed inner payload into the blob's stdin.
        stdin_data = _length_prefixed_payload(inner.code)
        result = run_blob(
            blob, config=config, timeout=exp.timeout, stdin_data=stdin_data
        )

        assert result.exit_code == exp.exit_code, (
            f"stager_fd {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        if exp.stdout is not None:
            assert result.stdout == exp.stdout

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_arch",
        OPERATING_SYSTEMS["linux"].architectures,
        ids=OPERATING_SYSTEMS["linux"].architectures,
    )
    def test_eof_on_stdin_exits_cleanly(self, target_arch: str) -> None:
        _check_skip("stager_fd", "linux", target_arch, test_payload="")

        blob = get_blob("stager_fd", "linux", target_arch)
        config = struct.pack("<I", 0)  # stdin, which will be empty
        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Named pipe stager tests
# ---------------------------------------------------------------------------


class TestStagerPipe:
    """Named pipe (FIFO) stager."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _stager_combos("stager_pipe"),
        ids=[f"{os}:{arch}" for os, arch in _stager_combos("stager_pipe")],
    )
    def test_pipe_stager_reads_and_executes(
        self,
        target_os: str,
        target_arch: str,
        tmp_path: Path,
    ) -> None:
        _check_skip("stager_pipe", target_os, target_arch, "test_pipe_ok")

        exp = EXPECTATIONS["stager_pipe"]
        blob = get_blob("stager_pipe", target_os, target_arch)

        inner = get_blob("test_pipe_ok", _inner_payload_os(target_os), target_arch)
        data = _length_prefixed_payload(inner.code)

        # Create FIFO.
        fifo = tmp_path / "test.fifo"
        os.mkfifo(str(fifo))

        # Writer thread (opens FIFO for writing after reader opens it).
        def _write_fifo() -> None:
            with fifo.open("wb") as f:
                f.write(data)

        writer = threading.Thread(target=_write_fifo, daemon=True)
        writer.start()

        # Config: pipe path length (u16) + path bytes.
        path_bytes = str(fifo).encode()
        config = struct.pack("<H", len(path_bytes)) + path_bytes

        result = run_blob(blob, config=config, timeout=exp.timeout)

        writer.join(timeout=5.0)

        assert result.exit_code == exp.exit_code, (
            f"stager_pipe {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        if exp.stdout_contains is not None:
            assert exp.stdout_contains in result.stdout


# ---------------------------------------------------------------------------
# Mmap file stager tests
# ---------------------------------------------------------------------------


class TestStagerMmap:
    """Memory-mapped file stager."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _stager_combos("stager_mmap"),
        ids=[f"{os}:{arch}" for os, arch in _stager_combos("stager_mmap")],
    )
    def test_mmap_stager_maps_and_executes(
        self,
        target_os: str,
        target_arch: str,
        payload_file,
    ) -> None:
        _check_skip("stager_mmap", target_os, target_arch, "test_mmap_ok")

        exp = EXPECTATIONS["stager_mmap"]
        blob = get_blob("stager_mmap", target_os, target_arch)

        inner = get_blob("test_mmap_ok", _inner_payload_os(target_os), target_arch)
        fpath = payload_file(inner.code)

        # Config: path length (u16) + path bytes + offset (u64) + size (u64).
        path_bytes = str(fpath).encode()
        config = (
            struct.pack("<H", len(path_bytes))
            + path_bytes
            + struct.pack("<QQ", 0, len(inner.code))
        )

        result = run_blob(blob, config=config, timeout=exp.timeout)

        assert result.exit_code == exp.exit_code, (
            f"stager_mmap {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        if exp.stdout is not None:
            assert result.stdout == exp.stdout
