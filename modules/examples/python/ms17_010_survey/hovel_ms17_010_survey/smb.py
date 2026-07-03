"""Minimal SMBv1 client for the MS17-010 vulnerability touch.

This is a deliberately small, dependency-free SMBv1 implementation that does only
what the survey needs: a NULL-session negotiate / session-setup / tree-connect to
IPC$, a named-pipe open probe against MS17-010 pipe candidates, and the
well-known PeekNamedPipe transaction that distinguishes a vulnerable srv.sys
(STATUS_INSUFF_SERVER_RESOURCES) from a patched one. It is reconnaissance only and
never corrupts remote memory.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# NetBIOS Session Service.
_NBSS_SESSION_MESSAGE = 0x00
_NBSS_HEADER_LEN = 4

# SMB header layout (32 bytes).
_SMB_MAGIC = b"\xffSMB"
_SMB_HEADER_LEN = 32
_OFF_COMMAND = 4
_OFF_STATUS = 5
_OFF_TREE_ID = 24
_OFF_USER_ID = 28

# SMB commands.
CMD_NEGOTIATE = 0x72
CMD_SESSION_SETUP_ANDX = 0x73
CMD_TREE_CONNECT_ANDX = 0x75
CMD_NT_CREATE_ANDX = 0xA2
CMD_TRANSACTION = 0x25

# SMB header flags.
_FLAGS_CANONICAL_PATHS = 0x18
_FLAGS2_NT_STATUS_LONG_NAMES = 0x4001

# AndX terminator.
_ANDX_NONE = 0xFF

# Session-setup capability bits (NT SMBs + 32-bit status codes).
_CAP_NT_SMBS = 0x00000010
_CAP_STATUS32 = 0x00000040
_MAX_MPX_COUNT = 0x0A

# NT_CREATE_ANDX fields for opening a named pipe read/write.
_ACCESS_READ_PIPE = 0x0002019F
_SHARE_READ_WRITE = 0x00000003
_CREATE_OPEN = 0x00000001
_CREATE_NON_DIRECTORY = 0x00000040
_IMPERSONATION_LEVEL = 0x00000002

# Transaction sub-command.
_TRANS2_PEEK_NMPIPE = 0x0023

# NT status codes relevant to the touch.
STATUS_SUCCESS = 0x00000000
STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034

# Smbtouch-compatible named-pipe candidates for the MS17-010 probe.
PIPE_WHITELIST = ("spoolss", "browser", "lsarpc")


class SmbError(Exception):
    """Raised when the SMB transport fails or a response cannot be parsed."""


@dataclass(frozen=True)
class SmbResponse:
    command: int
    status: int
    tree_id: int
    user_id: int


def build_header(command: int, tree_id: int, user_id: int, mid: int) -> bytes:
    """Pack a 32-byte SMBv1 header for the given command and session ids."""
    # 4s magic, B command, I status, B flags, H flags2, H pid-high,
    # 10x (8-byte signature + 2-byte reserved), then tree id, pid-low, uid, mid.
    return struct.pack(
        "<4sBIBHH10xHHHH",
        _SMB_MAGIC,
        command,
        STATUS_SUCCESS,
        _FLAGS_CANONICAL_PATHS,
        _FLAGS2_NT_STATUS_LONG_NAMES,
        0,
        tree_id,
        0,
        user_id,
        mid,
    )


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise SmbError("connection closed mid-message")
        chunks.extend(chunk)
    return bytes(chunks)


class SmbTouchClient:
    """Drives the SMB exchange needed to fingerprint MS17-010 on one host."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._tree_id = 0
        self._user_id = 0
        self._mid = 0

    def __enter__(self) -> SmbTouchClient:
        self._sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _header(self, command: int) -> bytes:
        self._mid += 1
        return build_header(command, self._tree_id, self._user_id, self._mid)

    def _send(self, command: int, body: bytes) -> SmbResponse:
        if self._sock is None:
            raise SmbError("client is not connected")
        message = self._header(command) + body
        framed = struct.pack(">B3s", _NBSS_SESSION_MESSAGE, len(message).to_bytes(3, "big")) + message
        self._sock.sendall(framed)
        return self._recv()

    def _recv(self) -> SmbResponse:
        if self._sock is None:
            raise SmbError("client is not connected")
        nbss = _read_exact(self._sock, _NBSS_HEADER_LEN)
        length = int.from_bytes(nbss[1:4], "big")
        payload = _read_exact(self._sock, length)
        if len(payload) < _SMB_HEADER_LEN or payload[:4] != _SMB_MAGIC:
            raise SmbError("malformed SMB response header")
        command = payload[_OFF_COMMAND]
        (status,) = struct.unpack_from("<I", payload, _OFF_STATUS)
        (tree_id,) = struct.unpack_from("<H", payload, _OFF_TREE_ID)
        (user_id,) = struct.unpack_from("<H", payload, _OFF_USER_ID)
        return SmbResponse(command=command, status=int(status), tree_id=int(tree_id), user_id=int(user_id))

    def negotiate(self) -> SmbResponse:
        dialects = b"\x02NT LM 0.12\x00"
        body = struct.pack("<BH", 0, len(dialects)) + dialects
        response = self._send(CMD_NEGOTIATE, body)
        if response.status != STATUS_SUCCESS:
            raise SmbError(f"negotiate failed: status 0x{response.status:08x}")
        return response

    def session_setup_null(self) -> SmbResponse:
        # 13-word NT LM 0.12 SESSION_SETUP_ANDX with empty OEM/Unicode passwords =
        # an anonymous NULL session, which is required for the remote unauthenticated touch.
        # XP SP3 rejects the bare 4-null byte block (DOS error ERRSRV 0x0001), so we
        # send empty account/domain but real NativeOS/NativeLanMan strings, and a
        # server-sized MaxMpxCount.
        names = b"\x00\x00Unix\x00Samba\x00"  # account, domain, native OS, native LAN manager
        words = struct.pack(
            "<BBHHHHIHHII",
            _ANDX_NONE,
            0,
            0,
            4356,
            _MAX_MPX_COUNT,
            0,
            0,
            0,
            0,
            0,
            _CAP_NT_SMBS | _CAP_STATUS32,
        )
        body = struct.pack("<B", len(words) // 2) + words + struct.pack("<H", len(names)) + names
        response = self._send(CMD_SESSION_SETUP_ANDX, body)
        if response.status != STATUS_SUCCESS:
            raise SmbError(f"NULL session setup rejected: status 0x{response.status:08x}")
        self._user_id = response.user_id
        return response

    def tree_connect_ipc(self) -> SmbResponse:
        path = f"\\\\{self._host}\\IPC$\x00".encode("ascii", errors="replace")
        service = b"?????\x00"
        password = b"\x00"
        buffer = password + path + service
        words = struct.pack("<BBHHH", _ANDX_NONE, 0, 0, 0, len(password))
        body = struct.pack("<B", len(words) // 2) + words + struct.pack("<H", len(buffer)) + buffer
        response = self._send(CMD_TREE_CONNECT_ANDX, body)
        if response.status != STATUS_SUCCESS:
            raise SmbError(f"tree connect to IPC$ failed: status 0x{response.status:08x}")
        self._tree_id = response.tree_id
        return response

    def open_pipe(self, pipe: str) -> SmbResponse:
        name = f"\\{pipe}\x00".encode("ascii", errors="replace")
        # NT_CREATE_ANDX, WordCount 24: AndX(B) AndXReserved(B) AndXOffset(H)
        # Reserved(B) NameLength(H) Flags(I) RootFid(I) DesiredAccess(I)
        # AllocationSize(Q) ExtFileAttributes(I) ShareAccess(I) CreateDisposition(I)
        # CreateOptions(I) ImpersonationLevel(I) SecurityFlags(B).
        words = struct.pack(
            "<BBHBHIIIQIIIIIB",
            _ANDX_NONE,
            0,
            0,
            0,
            len(name) - 1,
            0,
            0,
            _ACCESS_READ_PIPE,
            0,
            0,
            _SHARE_READ_WRITE,
            _CREATE_OPEN,
            _CREATE_NON_DIRECTORY,
            _IMPERSONATION_LEVEL,
            0,
        )
        body = struct.pack("<B", len(words) // 2) + words + struct.pack("<H", len(name)) + name
        return self._send(CMD_NT_CREATE_ANDX, body)

    def peek_named_pipe(self) -> SmbResponse:
        # PeekNamedPipe against an invalid FID. A vulnerable srv.sys answers
        # STATUS_INSUFF_SERVER_RESOURCES (0xC0000205); a patched one does not.
        name = b"\\PIPE\\\x00\x00"
        setup = struct.pack("<HH", _TRANS2_PEEK_NMPIPE, 0)
        param_offset = _SMB_HEADER_LEN + 1 + (14 * 2) + len(setup) + 2 + len(name)
        words = struct.pack(
            "<HHHHBBHIHHHHHBB",
            0,  # TotalParameterCount
            0,  # TotalDataCount
            0xFFFF,  # MaxParameterCount
            0xFFFF,  # MaxDataCount
            0,  # MaxSetupCount
            0,  # Reserved
            0,  # Flags
            0,  # Timeout
            0,  # Reserved2
            0,  # ParameterCount
            param_offset,  # ParameterOffset
            0,  # DataCount
            param_offset,  # DataOffset
            len(setup) // 2,  # SetupCount
            0,  # Reserved3
        )
        buffer = name
        body = struct.pack("<B", (len(words) + len(setup)) // 2) + words + setup
        body += struct.pack("<H", len(buffer)) + buffer
        return self._send(CMD_TRANSACTION, body)
