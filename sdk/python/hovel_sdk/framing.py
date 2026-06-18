from __future__ import annotations

import json
import threading
from typing import Any, BinaryIO

MAX_FRAME_BYTES = 64 * 1024 * 1024


class FrameError(Exception):
    pass


def encode_message(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    header = _read_until(stream, b"\r\n\r\n")
    if header == b"":
        return None
    content_length = _content_length_from_header(header)
    body = stream.read(content_length)
    if len(body) != content_length:
        raise FrameError("truncated frame body")
    return _decode_message_body(body)


def _content_length_from_header(header: bytes) -> int:
    content_length: int | None = None
    for line in header.decode("ascii").split("\r\n"):
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep == "" or name.lower() != "content-length":
            continue
        try:
            content_length = int(value.strip())
        except ValueError as exc:
            raise FrameError("invalid Content-Length") from exc
    if content_length is None:
        raise FrameError("missing Content-Length")
    if content_length < 0:
        raise FrameError("invalid Content-Length")
    if content_length > MAX_FRAME_BYTES:
        raise FrameError(f"Content-Length {content_length} exceeds maximum {MAX_FRAME_BYTES}")
    return content_length


def _decode_message_body(body: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise FrameError("invalid JSON frame body") from exc
    if not isinstance(decoded, dict):
        raise FrameError("JSON-RPC message must be an object")
    return decoded


def write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    stream.write(encode_message(message))
    stream.flush()


class MessageWriter:
    """Serialize framed writes to one stream.

    A module may emit logs or session notifications from code paths that overlap
    request handling. The protocol is stdout-framed, so every frame write must
    be atomic with respect to other frame writes.
    """

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, message: dict[str, Any]) -> None:
        encoded = encode_message(message)
        with self._lock:
            self._stream.write(encoded)
            self._stream.flush()


def _read_until(stream: BinaryIO, marker: bytes) -> bytes:
    data = bytearray()
    while True:
        chunk = stream.read(1)
        if chunk == b"":
            if not data:
                return b""
            raise FrameError("truncated frame header")
        data.extend(chunk)
        if data.endswith(marker):
            return bytes(data[: -len(marker)])
