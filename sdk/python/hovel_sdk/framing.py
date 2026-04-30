from __future__ import annotations

import json
from typing import Any, BinaryIO


class FrameError(Exception):
    pass


def encode_message(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    header = _read_until(stream, b"\r\n\r\n")
    if header == b"":
        return None
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
    body = stream.read(content_length)
    if len(body) != content_length:
        raise FrameError("truncated frame body")
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
