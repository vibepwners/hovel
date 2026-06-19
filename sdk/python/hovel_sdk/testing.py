from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, BinaryIO, Self, cast

from hovel_sdk.framing import encode_message, read_message
from hovel_sdk.module import HovelModule
from hovel_sdk.server import JSONRPCServer


class RPCError(RuntimeError):
    """Raised when a test RPC call returns a JSON-RPC error response."""


class _BytePipe:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self._closed = False
        self._condition = threading.Condition()

    def write(self, data: bytes) -> int:
        with self._condition:
            if self._closed:
                raise ValueError("write to closed pipe")
            self._buffer.extend(data)
            self._condition.notify_all()
            return len(data)

    def flush(self) -> None:
        return

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def read(self, size: int = -1) -> bytes:
        with self._condition:
            if size is None or size < 0:
                while not self._closed:
                    self._condition.wait()
                data = bytes(self._buffer)
                self._buffer.clear()
                return data

            while len(self._buffer) < size and not self._closed:
                self._condition.wait()
            if not self._buffer and self._closed:
                return b""

            count = min(size, len(self._buffer))
            data = bytes(self._buffer[:count])
            del self._buffer[:count]
            return data


class ModuleRPC:
    """Drive a module through the real Content-Length framed JSON-RPC server."""

    def __init__(self, module: HovelModule) -> None:
        self.notifications: list[dict[str, Any]] = []
        self._stdin = _BytePipe()
        self._stdout = _BytePipe()
        self._next_id = 0
        self._closed = False
        self._thread = threading.Thread(target=self._serve, args=(module,), daemon=True)
        self._thread.start()

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("module RPC connection is closed")
        self._next_id += 1
        request_id = self._next_id
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        self._stdin.write(encode_message(request))
        while True:
            message = read_message(cast("BinaryIO", self._stdout))
            if message is None:
                raise RuntimeError(f"module exited before responding to {method}")
            if "id" not in message:
                self.notifications.append(message)
                continue
            if message.get("id") != request_id:
                raise RuntimeError(f"unexpected response id {message.get('id')!r}, want {request_id!r}")
            if "error" in message:
                error = message["error"]
                if isinstance(error, dict):
                    raise RPCError(str(error.get("message", error)))
                raise RPCError(str(error))
            result = message.get("result", {})
            if isinstance(result, dict):
                return result
            return {"value": result}

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.call("shutdown")
        finally:
            self._closed = True
            self._stdin.close()
            self._thread.join(timeout=1)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _serve(self, module: HovelModule) -> None:
        try:
            JSONRPCServer(module, cast("BinaryIO", self._stdin), cast("BinaryIO", self._stdout)).serve_forever()
        finally:
            self._stdout.close()


def drive_module(module: HovelModule, script: Callable[[ModuleRPC], None]) -> list[dict[str, Any]]:
    """Run a concise RPC script and return notifications emitted during it."""
    with ModuleRPC(module) as rpc:
        script(rpc)
        return list(rpc.notifications)
