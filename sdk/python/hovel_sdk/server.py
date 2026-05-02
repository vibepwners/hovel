from __future__ import annotations

import asyncio
import inspect
import logging
import sys
from typing import Any, BinaryIO

from hovel_sdk.context import Context
from hovel_sdk.framing import FrameError, read_message, write_message
from hovel_sdk.logging import setup_logging
from hovel_sdk.module import HovelModule
from hovel_sdk.session import SessionManager


class JSONRPCServer:
    def __init__(self, module: HovelModule, stdin: BinaryIO, stdout: BinaryIO) -> None:
        self._module = module
        self._stdin = stdin
        self._stdout = stdout
        self._loop = asyncio.new_event_loop()
        self._sessions = SessionManager(self._emit_session_event)

    def serve_forever(self) -> None:
        asyncio.set_event_loop(self._loop)
        setup_logging(self._emit_log)
        while True:
            message = read_message(self._stdin)
            if message is None:
                return
            if "method" not in message:
                continue
            if "id" not in message:
                self._handle_notification(message)
                continue
            response = self._handle_request(message)
            write_message(self._stdout, response)
            if message.get("method") == "shutdown":
                return

    def _handle_notification(self, message: dict[str, Any]) -> None:
        if message.get("method") == "cancel":
            logging.getLogger("hovel.module").info("cancel requested")

    def _handle_request(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": "request method must be a string"},
            }
        try:
            result = self._dispatch(method, message.get("params") or {})
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:
            logging.getLogger("hovel.module").exception("module request failed")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(exc)},
            }

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "handshake":
            return self._module.info()
        if method == "schema":
            return self._module.module_schema()
        if method == "execute":
            return self._loop.run_until_complete(self._execute(params))
        if method.startswith("session/"):
            return self._loop.run_until_complete(self._dispatch_session(method, params))
        if method == "shutdown":
            self._loop.run_until_complete(self._sessions.close_all())
            return {"status": "ok"}
        raise ValueError(f"unknown method {method!r}")

    async def _dispatch_session(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "session/write":
            return await self._sessions.write_rpc(params)
        if method == "session/read":
            return await self._sessions.read_rpc(params)
        if method == "session/close":
            return await self._sessions.close_rpc(params)
        raise ValueError(f"unknown method {method!r}")

    async def _execute(self, params: dict[str, Any]) -> dict[str, Any]:
        run_id = str(params.get("runId", ""))
        module_id = str(params.get("moduleId", self._module.name))
        target = str(params.get("target", ""))
        sessions = self._sessions.for_run(run_id=run_id, module_id=module_id, target=target)
        ctx = Context(
            run_id=run_id,
            module_id=module_id,
            target=target,
            inputs=dict(params.get("inputs") or {}),
            chain_config=dict(params.get("chainConfig") or {}),
            target_config=dict(params.get("targetConfig") or {}),
            log=logging.getLogger(self._module.name or "hovel.module"),
            sessions=sessions,
        )
        maybe_result = self._module.run(ctx)
        if inspect.isawaitable(maybe_result):
            result = await maybe_result
        else:
            result = maybe_result
        return result.to_rpc(sessions=sessions.refs())

    def _emit_log(self, params: dict[str, Any]) -> None:
        write_message(self._stdout, {"jsonrpc": "2.0", "method": "module/log", "params": params})

    def _emit_session_event(self, params: dict[str, Any]) -> None:
        write_message(self._stdout, {"jsonrpc": "2.0", "method": "module/session", "params": params})


def serve(module: HovelModule, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
    server = JSONRPCServer(module, stdin or sys.stdin.buffer, stdout or sys.stdout.buffer)
    try:
        server.serve_forever()
    except FrameError as exc:
        sys.stderr.write(f"hovel sdk frame error: {exc}\n")
        raise SystemExit(2) from exc
