from __future__ import annotations

import asyncio
import inspect
import logging
import sys
from typing import Any, BinaryIO

from hovel_sdk.context import AgentContext, Context
from hovel_sdk.framing import FrameError, MessageWriter, read_message
from hovel_sdk.logging import setup_logging
from hovel_sdk.module import HovelModule
from hovel_sdk.session import SessionManager

_MODULE_TYPES = {"survey", "exploit", "payload_provider"}


class JSONRPCServer:
    def __init__(self, module: HovelModule, stdin: BinaryIO, stdout: BinaryIO) -> None:
        self._module = module
        self._stdin = stdin
        self._writer = MessageWriter(stdout)
        self._loop = asyncio.new_event_loop()
        self._sessions = SessionManager(self._emit_session_event)

    def serve_forever(self) -> None:
        asyncio.set_event_loop(self._loop)
        handler = setup_logging(self._emit_log)
        try:
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
                self._writer.write(response)
                if message.get("method") == "shutdown":
                    return
        finally:
            logging.getLogger().removeHandler(handler)
            self._loop.run_until_complete(self._sessions.close_all())
            self._loop.close()

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
            info = self._module.info()
            _validate_handshake_info(info)
            return info
        if method == "schema":
            return self._module.module_schema()
        if method.startswith("step."):
            return self._dispatch_step(method, params)
        if method == "execute":
            return self._loop.run_until_complete(self._execute(params))
        if method.startswith("session/"):
            return self._loop.run_until_complete(self._dispatch_session(method, params))
        if method == "shutdown":
            self._loop.run_until_complete(self._sessions.close_all())
            return {"status": "ok"}
        raise ValueError(f"unknown method {method!r}")

    def _dispatch_step(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "step.describe":
            return self._module.describe_steps()
        if method == "step.prepare":
            return self._module.prepare_step(params)
        if method == "step.execute":
            return self._module.execute_step(params)
        if method == "step.cleanup":
            return self._module.cleanup_step(params)
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
            agent=AgentContext.from_rpc(params.get("agentContext")),
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
        self._writer.write({"jsonrpc": "2.0", "method": "module/log", "params": params})

    def _emit_session_event(self, params: dict[str, Any]) -> None:
        self._writer.write({"jsonrpc": "2.0", "method": "module/session", "params": params})


def serve(module: HovelModule, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
    server = JSONRPCServer(module, stdin or sys.stdin.buffer, stdout or sys.stdout.buffer)
    try:
        server.serve_forever()
    except FrameError as exc:
        sys.stderr.write(f"hovel sdk frame error: {exc}\n")
        raise SystemExit(2) from exc


def _required_handshake_string(info: dict[str, Any], key: str) -> str:
    value = info.get(key, "")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"module handshake {key} is required")
    return value.strip()


def _validate_handshake_info(info: dict[str, Any]) -> None:
    _required_handshake_string(info, "name")
    _required_handshake_string(info, "version")
    module_type = _required_handshake_string(info, "moduleType")
    if module_type not in _MODULE_TYPES:
        raise ValueError(f"module handshake moduleType {module_type!r} is invalid")
