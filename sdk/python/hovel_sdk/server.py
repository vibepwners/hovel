from __future__ import annotations

import asyncio
import inspect
import logging
import sys
from typing import Any, BinaryIO, cast

from hovel_sdk.context import AgentContext, Context
from hovel_sdk.credential_delivery import _CREDENTIAL_RPC_DESCRIBE_METHOD, CredentialDeliveryDescriptor
from hovel_sdk.credential_provider import (
    _CREDENTIAL_RPC_ENCODE_METHOD,
    _CREDENTIAL_RPC_FILES_METHOD,
    _CREDENTIAL_RPC_PREFIX,
    _CREDENTIAL_RPC_RUNTIME_METHOD,
    _CREDENTIAL_RPC_STAMP_METHOD,
    CredentialDeliveryReceipt,
    CredentialEncodingRequest,
    CredentialEncodingResult,
    CredentialFilesRequest,
    CredentialRuntimeRequest,
    CredentialStampExecutionRequest,
    CredentialStampExecutionResult,
)
from hovel_sdk.framing import FrameError, MessageWriter, read_message
from hovel_sdk.logging import setup_logging
from hovel_sdk.mesh import (
    _DEFAULT_MESH_RUN_ID,
    _MESH_RPC_BEACONS_METHOD,
    _MESH_RPC_DESCRIBE_METHOD,
    _MESH_RPC_LISTENER_START_METHOD,
    _MESH_RPC_LISTENER_STOP_METHOD,
    _MESH_RPC_LISTENERS_METHOD,
    _MESH_RPC_OPEN_STREAM_METHOD,
    _MESH_RPC_PREFIX,
    _MESH_RPC_TASK_METHOD,
    _MESH_RPC_TOPOLOGY_METHOD,
    MESH_TASK_STATUS_SUCCEEDED,
    MeshBeacon,
    MeshBeaconRequest,
    MeshDescribeRequest,
    MeshListener,
    MeshListenerListRequest,
    MeshListenerStartRequest,
    MeshListenerStopRequest,
    MeshStreamRequest,
    MeshTaskRequest,
    MeshTaskResult,
    MeshTopologyRequest,
)
from hovel_sdk.module import HovelModule
from hovel_sdk.session import SessionManager, SessionRef

_MODULE_TYPES = {"survey", "exploit", "payload_provider"}
_MESH_LISTENER_METHODS = {
    _MESH_RPC_LISTENERS_METHOD,
    _MESH_RPC_LISTENER_START_METHOD,
    _MESH_RPC_LISTENER_STOP_METHOD,
}


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
            result = info
        elif method == "schema":
            result = self._module.module_schema()
        elif method.startswith(_MESH_RPC_PREFIX):
            result = self._loop.run_until_complete(self._dispatch_mesh(method, params))
        elif method.startswith(_CREDENTIAL_RPC_PREFIX):
            result = self._loop.run_until_complete(self._dispatch_credential(method, params))
        elif method.startswith("step."):
            result = self._dispatch_step(method, params)
        elif method == "execute":
            result = self._loop.run_until_complete(self._execute(params))
        elif method.startswith("session/"):
            result = self._loop.run_until_complete(self._dispatch_session(method, params))
        elif method == "shutdown":
            self._loop.run_until_complete(self._sessions.close_all())
            result = {"status": "ok"}
        else:
            raise ValueError(f"unknown method {method!r}")
        return result

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

    async def _dispatch_mesh(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == _MESH_RPC_DESCRIBE_METHOD:
            descriptor = await _resolve(self._module.describe_mesh(MeshDescribeRequest.from_rpc(params)))
            return descriptor.to_rpc() if hasattr(descriptor, "to_rpc") else dict(descriptor)
        if method == _MESH_RPC_TOPOLOGY_METHOD:
            topology = await _resolve(self._module.mesh_topology(MeshTopologyRequest.from_rpc(params)))
            return topology.to_rpc() if hasattr(topology, "to_rpc") else dict(topology)
        if method == _MESH_RPC_BEACONS_METHOD:
            beacons = await _resolve(self._module.list_mesh_beacons(MeshBeaconRequest.from_rpc(params)))
            return {"beacons": [_mesh_beacon_to_rpc(beacon) for beacon in beacons]}
        if method in _MESH_LISTENER_METHODS:
            return await self._dispatch_mesh_listener(method, params)
        if method == _MESH_RPC_TASK_METHOD:
            return await self._run_mesh_task(params)
        if method == _MESH_RPC_OPEN_STREAM_METHOD:
            return await self._open_mesh_stream(params)
        raise ValueError(f"unknown method {method!r}")

    async def _dispatch_mesh_listener(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == _MESH_RPC_LISTENERS_METHOD:
            listeners = await _resolve(self._module.list_mesh_listeners(MeshListenerListRequest.from_rpc(params)))
            return {"listeners": [_mesh_listener_to_rpc(listener) for listener in listeners]}
        if method == _MESH_RPC_LISTENER_START_METHOD:
            start_request = MeshListenerStartRequest.from_rpc(params)
            requested_id = _required_mesh_listener_id(start_request.listener_id)
            return _mesh_listener_lifecycle_to_rpc(
                requested_id,
                await _resolve(self._module.start_mesh_listener(start_request)),
            )
        if method == _MESH_RPC_LISTENER_STOP_METHOD:
            stop_request = MeshListenerStopRequest.from_rpc(params)
            requested_id = _required_mesh_listener_id(stop_request.listener_id)
            return _mesh_listener_lifecycle_to_rpc(
                requested_id,
                await _resolve(self._module.stop_mesh_listener(stop_request)),
            )
        raise ValueError(f"unknown method {method!r}")

    async def _dispatch_credential(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == _CREDENTIAL_RPC_DESCRIBE_METHOD:
            descriptor = cast(
                "CredentialDeliveryDescriptor",
                await _resolve(self._module.describe_credential_delivery()),
            )
            return descriptor.to_rpc()
        if method == _CREDENTIAL_RPC_RUNTIME_METHOD:
            runtime_request = CredentialRuntimeRequest.from_rpc(params)
            receipt = cast(
                "CredentialDeliveryReceipt",
                await _resolve(self._module.load_runtime_credential(runtime_request)),
            )
            receipt.validate_for(runtime_request.request_id)
            return receipt.to_rpc()
        if method == _CREDENTIAL_RPC_FILES_METHOD:
            files_request = CredentialFilesRequest.from_rpc(params)
            files_receipt = cast(
                "CredentialDeliveryReceipt",
                await _resolve(self._module.load_credential_files(files_request)),
            )
            files_receipt.validate_for(files_request.request_id)
            return files_receipt.to_rpc()
        if method == _CREDENTIAL_RPC_ENCODE_METHOD:
            encoding_request = CredentialEncodingRequest.from_rpc(params)
            encoding_result = cast(
                "CredentialEncodingResult",
                await _resolve(self._module.encode_credential_material(encoding_request)),
            )
            encoding_result.validate_for(encoding_request)
            return encoding_result.to_rpc()
        if method == _CREDENTIAL_RPC_STAMP_METHOD:
            stamp_request = CredentialStampExecutionRequest.from_rpc(params)
            stamp_result = cast(
                "CredentialStampExecutionResult",
                await _resolve(self._module.stamp_credential(stamp_request)),
            )
            stamp_result.validate_for(stamp_request)
            return stamp_result.to_rpc()
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

    async def _run_mesh_task(self, params: dict[str, Any]) -> dict[str, Any]:
        request = MeshTaskRequest.from_rpc(params)
        ctx = self._mesh_context(params)
        result = await _resolve(self._module.run_mesh_task(ctx, request))
        if isinstance(result, MeshTaskResult):
            return result.to_rpc(sessions=ctx.sessions.refs() if ctx.sessions is not None else [])
        out = dict(result)
        status = out.get("status")
        if status is None:
            out["status"] = MESH_TASK_STATUS_SUCCEEDED
        elif isinstance(status, str):
            out["status"] = status.strip() or MESH_TASK_STATUS_SUCCEEDED
        _merge_rpc_sessions(out, ctx.sessions.refs() if ctx.sessions is not None else [])
        return out

    async def _open_mesh_stream(self, params: dict[str, Any]) -> dict[str, Any]:
        request = MeshStreamRequest.from_rpc(params)
        ctx = self._mesh_context(params)
        session = await _resolve(self._module.open_mesh_stream(ctx, request))
        return session.to_rpc() if isinstance(session, SessionRef) else dict(session)

    def _mesh_context(self, params: dict[str, Any]) -> Context:
        context_params = self._mesh_context_params(params)
        run_id = str(context_params.get("runId", ""))
        module_id = str(context_params.get("moduleId", self._module.name))
        target = str(context_params.get("target", ""))
        config = context_params.get("config") or {}
        sessions = self._sessions.for_run(run_id=run_id, module_id=module_id, target=target)
        return Context(
            run_id=run_id,
            module_id=module_id,
            target=target,
            inputs=dict(config) if isinstance(config, dict) else {},
            agent=AgentContext.from_rpc(context_params.get("agentContext")),
            log=logging.getLogger(self._module.name or "hovel.module"),
            sessions=sessions,
        )

    def _mesh_context_params(self, params: dict[str, Any]) -> dict[str, Any]:
        out = dict(params)
        if not _nonblank_string(out.get("moduleId")):
            out["moduleId"] = _mesh_module_id(self._module)
        if not _nonblank_string(out.get("runId")):
            out["runId"] = _DEFAULT_MESH_RUN_ID
        if not _nonblank_string(out.get("target")) and _nonblank_string(out.get("destinationHost")):
            out["target"] = out["destinationHost"]
        if not _nonblank_string(out.get("target")) and _nonblank_string(out.get("nodeId")):
            out["target"] = out["nodeId"]
        return out

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


def _mesh_listener_to_rpc(listener: MeshListener | dict[str, Any]) -> dict[str, Any]:
    out = listener.to_rpc() if isinstance(listener, MeshListener) else dict(listener)
    if "config" in out:
        raise ValueError("mesh listener results must not include config")
    return out


def _mesh_listener_lifecycle_to_rpc(
    requested_id: str,
    listener: MeshListener | dict[str, Any],
) -> dict[str, Any]:
    requested_id = _required_mesh_listener_id(requested_id)
    out = _mesh_listener_to_rpc(listener)
    raw_listener_id = out.get("id")
    listener_id = raw_listener_id.strip() if isinstance(raw_listener_id, str) else ""
    if not listener_id:
        raise ValueError("mesh listener result id is required")
    if listener_id != requested_id:
        raise ValueError(f"mesh listener result id {listener_id!r} does not match requested id {requested_id!r}")
    out["id"] = listener_id
    return out


def _required_mesh_listener_id(listener_id: str) -> str:
    listener_id = listener_id.strip()
    if not listener_id:
        raise ValueError("mesh listener listenerId is required")
    return listener_id


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


def _nonblank_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _mesh_module_id(module: HovelModule) -> str:
    name = module.name.strip()
    version = module.version.strip()
    return f"{name}@{version}" if version else name


async def _resolve(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _mesh_beacon_to_rpc(beacon: MeshBeacon | dict[str, Any]) -> dict[str, Any]:
    return beacon.to_rpc() if hasattr(beacon, "to_rpc") else dict(beacon)


def _merge_rpc_sessions(out: dict[str, Any], sessions: list[SessionRef]) -> None:
    if not sessions:
        return
    existing = out.get("sessions")
    if not isinstance(existing, list):
        out["sessions"] = [session.to_rpc() for session in sessions]
        return
    seen = {session.get("id") for session in existing if isinstance(session, dict)}
    existing.extend(session.to_rpc() for session in sessions if session.id not in seen)
