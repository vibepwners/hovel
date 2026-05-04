from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

_TIMEOUT_ERRORS = (asyncio.TimeoutError,)


@dataclass(frozen=True)
class SessionRef:
    id: str
    run_id: str
    module_id: str
    target: str
    name: str = ""
    kind: str = "shell"
    state: str = "active"
    transport: str = "stdio"
    capabilities: tuple[str, ...] = ("read", "write", "close")

    def to_rpc(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "runId": self.run_id,
            "moduleId": self.module_id,
            "target": self.target,
            "name": self.name,
            "kind": self.kind,
            "state": self.state,
            "transport": self.transport,
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True)
class SessionScope:
    run_id: str
    module_id: str
    target: str


@dataclass(frozen=True)
class SessionOpenOptions:
    name: str = ""
    kind: str = "shell"
    transport: str = "stdio"
    capabilities: tuple[str, ...] = ("read", "write", "close")


class Session(Protocol):
    @property
    def closed(self) -> bool:
        raise NotImplementedError

    async def open(self) -> None:
        raise NotImplementedError

    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    async def read(self, wait: float | None = None) -> bytes:
        raise NotImplementedError

    async def close(self, reason: str = "closed") -> None:
        raise NotImplementedError


class LineShellSession:
    """Small async shell base class for modules that can answer line commands."""

    def __init__(self, *, prompt: str = "$ ", echo: bool = False) -> None:
        self.prompt = prompt
        self.echo = echo
        self._buffer = bytearray()
        self._output: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def open(self) -> None:
        await self.emit(self.prompt)

    async def write(self, data: bytes) -> None:
        if self._closed:
            return
        if self.echo and data:
            await self.emit(data)
        self._buffer.extend(data)
        while b"\n" in self._buffer:
            line, _, remaining = self._buffer.partition(b"\n")
            self._buffer = bytearray(remaining)
            command = line.rstrip(b"\r").decode("utf-8", errors="replace").strip()
            await self._handle_line(command)

    async def read(self, wait: float | None = None) -> bytes:
        try:
            if wait is None:
                chunk = await self._output.get()
            else:
                chunk = await asyncio.wait_for(self._output.get(), timeout=wait)
        except _TIMEOUT_ERRORS:
            return b""
        return chunk or b""

    async def close(self, reason: str = "closed") -> None:
        _ = reason
        if self._closed:
            return
        self._closed = True
        await self._output.put(None)

    async def emit(self, data: str | bytes) -> None:
        if isinstance(data, str):
            data = data.encode()
        await self._output.put(data)

    async def handle_command(self, command: str) -> str | bytes | None:
        raise NotImplementedError

    async def _handle_line(self, command: str) -> None:
        if command in {"exit", "logout"}:
            await self.close("operator requested close")
            return
        if command == "":
            await self.emit(self.prompt)
            return

        output = await self.handle_command(command)
        if isinstance(output, str):
            output = output.encode()
        if output:
            if not output.endswith(b"\n"):
                output += b"\n"
            await self.emit(output)
        if not self._closed:
            await self.emit(self.prompt)


@dataclass
class _ManagedSession:
    ref: SessionRef
    session: Session


class SessionManager:
    def __init__(self, emit_event: Callable[[dict[str, Any]], None] | None = None) -> None:
        self._emit_event = emit_event
        self._sessions: dict[str, _ManagedSession] = {}
        self._next = 0

    def for_run(self, *, run_id: str, module_id: str, target: str) -> SessionRegistry:
        return SessionRegistry(self, scope=SessionScope(run_id=run_id, module_id=module_id, target=target))

    async def write_rpc(self, params: dict[str, Any]) -> dict[str, Any]:
        session_id = str(params.get("sessionId", ""))
        encoded = str(params.get("data", ""))
        await self.write(session_id, base64.b64decode(encoded.encode()))
        return {"status": "ok"}

    async def read_rpc(self, params: dict[str, Any]) -> dict[str, Any]:
        session_id = str(params.get("sessionId", ""))
        timeout_ms = float(params.get("timeoutMs", 1000))
        timeout = timeout_ms / 1000 if timeout_ms >= 0 else None
        chunk = await self.read(session_id, wait=timeout)
        ref = self._session(session_id).ref
        return {
            "sessionId": session_id,
            "data": base64.b64encode(chunk).decode(),
            "closed": ref.state == "closed",
        }

    async def close_rpc(self, params: dict[str, Any]) -> dict[str, Any]:
        session_id = str(params.get("sessionId", ""))
        reason = str(params.get("reason", "closed"))
        await self.close(session_id, reason=reason)
        return {"status": "ok"}

    async def close_all(self, reason: str = "shutdown") -> None:
        for session_id in list(self._sessions):
            await self.close(session_id, reason=reason)

    async def open(
        self,
        session: Session,
        *,
        scope: SessionScope,
        options: SessionOpenOptions,
    ) -> SessionRef:
        self._next += 1
        session_id = f"{scope.run_id}-session-{self._next}"
        ref = SessionRef(
            id=session_id,
            run_id=scope.run_id,
            module_id=scope.module_id,
            target=scope.target,
            name=options.name,
            kind=options.kind,
            transport=options.transport,
            capabilities=options.capabilities,
        )
        self._sessions[session_id] = _ManagedSession(ref=ref, session=session)
        await session.open()
        self._emit("session.created", ref)
        return ref

    async def write(self, session_id: str, data: bytes) -> None:
        await self._session(session_id).session.write(data)

    async def read(self, session_id: str, *, wait: float | None = None) -> bytes:
        managed = self._session(session_id)
        chunk = await managed.session.read(wait=wait)
        if managed.session.closed and managed.ref.state != "closed":
            self._mark_closed(session_id, "closed")
        return chunk

    async def close(self, session_id: str, *, reason: str = "closed") -> None:
        managed = self._session(session_id)
        await managed.session.close(reason=reason)
        self._mark_closed(session_id, reason)

    def refs_for_run(self, run_id: str) -> list[SessionRef]:
        return [managed.ref for managed in self._sessions.values() if managed.ref.run_id == run_id]

    def _session(self, session_id: str) -> _ManagedSession:
        if session_id not in self._sessions:
            raise ValueError(f"unknown session {session_id!r}")
        return self._sessions[session_id]

    def _mark_closed(self, session_id: str, reason: str) -> None:
        managed = self._session(session_id)
        if managed.ref.state == "closed":
            return
        managed.ref = SessionRef(
            id=managed.ref.id,
            run_id=managed.ref.run_id,
            module_id=managed.ref.module_id,
            target=managed.ref.target,
            name=managed.ref.name,
            kind=managed.ref.kind,
            state="closed",
            transport=managed.ref.transport,
            capabilities=managed.ref.capabilities,
        )
        self._emit("session.closed", managed.ref, {"reason": reason})

    def _emit(self, event: str, ref: SessionRef, fields: dict[str, Any] | None = None) -> None:
        if self._emit_event is None:
            return
        params = {"event": event, "session": ref.to_rpc()}
        if fields:
            params["fields"] = fields
        self._emit_event(params)


class SessionRegistry:
    def __init__(self, manager: SessionManager, *, scope: SessionScope) -> None:
        self._manager = manager
        self._scope = scope

    async def open(
        self,
        session: Session,
        *,
        name: str = "",
        kind: str = "shell",
        transport: str = "stdio",
        capabilities: tuple[str, ...] = ("read", "write", "close"),
    ) -> SessionRef:
        return await self._manager.open(
            session,
            scope=self._scope,
            options=SessionOpenOptions(
                name=name,
                kind=kind,
                transport=transport,
                capabilities=capabilities,
            ),
        )

    def refs(self) -> list[SessionRef]:
        return self._manager.refs_for_run(self._scope.run_id)
