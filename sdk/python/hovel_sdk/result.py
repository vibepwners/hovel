from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from hovel_sdk.session import SessionRef


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str = "info"
    detail: str = ""

    def to_rpc(self) -> dict[str, Any]:
        return {"title": self.title, "severity": self.severity, "detail": self.detail}


@dataclass(frozen=True)
class Artifact:
    name: str
    kind: str
    data: str = ""
    path: str = ""

    @classmethod
    def inline(cls, name: str, kind: str, data: str | bytes) -> Artifact:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        return cls(name=name, kind=kind, data=data)

    @classmethod
    def text(cls, name: str, data: str | bytes) -> Artifact:
        return cls.inline(name, "text/plain", data)

    @classmethod
    def json(cls, name: str, data: Any) -> Artifact:
        return cls.inline(name, "application/json", json.dumps(data, sort_keys=True, separators=(",", ":")))

    @classmethod
    def file(cls, path: str | Path, *, name: str | None = None, kind: str = "application/octet-stream") -> Artifact:
        path = Path(path)
        return cls(name=name or path.name, kind=kind, path=str(path))

    def to_rpc(self) -> dict[str, Any]:
        out = {"name": self.name, "kind": self.kind}
        if self.data:
            out["data"] = self.data
        if self.path:
            out["path"] = self.path
        return out


@dataclass(frozen=True)
class PayloadProviderRecord:
    schema: str = ""
    descriptor: dict[str, Any] = field(default_factory=dict)
    config: dict[str, str] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.schema:
            out["schema"] = self.schema
        if self.descriptor:
            out["descriptor"] = dict(self.descriptor)
        if self.config:
            out["config"] = dict(self.config)
        return out


@dataclass(frozen=True)
class InstalledPayload:
    provider: str
    payload_id: str
    target: str
    state: str
    payload_version: str = ""
    target_id: str = ""
    transport: str = ""
    endpoint: str = ""
    instance_key: str = ""
    stamp_id: str = ""
    supports_reconnect: bool = False
    supports_multiple_sessions: bool = False
    reconnect: PayloadProviderRecord | None = None
    cleanup: PayloadProviderRecord | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "provider": self.provider,
            "payloadId": self.payload_id,
            "target": self.target,
            "state": self.state,
        }
        optional_strings = {
            "payloadVersion": self.payload_version,
            "targetId": self.target_id,
            "transport": self.transport,
            "endpoint": self.endpoint,
            "instanceKey": self.instance_key,
            "stampId": self.stamp_id,
        }
        out.update({key: value for key, value in optional_strings.items() if value})
        if self.supports_reconnect:
            out["supportsReconnect"] = True
        if self.supports_multiple_sessions:
            out["supportsMultipleSessions"] = True
        if self.reconnect is not None:
            out["reconnect"] = self.reconnect.to_rpc()
        if self.cleanup is not None:
            out["cleanup"] = self.cleanup.to_rpc()
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out


@dataclass(frozen=True)
class Result:
    status: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    outputs: dict[str, Any] = field(default_factory=dict)
    sessions: list[SessionRef] = field(default_factory=list)
    installed_payloads: list[InstalledPayload | dict[str, Any]] = field(default_factory=list)

    @classmethod
    def ok(
        cls,
        outputs: dict[str, Any] | None = None,
        *,
        summary: str = "module completed",
        findings: list[Finding] | None = None,
        artifacts: list[Artifact] | None = None,
        sessions: list[SessionRef] | None = None,
    ) -> Result:
        return cls(
            status="succeeded",
            summary=summary,
            findings=findings or [],
            artifacts=artifacts or [],
            outputs=outputs or {},
            sessions=sessions or [],
        )

    @classmethod
    def failed(
        cls,
        summary: str,
        *,
        findings: list[Finding] | None = None,
        artifacts: list[Artifact] | None = None,
        outputs: dict[str, Any] | None = None,
        sessions: list[SessionRef] | None = None,
    ) -> Result:
        return cls(
            status="failed",
            summary=summary,
            findings=findings or [],
            artifacts=artifacts or [],
            outputs=outputs or {},
            sessions=sessions or [],
        )

    def with_installed_payloads(self, *payloads: InstalledPayload | dict[str, Any]) -> Result:
        return replace(self, installed_payloads=[*self.installed_payloads, *payloads])

    def to_rpc(self, *, sessions: list[SessionRef] | None = None) -> dict[str, Any]:
        session_refs = list(self.sessions)
        if sessions:
            seen = {session.id for session in session_refs}
            session_refs.extend(session for session in sessions if session.id not in seen)
        out = {
            "status": self.status,
            "summary": self.summary,
            "findings": [finding.to_rpc() for finding in self.findings],
            "artifacts": [artifact.to_rpc() for artifact in self.artifacts],
            "outputs": dict(self.outputs),
            "sessions": [session.to_rpc() for session in session_refs],
        }
        if self.installed_payloads:
            out["installedPayloads"] = [
                payload.to_rpc() if hasattr(payload, "to_rpc") else dict(payload)
                for payload in self.installed_payloads
            ]
        return out
