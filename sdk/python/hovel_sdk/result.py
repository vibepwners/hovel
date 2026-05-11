from __future__ import annotations

import json
from dataclasses import dataclass, field
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
class Result:
    status: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    outputs: dict[str, Any] = field(default_factory=dict)
    sessions: list[SessionRef] = field(default_factory=list)

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

    def to_rpc(self, *, sessions: list[SessionRef] | None = None) -> dict[str, Any]:
        session_refs = list(self.sessions)
        if sessions:
            seen = {session.id for session in session_refs}
            session_refs.extend(session for session in sessions if session.id not in seen)
        return {
            "status": self.status,
            "summary": self.summary,
            "findings": [finding.to_rpc() for finding in self.findings],
            "artifacts": [artifact.to_rpc() for artifact in self.artifacts],
            "outputs": dict(self.outputs),
            "sessions": [session.to_rpc() for session in session_refs],
        }
