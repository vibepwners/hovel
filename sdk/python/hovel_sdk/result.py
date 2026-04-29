from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    data: str

    def to_rpc(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "data": self.data}


@dataclass(frozen=True)
class Result:
    status: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    outputs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(
        cls,
        outputs: dict[str, Any] | None = None,
        *,
        summary: str = "module completed",
        findings: list[Finding] | None = None,
        artifacts: list[Artifact] | None = None,
    ) -> Result:
        return cls(
            status="succeeded",
            summary=summary,
            findings=findings or [],
            artifacts=artifacts or [],
            outputs=outputs or {},
        )

    @classmethod
    def failed(
        cls,
        summary: str,
        *,
        findings: list[Finding] | None = None,
        artifacts: list[Artifact] | None = None,
        outputs: dict[str, Any] | None = None,
    ) -> Result:
        return cls(
            status="failed",
            summary=summary,
            findings=findings or [],
            artifacts=artifacts or [],
            outputs=outputs or {},
        )

    def to_rpc(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "summary": self.summary,
            "findings": [finding.to_rpc() for finding in self.findings],
            "artifacts": [artifact.to_rpc() for artifact in self.artifacts],
            "outputs": dict(self.outputs),
        }
