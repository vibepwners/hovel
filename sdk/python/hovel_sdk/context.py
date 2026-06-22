from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hovel_sdk.session import Session, SessionRef

if TYPE_CHECKING:
    from hovel_sdk.session import SessionRegistry


@dataclass(frozen=True)
class AgentEntity:
    id: str = ""
    kind: str = ""
    display_name: str = ""
    agent: bool = False

    @classmethod
    def from_rpc(cls, value: Any) -> AgentEntity:
        if not isinstance(value, dict):
            return cls()
        return cls(
            id=str(value.get("id", "")),
            kind=str(value.get("kind", "")),
            display_name=str(value.get("displayName", "")),
            agent=bool(value.get("agent", False)),
        )


@dataclass(frozen=True)
class AgentContext:
    schema: str = ""
    entity: AgentEntity = field(default_factory=AgentEntity)
    operation: str = ""
    chain: str = ""
    plan_id: str = ""
    plan_hash: str = ""
    approval_state: str = ""
    phase: str = ""
    resources: tuple[str, ...] = ()

    @classmethod
    def from_rpc(cls, value: Any) -> AgentContext | None:
        if not isinstance(value, dict):
            return None
        resources = value.get("resources") or ()
        if not isinstance(resources, (list, tuple)):
            resources = ()
        return cls(
            schema=str(value.get("schema", "")),
            entity=AgentEntity.from_rpc(value.get("entity")),
            operation=str(value.get("operation", "")),
            chain=str(value.get("chain", "")),
            plan_id=str(value.get("planId", "")),
            plan_hash=str(value.get("planHash", "")),
            approval_state=str(value.get("approvalState", "")),
            phase=str(value.get("phase", "")),
            resources=tuple(str(item) for item in resources),
        )


@dataclass(frozen=True)
class Context:
    run_id: str
    module_id: str
    target: str
    inputs: dict[str, Any] = field(default_factory=dict)
    chain_config: dict[str, Any] = field(default_factory=dict)
    target_config: dict[str, Any] = field(default_factory=dict)
    agent: AgentContext | None = None
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("hovel.module"))
    sessions: SessionRegistry | None = field(default=None, repr=False)

    def input(self, key: str, default: Any = None) -> Any:
        if key in self.inputs:
            return self.inputs[key]
        if key in self.target_config:
            return self.target_config[key]
        return self.chain_config.get(key, default)

    async def open_session(
        self,
        session: Session,
        *,
        name: str = "",
        kind: str = "shell",
        transport: str = "stdio",
        capabilities: tuple[str, ...] = ("read", "write", "close"),
    ) -> SessionRef:
        if self.sessions is None:
            raise RuntimeError("session support is not available in this runtime")
        return await self.sessions.open(
            session,
            name=name,
            kind=kind,
            transport=transport,
            capabilities=capabilities,
        )
