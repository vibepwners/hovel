from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hovel_sdk.context import AgentContext
from hovel_sdk.result import AgentHint, Artifact, Finding
from hovel_sdk.session import SessionRef

MESH_TASK_SURVEY = "survey"
MESH_TASK_UPLOAD = "upload"
MESH_TASK_EXECUTE = "execute"
MESH_TASK_UPLOAD_EXECUTE = "upload_execute"
MESH_TASK_COMMAND = "command"
MESH_TASK_LOAD = "load"
MESH_TASK_STREAM = "stream"

MESH_TARGET_NODE = "node"
MESH_TARGET_ROUTE = "route"
MESH_TARGET_DESTINATION = "destination"


@dataclass(frozen=True)
class MeshNode:
    id: str
    parent_id: str = ""
    name: str = ""
    kind: str = ""
    state: str = ""
    address: str = ""
    platform: str = ""
    os: str = ""
    arch: str = ""
    labels: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    last_seen: str = ""

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id}
        _put_string(out, "parentId", self.parent_id)
        _put_string(out, "name", self.name)
        _put_string(out, "kind", self.kind)
        _put_string(out, "state", self.state)
        _put_string(out, "address", self.address)
        _put_string(out, "platform", self.platform)
        _put_string(out, "os", self.os)
        _put_string(out, "arch", self.arch)
        _put_dict(out, "labels", self.labels)
        _put_dict(out, "attributes", self.attributes)
        _put_list(out, "capabilities", self.capabilities)
        _put_string(out, "lastSeen", self.last_seen)
        return out


@dataclass(frozen=True)
class MeshLink:
    id: str
    source: str
    target: str
    kind: str = ""
    state: str = ""
    transport: str = ""
    cost: int = 0
    latency_ms: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "source": self.source,
            "target": self.target,
        }
        _put_string(out, "kind", self.kind)
        _put_string(out, "state", self.state)
        _put_string(out, "transport", self.transport)
        _put_int(out, "cost", self.cost)
        _put_int(out, "latencyMs", self.latency_ms)
        _put_dict(out, "attributes", self.attributes)
        return out


@dataclass(frozen=True)
class MeshRoute:
    nodes: list[str]
    id: str = ""
    links: list[str] = field(default_factory=list)
    cost: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_rpc(cls, value: Any) -> MeshRoute | None:
        if not isinstance(value, dict):
            return None
        return cls(
            id=str(value.get("id", "")),
            nodes=_string_list(value.get("nodes")),
            links=_string_list(value.get("links")),
            cost=_int_value(value.get("cost")),
            attributes=_dict_value(value.get("attributes")),
        )

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _put_string(out, "id", self.id)
        _put_list(out, "nodes", self.nodes)
        _put_list(out, "links", self.links)
        _put_int(out, "cost", self.cost)
        _put_dict(out, "attributes", self.attributes)
        return out


@dataclass(frozen=True)
class MeshTopology:
    root: str = ""
    nodes: list[MeshNode] = field(default_factory=list)
    links: list[MeshLink] = field(default_factory=list)
    routes: list[MeshRoute] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _put_string(out, "root", self.root)
        if self.nodes:
            out["nodes"] = [node.to_rpc() for node in self.nodes]
        if self.links:
            out["links"] = [link.to_rpc() for link in self.links]
        if self.routes:
            out["routes"] = [route.to_rpc() for route in self.routes]
        _put_dict(out, "attributes", self.attributes)
        return out


@dataclass(frozen=True)
class MeshTaskSpec:
    kind: str
    summary: str = ""
    config_schema: dict[str, Any] = field(default_factory=dict)
    read_only: bool = False
    destructive: bool = False
    opens_stream: bool = False
    target_scopes: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        _put_string(out, "summary", self.summary)
        _put_dict(out, "configSchema", self.config_schema)
        _put_bool(out, "readOnly", value=self.read_only)
        _put_bool(out, "destructive", value=self.destructive)
        _put_bool(out, "opensStream", value=self.opens_stream)
        _put_list(out, "targetScopes", self.target_scopes)
        _put_list(out, "capabilities", self.capabilities)
        return out


@dataclass(frozen=True)
class MeshTrigger:
    id: str
    name: str = ""
    kind: str = ""
    node_id: str = ""
    state: str = ""
    expression: str = ""
    schedule: str = ""
    action_kind: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    last_fired: str = ""

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id}
        _put_string(out, "name", self.name)
        _put_string(out, "kind", self.kind)
        _put_string(out, "nodeId", self.node_id)
        _put_string(out, "state", self.state)
        _put_string(out, "expression", self.expression)
        _put_string(out, "schedule", self.schedule)
        _put_string(out, "actionKind", self.action_kind)
        _put_dict(out, "config", self.config)
        _put_string(out, "lastFired", self.last_fired)
        return out


@dataclass(frozen=True)
class MeshBeacon:
    id: str
    node_id: str
    time: str = ""
    state: str = ""
    transport: str = ""
    remote_addr: str = ""
    interval_seconds: int = 0
    fields: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "nodeId": self.node_id,
        }
        _put_string(out, "time", self.time)
        _put_string(out, "state", self.state)
        _put_string(out, "transport", self.transport)
        _put_string(out, "remoteAddr", self.remote_addr)
        _put_int(out, "intervalSeconds", self.interval_seconds)
        _put_dict(out, "fields", self.fields)
        return out


@dataclass(frozen=True)
class MeshDescriptor:
    name: str = ""
    version: str = ""
    summary: str = ""
    capabilities: list[str] = field(default_factory=list)
    topology: MeshTopology | None = None
    tasks: list[MeshTaskSpec] = field(default_factory=list)
    triggers: list[MeshTrigger] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _put_string(out, "name", self.name)
        _put_string(out, "version", self.version)
        _put_string(out, "summary", self.summary)
        _put_list(out, "capabilities", self.capabilities)
        if self.topology is not None:
            out["topology"] = self.topology.to_rpc()
        if self.tasks:
            out["tasks"] = [task.to_rpc() for task in self.tasks]
        if self.triggers:
            out["triggers"] = [trigger.to_rpc() for trigger in self.triggers]
        _put_dict(out, "attributes", self.attributes)
        return out


@dataclass(frozen=True)
class MeshDescribeRequest:
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshDescribeRequest:
        return cls(agent=AgentContext.from_rpc(value.get("agentContext")))


@dataclass(frozen=True)
class MeshTopologyRequest:
    root: str = ""
    include_routes: bool = False
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshTopologyRequest:
        return cls(
            root=str(value.get("root", "")),
            include_routes=bool(value.get("includeRoutes", False)),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshBeaconRequest:
    node_id: str = ""
    since: str = ""
    limit: int = 0
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshBeaconRequest:
        return cls(
            node_id=str(value.get("nodeId", "")),
            since=str(value.get("since", "")),
            limit=_int_value(value.get("limit")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshTaskRequest:
    kind: str
    run_id: str = ""
    task_id: str = ""
    node_id: str = ""
    target: str = ""
    route: MeshRoute | None = None
    destination_host: str = ""
    destination_port: int = 0
    protocol: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    args: list[str] = field(default_factory=list)
    input_data: str = ""
    input_encoding: str = ""
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshTaskRequest:
        return cls(
            run_id=str(value.get("runId", "")),
            task_id=str(value.get("taskId", "")),
            kind=str(value.get("kind", "")),
            node_id=str(value.get("nodeId", "")),
            target=str(value.get("target", "")),
            route=MeshRoute.from_rpc(value.get("route")),
            destination_host=str(value.get("destinationHost", "")),
            destination_port=_int_value(value.get("destinationPort")),
            protocol=str(value.get("protocol", "")),
            config=_dict_value(value.get("config")),
            args=_string_list(value.get("args")),
            input_data=str(value.get("inputData", "")),
            input_encoding=str(value.get("inputEncoding", "")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshEvent:
    kind: str
    id: str = ""
    node_id: str = ""
    level: str = ""
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _put_string(out, "id", self.id)
        _put_string(out, "kind", self.kind)
        _put_string(out, "nodeId", self.node_id)
        _put_string(out, "level", self.level)
        _put_string(out, "message", self.message)
        _put_dict(out, "fields", self.fields)
        return out


@dataclass(frozen=True)
class MeshTaskResult:
    status: str = "succeeded"
    summary: str = ""
    task_id: str = ""
    node_id: str = ""
    route: MeshRoute | None = None
    destination_host: str = ""
    destination_port: int = 0
    protocol: str = ""
    outputs: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    sessions: list[SessionRef] = field(default_factory=list)
    beacons: list[MeshBeacon] = field(default_factory=list)
    events: list[MeshEvent] = field(default_factory=list)
    agent_hints: list[AgentHint | dict[str, Any]] = field(default_factory=list)

    @classmethod
    def succeeded(cls, summary: str) -> MeshTaskResult:
        return cls(status="succeeded", summary=summary)

    def to_rpc(self, *, sessions: list[SessionRef] | None = None) -> dict[str, Any]:
        session_refs = _merge_session_refs(self.sessions, sessions or [])
        out: dict[str, Any] = {
            "status": self.status or "succeeded",
        }
        _put_string(out, "summary", self.summary)
        _put_string(out, "taskId", self.task_id)
        _put_string(out, "nodeId", self.node_id)
        if self.route is not None:
            out["route"] = self.route.to_rpc()
        _put_string(out, "destinationHost", self.destination_host)
        _put_int(out, "destinationPort", self.destination_port)
        _put_string(out, "protocol", self.protocol)
        _put_dict(out, "outputs", self.outputs)
        if self.findings:
            out["findings"] = [finding.to_rpc() for finding in self.findings]
        if self.artifacts:
            out["artifacts"] = [artifact.to_rpc() for artifact in self.artifacts]
        if session_refs:
            out["sessions"] = [session.to_rpc() for session in session_refs]
        if self.beacons:
            out["beacons"] = [beacon.to_rpc() for beacon in self.beacons]
        if self.events:
            out["events"] = [event.to_rpc() for event in self.events]
        if self.agent_hints:
            out["agentHints"] = [
                hint.to_rpc() if hasattr(hint, "to_rpc") else dict(hint)
                for hint in self.agent_hints
            ]
        return out


@dataclass(frozen=True)
class MeshStreamRequest:
    run_id: str = ""
    module_id: str = ""
    target: str = ""
    node_id: str = ""
    route: MeshRoute | None = None
    destination_host: str = ""
    destination_port: int = 0
    protocol: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshStreamRequest:
        return cls(
            run_id=str(value.get("runId", "")),
            module_id=str(value.get("moduleId", "")),
            target=str(value.get("target", "")),
            node_id=str(value.get("nodeId", "")),
            route=MeshRoute.from_rpc(value.get("route")),
            destination_host=str(value.get("destinationHost", "")),
            destination_port=_int_value(value.get("destinationPort")),
            protocol=str(value.get("protocol", "")),
            config=_dict_value(value.get("config")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


def _merge_session_refs(explicit: list[SessionRef], opened: list[SessionRef]) -> list[SessionRef]:
    refs = list(explicit)
    seen = {ref.id for ref in refs}
    refs.extend(ref for ref in opened if ref.id and ref.id not in seen)
    return refs


def _put_string(out: dict[str, Any], key: str, value: str) -> None:
    if value:
        out[key] = value


def _put_bool(out: dict[str, Any], key: str, *, value: bool) -> None:
    if value:
        out[key] = value


def _put_int(out: dict[str, Any], key: str, value: int) -> None:
    if value:
        out[key] = value


def _put_list(out: dict[str, Any], key: str, value: list[Any]) -> None:
    if value:
        out[key] = list(value)


def _put_dict(out: dict[str, Any], key: str, value: dict[str, Any]) -> None:
    if value:
        out[key] = dict(value)


def _dict_value(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return 0
    return 0
