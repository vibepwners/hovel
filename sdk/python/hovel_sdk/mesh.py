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

MESH_TASK_STATUS_SUCCEEDED = "succeeded"
MESH_TASK_STATUS_FAILED = "failed"

MESH_LISTENER_DEPLOYMENT_EMBEDDED = "embedded"
MESH_LISTENER_DEPLOYMENT_SEPARATE = "separate"

MESH_LISTENER_MANAGEMENT_PROVIDER = "provider"
MESH_LISTENER_MANAGEMENT_EXTERNAL = "external"

MESH_LISTENER_STATE_STARTING = "starting"
MESH_LISTENER_STATE_ACTIVE = "active"
MESH_LISTENER_STATE_STOPPING = "stopping"
MESH_LISTENER_STATE_STOPPED = "stopped"
MESH_LISTENER_STATE_FAILED = "failed"

_MESH_RPC_PREFIX = "mesh."
_MESH_RPC_DESCRIBE_METHOD = "mesh.describe"
_MESH_RPC_TOPOLOGY_METHOD = "mesh.topology"
_MESH_RPC_BEACONS_METHOD = "mesh.beacons"
_MESH_RPC_LISTENERS_METHOD = "mesh.listeners"
_MESH_RPC_LISTENER_START_METHOD = "mesh.listener.start"
_MESH_RPC_LISTENER_STOP_METHOD = "mesh.listener.stop"
_MESH_RPC_TASK_METHOD = "mesh.task"
_MESH_RPC_OPEN_STREAM_METHOD = "mesh.open_stream"
_DEFAULT_MESH_RUN_ID = "mesh"


@dataclass(frozen=True)
class MeshNode:
    id: str
    parent_id: str = ""
    listener_id: str = ""
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
        _put_string(out, "listenerId", self.listener_id)
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
            id=_string_value(value.get("id")),
            nodes=_string_list(value.get("nodes")),
            links=_string_list(value.get("links")),
            cost=_int_value(value.get("cost")),
            attributes=_dict_value(value.get("attributes")),
        )

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"nodes": list(self.nodes)}
        _put_string(out, "id", self.id)
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
class MeshListenerSpec:
    kind: str
    summary: str = ""
    deployments: list[str] = field(default_factory=list)
    management_modes: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        _put_string(out, "summary", self.summary)
        _put_list(out, "deployments", self.deployments)
        _put_list(out, "managementModes", self.management_modes)
        _put_list(out, "protocols", self.protocols)
        _put_dict(out, "configSchema", self.config_schema)
        _put_list(out, "capabilities", self.capabilities)
        return out


@dataclass(frozen=True)
class MeshTrigger:
    id: str
    name: str = ""
    kind: str = ""
    node_id: str = ""
    listener_id: str = ""
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
        _put_string(out, "listenerId", self.listener_id)
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
    listener_id: str = ""
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
        _put_string(out, "listenerId", self.listener_id)
        _put_string(out, "state", self.state)
        _put_string(out, "transport", self.transport)
        _put_string(out, "remoteAddr", self.remote_addr)
        _put_int(out, "intervalSeconds", self.interval_seconds)
        _put_dict(out, "fields", self.fields)
        return out


@dataclass(frozen=True)
class MeshListener:
    id: str
    name: str = ""
    kind: str = ""
    state: str = ""
    deployment: str = ""
    management: str = ""
    node_id: str = ""
    addresses: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    labels: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id}
        _put_string(out, "name", self.name)
        _put_string(out, "kind", self.kind)
        _put_string(out, "state", self.state)
        _put_string(out, "deployment", self.deployment)
        _put_string(out, "management", self.management)
        _put_string(out, "nodeId", self.node_id)
        _put_list(out, "addresses", self.addresses)
        _put_list(out, "protocols", self.protocols)
        _put_list(out, "capabilities", self.capabilities)
        _put_dict(out, "labels", self.labels)
        _put_dict(out, "attributes", self.attributes)
        _put_string(out, "updatedAt", self.updated_at)
        return out


@dataclass(frozen=True)
class MeshDescriptor:
    name: str = ""
    version: str = ""
    summary: str = ""
    capabilities: list[str] = field(default_factory=list)
    topology: MeshTopology | None = None
    tasks: list[MeshTaskSpec] = field(default_factory=list)
    listener_types: list[MeshListenerSpec] = field(default_factory=list)
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
        if self.listener_types:
            out["listenerTypes"] = [listener.to_rpc() for listener in self.listener_types]
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
    listener_id: str = ""
    include_routes: bool = False
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshTopologyRequest:
        return cls(
            root=_string_value(value.get("root")),
            listener_id=_string_value(value.get("listenerId")),
            include_routes=_bool_value(value.get("includeRoutes")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshBeaconRequest:
    node_id: str = ""
    listener_id: str = ""
    since: str = ""
    limit: int = 0
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshBeaconRequest:
        return cls(
            node_id=_string_value(value.get("nodeId")),
            listener_id=_string_value(value.get("listenerId")),
            since=_string_value(value.get("since")),
            limit=_int_value(value.get("limit")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshListenerListRequest:
    listener_id: str = ""
    state: str = ""
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshListenerListRequest:
        return cls(
            listener_id=_optional_string(value, "listenerId").strip(),
            state=_optional_string(value, "state").strip(),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshListenerStartRequest:
    listener_id: str
    name: str = ""
    kind: str = ""
    deployment: str = ""
    management: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshListenerStartRequest:
        return cls(
            listener_id=_optional_string(value, "listenerId").strip(),
            name=_optional_string(value, "name"),
            kind=_optional_string(value, "kind"),
            deployment=_optional_string(value, "deployment").strip(),
            management=_optional_string(value, "management").strip(),
            config=_optional_dict(value, "config"),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshListenerStopRequest:
    listener_id: str
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshListenerStopRequest:
        return cls(
            listener_id=_optional_string(value, "listenerId").strip(),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshTaskRequest:
    kind: str
    run_id: str = ""
    task_id: str = ""
    node_id: str = ""
    listener_id: str = ""
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
            run_id=_string_value(value.get("runId")),
            task_id=_string_value(value.get("taskId")),
            kind=_string_value(value.get("kind")),
            node_id=_string_value(value.get("nodeId")),
            listener_id=_string_value(value.get("listenerId")),
            target=_string_value(value.get("target")),
            route=MeshRoute.from_rpc(value.get("route")),
            destination_host=_string_value(value.get("destinationHost")),
            destination_port=_int_value(value.get("destinationPort")),
            protocol=_string_value(value.get("protocol")),
            config=_dict_value(value.get("config")),
            args=_string_list(value.get("args")),
            input_data=_string_value(value.get("inputData")),
            input_encoding=_string_value(value.get("inputEncoding")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


@dataclass(frozen=True)
class MeshEvent:
    kind: str
    id: str = ""
    node_id: str = ""
    listener_id: str = ""
    level: str = ""
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        _put_string(out, "id", self.id)
        _put_string(out, "nodeId", self.node_id)
        _put_string(out, "listenerId", self.listener_id)
        _put_string(out, "level", self.level)
        _put_string(out, "message", self.message)
        _put_dict(out, "fields", self.fields)
        return out


@dataclass(frozen=True)
class MeshTaskResult:
    status: str = MESH_TASK_STATUS_SUCCEEDED
    summary: str = ""
    task_id: str = ""
    node_id: str = ""
    listener_id: str = ""
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
        return cls(status=MESH_TASK_STATUS_SUCCEEDED, summary=summary)

    def to_rpc(self, *, sessions: list[SessionRef] | None = None) -> dict[str, Any]:
        session_refs = _merge_session_refs(self.sessions, sessions or [])
        out: dict[str, Any] = {
            "status": self.status.strip() or MESH_TASK_STATUS_SUCCEEDED,
        }
        _put_string(out, "summary", self.summary)
        _put_string(out, "taskId", self.task_id)
        _put_string(out, "nodeId", self.node_id)
        _put_string(out, "listenerId", self.listener_id)
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
            out["agentHints"] = [hint.to_rpc() if hasattr(hint, "to_rpc") else dict(hint) for hint in self.agent_hints]
        return out


@dataclass(frozen=True)
class MeshStreamRequest:
    run_id: str = ""
    module_id: str = ""
    target: str = ""
    node_id: str = ""
    listener_id: str = ""
    route: MeshRoute | None = None
    destination_host: str = ""
    destination_port: int = 0
    protocol: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    agent: AgentContext | None = None

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> MeshStreamRequest:
        return cls(
            run_id=_string_value(value.get("runId")),
            module_id=_string_value(value.get("moduleId")),
            target=_string_value(value.get("target")),
            node_id=_string_value(value.get("nodeId")),
            listener_id=_string_value(value.get("listenerId")),
            route=MeshRoute.from_rpc(value.get("route")),
            destination_host=_string_value(value.get("destinationHost")),
            destination_port=_int_value(value.get("destinationPort")),
            protocol=_string_value(value.get("protocol")),
            config=_dict_value(value.get("config")),
            agent=AgentContext.from_rpc(value.get("agentContext")),
        )


def _merge_session_refs(explicit: list[SessionRef], opened: list[SessionRef]) -> list[SessionRef]:
    refs = list(explicit)
    seen = {ref.id for ref in refs}
    for ref in opened:
        if not ref.id or ref.id in seen:
            continue
        seen.add(ref.id)
        refs.append(ref)
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


def _optional_dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    if key not in value or value[key] is None:
        return {}
    if not isinstance(value[key], dict):
        raise TypeError(f"mesh listener {key} must be an object")
    return dict(value[key])


def _optional_string(value: dict[str, Any], key: str) -> str:
    if key not in value or value[key] is None:
        return ""
    item = value[key]
    if not isinstance(item, str):
        raise TypeError(f"mesh listener {key} must be a string")
    return item


def _string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _bool_value(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_value(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
