//! Node Mesh extension types.
//!
//! A Mesh is broader than a transport or tunnel: it is a provider-owned node
//! operations plane that may expose topology, routes, tasks, streams, triggers,
//! and beacons.

use crate::credential_delivery::CredentialDeliveryDescriptor;
use crate::json::Value;
use crate::result::{Artifact, Finding};
use crate::session::SessionRef;

pub const MESH_TASK_SURVEY: &str = "survey";
pub const MESH_TASK_UPLOAD: &str = "upload";
pub const MESH_TASK_EXECUTE: &str = "execute";
pub const MESH_TASK_UPLOAD_EXECUTE: &str = "upload_execute";
pub const MESH_TASK_COMMAND: &str = "command";
pub const MESH_TASK_LOAD: &str = "load";
pub const MESH_TASK_STREAM: &str = "stream";

pub const MESH_TARGET_NODE: &str = "node";
pub const MESH_TARGET_ROUTE: &str = "route";
pub const MESH_TARGET_DESTINATION: &str = "destination";

pub const MESH_TASK_STATUS_SUCCEEDED: &str = "succeeded";
pub const MESH_TASK_STATUS_FAILED: &str = "failed";

pub const MESH_LISTENER_DEPLOYMENT_EMBEDDED: &str = "embedded";
pub const MESH_LISTENER_DEPLOYMENT_SEPARATE: &str = "separate";
pub const MESH_LISTENER_MANAGEMENT_PROVIDER: &str = "provider";
pub const MESH_LISTENER_MANAGEMENT_EXTERNAL: &str = "external";
pub const MESH_LISTENER_STATE_STARTING: &str = "starting";
pub const MESH_LISTENER_STATE_ACTIVE: &str = "active";
pub const MESH_LISTENER_STATE_STOPPING: &str = "stopping";
pub const MESH_LISTENER_STATE_STOPPED: &str = "stopped";
pub const MESH_LISTENER_STATE_FAILED: &str = "failed";

pub(crate) const DEFAULT_MESH_RUN_ID: &str = "mesh";
pub(crate) const MESH_RPC_DESCRIBE_METHOD: &str = "mesh.describe";
pub(crate) const MESH_RPC_TOPOLOGY_METHOD: &str = "mesh.topology";
pub(crate) const MESH_RPC_BEACONS_METHOD: &str = "mesh.beacons";
pub(crate) const MESH_RPC_LISTENERS_METHOD: &str = "mesh.listeners";
pub(crate) const MESH_RPC_LISTENER_START_METHOD: &str = "mesh.listener.start";
pub(crate) const MESH_RPC_LISTENER_STOP_METHOD: &str = "mesh.listener.stop";
pub(crate) const MESH_RPC_TASK_METHOD: &str = "mesh.task";
pub(crate) const MESH_RPC_OPEN_STREAM_METHOD: &str = "mesh.open_stream";

const MAX_MESH_PORT: i64 = 65_535;

/// Identity attached to an agent-aware Mesh request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentEntity {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    pub agent: bool,
}

impl AgentEntity {
    fn from_value(value: Option<&Value>) -> AgentEntity {
        let Some(value @ Value::Object(_)) = value else {
            return AgentEntity::default();
        };
        AgentEntity {
            id: string_field(value, "id"),
            kind: string_field(value, "kind"),
            display_name: string_field(value, "displayName"),
            agent: bool_field(value, "agent"),
        }
    }

    fn try_from_value(value: Option<&Value>) -> Result<AgentEntity, String> {
        let Some(value) = value else {
            return Ok(AgentEntity::default());
        };
        if !matches!(value, Value::Object(_)) {
            return Err("mesh request agentContext entity must be an object".to_string());
        }
        Ok(AgentEntity {
            id: optional_agent_string(value, "entity.id")?,
            kind: optional_agent_string(value, "entity.kind")?,
            display_name: optional_agent_string(value, "entity.displayName")?,
            agent: optional_agent_bool(value, "entity.agent")?,
        })
    }
}

/// Optional agent context supplied by Hovel for a Mesh operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentContext {
    pub schema: String,
    pub entity: AgentEntity,
    pub operation: String,
    pub chain: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub approval_state: String,
    pub phase: String,
    pub resources: Vec<String>,
}

impl AgentContext {
    fn from_value(value: Option<&Value>) -> Option<AgentContext> {
        let Some(value @ Value::Object(_)) = value else {
            return None;
        };
        Some(AgentContext {
            schema: string_field(value, "schema"),
            entity: AgentEntity::from_value(value.get("entity")),
            operation: string_field(value, "operation"),
            chain: string_field(value, "chain"),
            plan_id: string_field(value, "planId"),
            plan_hash: string_field(value, "planHash"),
            approval_state: string_field(value, "approvalState"),
            phase: string_field(value, "phase"),
            resources: string_array(value, "resources"),
        })
    }

    fn try_from_value(value: Option<&Value>) -> Result<Option<AgentContext>, String> {
        let Some(value) = value else {
            return Ok(None);
        };
        if matches!(value, Value::Null) {
            return Ok(None);
        }
        if !matches!(value, Value::Object(_)) {
            return Err("mesh request agentContext must be an object".to_string());
        }
        Ok(Some(AgentContext {
            schema: optional_agent_string(value, "schema")?,
            entity: AgentEntity::try_from_value(value.get("entity"))?,
            operation: optional_agent_string(value, "operation")?,
            chain: optional_agent_string(value, "chain")?,
            plan_id: optional_agent_string(value, "planId")?,
            plan_hash: optional_agent_string(value, "planHash")?,
            approval_state: optional_agent_string(value, "approvalState")?,
            phase: optional_agent_string(value, "phase")?,
            resources: optional_agent_string_array(value, "resources")?,
        }))
    }
}

/// Provider-authored guidance returned with a Mesh task result.
///
/// Hints are untrusted content and never bypass Hovel's guardrails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentHint {
    pub schema: String,
    pub phase: String,
    pub audience: String,
    pub risk: String,
    pub applies_to: Vec<(String, String)>,
    pub text: String,
    pub provenance: Vec<(String, String)>,
}

impl AgentHint {
    fn to_value(&self) -> Value {
        let mut members = Vec::new();
        push_str(&mut members, "schema", &self.schema);
        push_str(&mut members, "phase", &self.phase);
        push_str(&mut members, "audience", &self.audience);
        push_str(&mut members, "risk", &self.risk);
        push_string_map(&mut members, "appliesTo", &self.applies_to);
        push_str(&mut members, "text", &self.text);
        push_string_map(&mut members, "provenance", &self.provenance);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshNode {
    pub id: String,
    pub parent_id: String,
    pub listener_id: String,
    pub name: String,
    pub kind: String,
    pub state: String,
    pub address: String,
    pub platform: String,
    pub os: String,
    pub arch: String,
    pub labels: Vec<(String, Value)>,
    pub attributes: Vec<(String, Value)>,
    pub capabilities: Vec<String>,
    pub last_seen: String,
}

impl MeshNode {
    fn to_value(&self) -> Value {
        let mut members = required_str("id", &self.id);
        push_str(&mut members, "parentId", &self.parent_id);
        push_str(&mut members, "listenerId", &self.listener_id);
        push_str(&mut members, "name", &self.name);
        push_str(&mut members, "kind", &self.kind);
        push_str(&mut members, "state", &self.state);
        push_str(&mut members, "address", &self.address);
        push_str(&mut members, "platform", &self.platform);
        push_str(&mut members, "os", &self.os);
        push_str(&mut members, "arch", &self.arch);
        push_object(&mut members, "labels", &self.labels);
        push_object(&mut members, "attributes", &self.attributes);
        push_strings(&mut members, "capabilities", &self.capabilities);
        push_str(&mut members, "lastSeen", &self.last_seen);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshLink {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub state: String,
    pub transport: String,
    pub cost: i64,
    pub latency_ms: i64,
    pub attributes: Vec<(String, Value)>,
}

impl MeshLink {
    fn to_value(&self) -> Value {
        let mut members = required_str("id", &self.id);
        members.push(("source".to_string(), Value::from(self.source.as_str())));
        members.push(("target".to_string(), Value::from(self.target.as_str())));
        push_str(&mut members, "kind", &self.kind);
        push_str(&mut members, "state", &self.state);
        push_str(&mut members, "transport", &self.transport);
        push_i64(&mut members, "cost", self.cost);
        push_i64(&mut members, "latencyMs", self.latency_ms);
        push_object(&mut members, "attributes", &self.attributes);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshRoute {
    pub id: String,
    pub nodes: Vec<String>,
    pub links: Vec<String>,
    pub cost: i64,
    pub attributes: Vec<(String, Value)>,
}

impl MeshRoute {
    fn try_from_value(value: &Value) -> Result<MeshRoute, String> {
        if !matches!(value, Value::Object(_)) {
            return Err("mesh request route must be an object".to_string());
        }
        Ok(MeshRoute {
            id: optional_mesh_string(value, "id")?,
            nodes: required_mesh_string_array(value, "nodes")?,
            links: optional_mesh_string_array(value, "links")?,
            cost: optional_mesh_integer(value, "cost", i64::MAX)?,
            attributes: optional_mesh_object(value, "attributes")?,
        })
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut members = Vec::new();
        push_str(&mut members, "id", &self.id);
        members.push((
            "nodes".to_string(),
            Value::Array(self.nodes.iter().cloned().map(Value::Str).collect()),
        ));
        push_strings(&mut members, "links", &self.links);
        push_i64(&mut members, "cost", self.cost);
        push_object(&mut members, "attributes", &self.attributes);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTopology {
    pub root: String,
    pub nodes: Vec<MeshNode>,
    pub links: Vec<MeshLink>,
    pub routes: Vec<MeshRoute>,
    pub attributes: Vec<(String, Value)>,
}

impl MeshTopology {
    pub(crate) fn to_value(&self) -> Value {
        let mut members = Vec::new();
        push_str(&mut members, "root", &self.root);
        if !self.nodes.is_empty() {
            members.push((
                "nodes".to_string(),
                Value::Array(self.nodes.iter().map(MeshNode::to_value).collect()),
            ));
        }
        if !self.links.is_empty() {
            members.push((
                "links".to_string(),
                Value::Array(self.links.iter().map(MeshLink::to_value).collect()),
            ));
        }
        if !self.routes.is_empty() {
            members.push((
                "routes".to_string(),
                Value::Array(self.routes.iter().map(MeshRoute::to_value).collect()),
            ));
        }
        push_object(&mut members, "attributes", &self.attributes);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTaskSpec {
    pub kind: String,
    pub summary: String,
    pub config_schema: Vec<(String, Value)>,
    pub read_only: bool,
    pub destructive: bool,
    pub opens_stream: bool,
    pub target_scopes: Vec<String>,
    pub capabilities: Vec<String>,
}

impl MeshTaskSpec {
    fn to_value(&self) -> Value {
        let mut members = required_str("kind", &self.kind);
        push_str(&mut members, "summary", &self.summary);
        push_object(&mut members, "configSchema", &self.config_schema);
        push_bool(&mut members, "readOnly", self.read_only);
        push_bool(&mut members, "destructive", self.destructive);
        push_bool(&mut members, "opensStream", self.opens_stream);
        push_strings(&mut members, "targetScopes", &self.target_scopes);
        push_strings(&mut members, "capabilities", &self.capabilities);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshListenerSpec {
    pub kind: String,
    pub summary: String,
    pub deployments: Vec<String>,
    pub management_modes: Vec<String>,
    pub protocols: Vec<String>,
    pub config_schema: Vec<(String, Value)>,
    pub capabilities: Vec<String>,
}

impl MeshListenerSpec {
    fn to_value(&self) -> Value {
        let mut members = required_str("kind", &self.kind);
        push_str(&mut members, "summary", &self.summary);
        push_strings(&mut members, "deployments", &self.deployments);
        push_strings(&mut members, "managementModes", &self.management_modes);
        push_strings(&mut members, "protocols", &self.protocols);
        push_object(&mut members, "configSchema", &self.config_schema);
        push_strings(&mut members, "capabilities", &self.capabilities);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTrigger {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub node_id: String,
    pub listener_id: String,
    pub state: String,
    pub expression: String,
    pub schedule: String,
    pub action_kind: String,
    pub config: Vec<(String, Value)>,
    pub last_fired: String,
}

impl MeshTrigger {
    fn to_value(&self) -> Value {
        let mut members = required_str("id", &self.id);
        push_str(&mut members, "name", &self.name);
        push_str(&mut members, "kind", &self.kind);
        push_str(&mut members, "nodeId", &self.node_id);
        push_str(&mut members, "listenerId", &self.listener_id);
        push_str(&mut members, "state", &self.state);
        push_str(&mut members, "expression", &self.expression);
        push_str(&mut members, "schedule", &self.schedule);
        push_str(&mut members, "actionKind", &self.action_kind);
        push_object(&mut members, "config", &self.config);
        push_str(&mut members, "lastFired", &self.last_fired);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshBeacon {
    pub id: String,
    pub node_id: String,
    pub listener_id: String,
    pub time: String,
    pub state: String,
    pub transport: String,
    pub remote_addr: String,
    pub interval_seconds: i64,
    pub fields: Vec<(String, Value)>,
}

impl MeshBeacon {
    pub(crate) fn to_value(&self) -> Value {
        let mut members = required_str("id", &self.id);
        members.push(("nodeId".to_string(), Value::from(self.node_id.as_str())));
        push_str(&mut members, "listenerId", &self.listener_id);
        push_str(&mut members, "time", &self.time);
        push_str(&mut members, "state", &self.state);
        push_str(&mut members, "transport", &self.transport);
        push_str(&mut members, "remoteAddr", &self.remote_addr);
        push_i64(&mut members, "intervalSeconds", self.interval_seconds);
        push_object(&mut members, "fields", &self.fields);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshListener {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub state: String,
    pub deployment: String,
    pub management: String,
    pub node_id: String,
    pub addresses: Vec<String>,
    pub protocols: Vec<String>,
    pub capabilities: Vec<String>,
    pub labels: Vec<(String, Value)>,
    pub attributes: Vec<(String, Value)>,
    pub updated_at: String,
}

impl MeshListener {
    pub(crate) fn to_value(&self) -> Value {
        let mut members = required_str("id", &self.id);
        push_str(&mut members, "name", &self.name);
        push_str(&mut members, "kind", &self.kind);
        push_str(&mut members, "state", &self.state);
        push_str(&mut members, "deployment", &self.deployment);
        push_str(&mut members, "management", &self.management);
        push_str(&mut members, "nodeId", &self.node_id);
        push_strings(&mut members, "addresses", &self.addresses);
        push_strings(&mut members, "protocols", &self.protocols);
        push_strings(&mut members, "capabilities", &self.capabilities);
        push_object(&mut members, "labels", &self.labels);
        push_object(&mut members, "attributes", &self.attributes);
        push_str(&mut members, "updatedAt", &self.updated_at);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshDescriptor {
    pub name: String,
    pub version: String,
    pub summary: String,
    pub capabilities: Vec<String>,
    pub topology: MeshTopology,
    pub tasks: Vec<MeshTaskSpec>,
    pub listener_types: Vec<MeshListenerSpec>,
    pub triggers: Vec<MeshTrigger>,
    pub credential_delivery: Option<CredentialDeliveryDescriptor>,
    pub attributes: Vec<(String, Value)>,
}

impl MeshDescriptor {
    pub(crate) fn to_value(&self) -> Value {
        let mut members = Vec::new();
        push_str(&mut members, "name", &self.name);
        push_str(&mut members, "version", &self.version);
        push_str(&mut members, "summary", &self.summary);
        push_strings(&mut members, "capabilities", &self.capabilities);
        if !self.topology.root.is_empty()
            || !self.topology.nodes.is_empty()
            || !self.topology.links.is_empty()
            || !self.topology.routes.is_empty()
            || !self.topology.attributes.is_empty()
        {
            members.push(("topology".to_string(), self.topology.to_value()));
        }
        if !self.tasks.is_empty() {
            members.push((
                "tasks".to_string(),
                Value::Array(self.tasks.iter().map(MeshTaskSpec::to_value).collect()),
            ));
        }
        if !self.listener_types.is_empty() {
            members.push((
                "listenerTypes".to_string(),
                Value::Array(
                    self.listener_types
                        .iter()
                        .map(MeshListenerSpec::to_value)
                        .collect(),
                ),
            ));
        }
        if !self.triggers.is_empty() {
            members.push((
                "triggers".to_string(),
                Value::Array(self.triggers.iter().map(MeshTrigger::to_value).collect()),
            ));
        }
        if let Some(credential_delivery) = &self.credential_delivery {
            members.push((
                "credentialDelivery".to_string(),
                credential_delivery.to_value(),
            ));
        }
        push_object(&mut members, "attributes", &self.attributes);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshDescribeRequest {
    pub agent: Option<AgentContext>,
}

impl MeshDescribeRequest {
    pub(crate) fn from_value(value: &Value) -> MeshDescribeRequest {
        MeshDescribeRequest {
            agent: AgentContext::from_value(value.get("agentContext")),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTopologyRequest {
    pub root: String,
    pub listener_id: String,
    pub include_routes: bool,
    pub agent: Option<AgentContext>,
}

impl MeshTopologyRequest {
    pub(crate) fn from_value(value: &Value) -> MeshTopologyRequest {
        MeshTopologyRequest {
            root: string_field(value, "root"),
            listener_id: string_field(value, "listenerId"),
            include_routes: bool_field(value, "includeRoutes"),
            agent: AgentContext::from_value(value.get("agentContext")),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshBeaconRequest {
    pub node_id: String,
    pub listener_id: String,
    pub since: String,
    pub limit: i64,
    pub agent: Option<AgentContext>,
}

impl MeshBeaconRequest {
    pub(crate) fn from_value(value: &Value) -> MeshBeaconRequest {
        MeshBeaconRequest {
            node_id: string_field(value, "nodeId"),
            listener_id: string_field(value, "listenerId"),
            since: string_field(value, "since"),
            limit: i64_field(value, "limit"),
            agent: AgentContext::from_value(value.get("agentContext")),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshListenerListRequest {
    pub listener_id: String,
    pub state: String,
    pub agent: Option<AgentContext>,
}

impl MeshListenerListRequest {
    pub(crate) fn from_value(value: &Value) -> Result<MeshListenerListRequest, String> {
        Ok(MeshListenerListRequest {
            listener_id: listener_string_field(value, "listenerId")?
                .trim()
                .to_string(),
            state: listener_string_field(value, "state")?.trim().to_string(),
            agent: AgentContext::from_value(value.get("agentContext")),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshListenerStartRequest {
    pub listener_id: String,
    pub name: String,
    pub kind: String,
    pub deployment: String,
    pub management: String,
    pub config: Vec<(String, Value)>,
    pub agent: Option<AgentContext>,
}

impl MeshListenerStartRequest {
    pub(crate) fn from_value(value: &Value) -> Result<MeshListenerStartRequest, String> {
        Ok(MeshListenerStartRequest {
            listener_id: listener_string_field(value, "listenerId")?
                .trim()
                .to_string(),
            name: listener_string_field(value, "name")?,
            kind: listener_string_field(value, "kind")?,
            deployment: listener_string_field(value, "deployment")?
                .trim()
                .to_string(),
            management: listener_string_field(value, "management")?
                .trim()
                .to_string(),
            config: listener_object_field(value, "config")?,
            agent: AgentContext::from_value(value.get("agentContext")),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshListenerStopRequest {
    pub listener_id: String,
    pub agent: Option<AgentContext>,
}

impl MeshListenerStopRequest {
    pub(crate) fn from_value(value: &Value) -> Result<MeshListenerStopRequest, String> {
        Ok(MeshListenerStopRequest {
            listener_id: listener_string_field(value, "listenerId")?
                .trim()
                .to_string(),
            agent: AgentContext::from_value(value.get("agentContext")),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTaskRequest {
    pub run_id: String,
    pub task_id: String,
    pub kind: String,
    pub node_id: String,
    pub listener_id: String,
    pub target: String,
    pub route: Option<MeshRoute>,
    pub destination_host: String,
    pub destination_port: i64,
    pub protocol: String,
    pub config: Vec<(String, Value)>,
    pub args: Vec<String>,
    pub input_data: String,
    pub input_encoding: String,
    pub agent: Option<AgentContext>,
}

impl MeshTaskRequest {
    pub(crate) fn try_from_value(value: &Value) -> Result<MeshTaskRequest, String> {
        Ok(MeshTaskRequest {
            run_id: optional_mesh_string(value, "runId")?,
            task_id: optional_mesh_string(value, "taskId")?,
            kind: required_mesh_string(value, "kind")?,
            node_id: optional_mesh_string(value, "nodeId")?,
            listener_id: optional_mesh_string(value, "listenerId")?,
            target: optional_mesh_string(value, "target")?,
            route: optional_mesh_route(value)?,
            destination_host: optional_mesh_string(value, "destinationHost")?,
            destination_port: optional_mesh_integer(value, "destinationPort", MAX_MESH_PORT)?,
            protocol: optional_mesh_string(value, "protocol")?,
            config: optional_mesh_object(value, "config")?,
            args: optional_mesh_string_array(value, "args")?,
            input_data: optional_mesh_string(value, "inputData")?,
            input_encoding: optional_mesh_string(value, "inputEncoding")?,
            agent: AgentContext::try_from_value(value.get("agentContext"))?,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTaskResult {
    pub task_id: String,
    pub status: String,
    pub summary: String,
    pub node_id: String,
    pub listener_id: String,
    pub route: Option<MeshRoute>,
    pub destination_host: String,
    pub destination_port: i64,
    pub protocol: String,
    pub outputs: Vec<(String, Value)>,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<Artifact>,
    pub sessions: Vec<SessionRef>,
    pub beacons: Vec<MeshBeacon>,
    pub events: Vec<MeshEvent>,
    pub agent_hints: Vec<AgentHint>,
}

impl MeshTaskResult {
    pub fn succeeded(summary: &str) -> MeshTaskResult {
        MeshTaskResult {
            status: MESH_TASK_STATUS_SUCCEEDED.to_string(),
            summary: summary.to_string(),
            ..MeshTaskResult::default()
        }
    }

    pub(crate) fn to_value(mut self, opened_sessions: Vec<SessionRef>) -> Value {
        self.sessions = merge_sessions(self.sessions, opened_sessions);
        let mut members = Vec::new();
        push_str(&mut members, "taskId", &self.task_id);
        let normalized_status = self.status.trim();
        let status = if normalized_status.is_empty() {
            MESH_TASK_STATUS_SUCCEEDED
        } else {
            normalized_status
        };
        push_str(&mut members, "status", status);
        push_str(&mut members, "summary", &self.summary);
        push_str(&mut members, "nodeId", &self.node_id);
        push_str(&mut members, "listenerId", &self.listener_id);
        if let Some(route) = self.route {
            members.push(("route".to_string(), route.to_value()));
        }
        push_str(&mut members, "destinationHost", &self.destination_host);
        push_i64(&mut members, "destinationPort", self.destination_port);
        push_str(&mut members, "protocol", &self.protocol);
        push_object(&mut members, "outputs", &self.outputs);
        if !self.findings.is_empty() {
            members.push((
                "findings".to_string(),
                Value::Array(self.findings.iter().map(Finding::to_value).collect()),
            ));
        }
        if !self.artifacts.is_empty() {
            members.push((
                "artifacts".to_string(),
                Value::Array(self.artifacts.iter().map(Artifact::to_value).collect()),
            ));
        }
        if !self.sessions.is_empty() {
            members.push((
                "sessions".to_string(),
                Value::Array(self.sessions.iter().map(SessionRef::to_value).collect()),
            ));
        }
        if !self.beacons.is_empty() {
            members.push((
                "beacons".to_string(),
                Value::Array(self.beacons.iter().map(MeshBeacon::to_value).collect()),
            ));
        }
        if !self.events.is_empty() {
            members.push((
                "events".to_string(),
                Value::Array(self.events.iter().map(MeshEvent::to_value).collect()),
            ));
        }
        if !self.agent_hints.is_empty() {
            members.push((
                "agentHints".to_string(),
                Value::Array(self.agent_hints.iter().map(AgentHint::to_value).collect()),
            ));
        }
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshEvent {
    pub id: String,
    pub kind: String,
    pub node_id: String,
    pub listener_id: String,
    pub level: String,
    pub message: String,
    pub fields: Vec<(String, Value)>,
}

impl MeshEvent {
    fn to_value(&self) -> Value {
        let mut members = Vec::new();
        push_str(&mut members, "id", &self.id);
        members.push(("kind".to_string(), Value::from(self.kind.as_str())));
        push_str(&mut members, "nodeId", &self.node_id);
        push_str(&mut members, "listenerId", &self.listener_id);
        push_str(&mut members, "level", &self.level);
        push_str(&mut members, "message", &self.message);
        push_object(&mut members, "fields", &self.fields);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshStreamRequest {
    pub run_id: String,
    pub module_id: String,
    pub target: String,
    pub node_id: String,
    pub listener_id: String,
    pub route: Option<MeshRoute>,
    pub destination_host: String,
    pub destination_port: i64,
    pub protocol: String,
    pub config: Vec<(String, Value)>,
    pub agent: Option<AgentContext>,
}

impl MeshStreamRequest {
    pub(crate) fn try_from_value(value: &Value) -> Result<MeshStreamRequest, String> {
        Ok(MeshStreamRequest {
            run_id: optional_mesh_string(value, "runId")?,
            module_id: optional_mesh_string(value, "moduleId")?,
            target: optional_mesh_string(value, "target")?,
            node_id: optional_mesh_string(value, "nodeId")?,
            listener_id: optional_mesh_string(value, "listenerId")?,
            route: optional_mesh_route(value)?,
            destination_host: optional_mesh_string(value, "destinationHost")?,
            destination_port: optional_mesh_integer(value, "destinationPort", MAX_MESH_PORT)?,
            protocol: optional_mesh_string(value, "protocol")?,
            config: optional_mesh_object(value, "config")?,
            agent: AgentContext::try_from_value(value.get("agentContext"))?,
        })
    }
}

pub(crate) fn context_params(module_id: &str, params: &Value) -> Value {
    let mut members = match params {
        Value::Object(items) => items.clone(),
        _ => Vec::new(),
    };
    set_default_string(&mut members, "moduleId", module_id);
    set_default_string(&mut members, "runId", DEFAULT_MESH_RUN_ID);
    if string_member_is_blank(&members, "target") {
        let destination_host = string_member(&members, "destinationHost")
            .unwrap_or("")
            .to_string();
        if !destination_host.trim().is_empty() {
            set_string_member(&mut members, "target", &destination_host);
        }
    }
    if string_member_is_blank(&members, "target") {
        let node_id = string_member(&members, "nodeId").unwrap_or("").to_string();
        if !node_id.trim().is_empty() {
            set_string_member(&mut members, "target", &node_id);
        }
    }
    Value::Object(members)
}

fn merge_sessions(mut explicit: Vec<SessionRef>, opened: Vec<SessionRef>) -> Vec<SessionRef> {
    for session in opened {
        if !session.id.is_empty() && !explicit.iter().any(|existing| existing.id == session.id) {
            explicit.push(session);
        }
    }
    explicit
}

fn string_member<'a>(members: &'a [(String, Value)], key: &str) -> Option<&'a str> {
    members
        .iter()
        .find(|(existing, _)| existing == key)
        .and_then(|(_, value)| value.as_str())
}

fn string_member_is_blank(members: &[(String, Value)], key: &str) -> bool {
    string_member(members, key).is_none_or(|value| value.trim().is_empty())
}

fn set_default_string(members: &mut Vec<(String, Value)>, key: &str, default: &str) {
    if string_member_is_blank(members, key) {
        set_string_member(members, key, default);
    }
}

fn set_string_member(members: &mut Vec<(String, Value)>, key: &str, value: &str) {
    if let Some((_, existing)) = members.iter_mut().find(|(existing, _)| existing == key) {
        *existing = Value::from(value);
        return;
    }
    members.push((key.to_string(), Value::from(value)));
}

fn required_str(key: &str, value: &str) -> Vec<(String, Value)> {
    vec![(key.to_string(), Value::from(value))]
}

fn push_str(members: &mut Vec<(String, Value)>, key: &str, value: &str) {
    if !value.is_empty() {
        members.push((key.to_string(), Value::from(value)));
    }
}

fn push_bool(members: &mut Vec<(String, Value)>, key: &str, value: bool) {
    if value {
        members.push((key.to_string(), Value::Bool(value)));
    }
}

fn push_i64(members: &mut Vec<(String, Value)>, key: &str, value: i64) {
    if value != 0 {
        members.push((key.to_string(), Value::from(value)));
    }
}

fn push_strings(members: &mut Vec<(String, Value)>, key: &str, values: &[String]) {
    if !values.is_empty() {
        members.push((
            key.to_string(),
            Value::Array(values.iter().cloned().map(Value::Str).collect()),
        ));
    }
}

fn push_object(members: &mut Vec<(String, Value)>, key: &str, values: &[(String, Value)]) {
    if !values.is_empty() {
        members.push((key.to_string(), Value::Object(values.to_vec())));
    }
}

fn push_string_map(members: &mut Vec<(String, Value)>, key: &str, values: &[(String, String)]) {
    if !values.is_empty() {
        members.push((
            key.to_string(),
            Value::Object(
                values
                    .iter()
                    .map(|(name, value)| (name.clone(), Value::from(value.as_str())))
                    .collect(),
            ),
        ));
    }
}

fn required_mesh_string(value: &Value, key: &str) -> Result<String, String> {
    let item = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("mesh request {key} must be a string"))?;
    if item.trim().is_empty() {
        return Err(format!("mesh request {key} must be a non-empty string"));
    }
    Ok(item.to_string())
}

fn optional_mesh_string(value: &Value, key: &str) -> Result<String, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Str(item)) => Ok(item.clone()),
        Some(_) => Err(format!("mesh request {key} must be a string")),
    }
}

fn optional_mesh_integer(value: &Value, key: &str, maximum: i64) -> Result<i64, String> {
    let Some(item) = value.get(key) else {
        return Ok(0);
    };
    if matches!(item, Value::Null) {
        return Ok(0);
    }
    let number = item
        .as_f64()
        .filter(|number| number.is_finite() && number.fract() == 0.0)
        .ok_or_else(|| format!("mesh request {key} must be an integer"))?;
    if number < 0.0 || number > maximum as f64 {
        return Err(format!(
            "mesh request {key} must be between 0 and {maximum}"
        ));
    }
    Ok(number as i64)
}

fn optional_mesh_object(value: &Value, key: &str) -> Result<Vec<(String, Value)>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(members)) => Ok(members.clone()),
        Some(_) => Err(format!("mesh request {key} must be an object")),
    }
}

fn optional_mesh_string_array(value: &Value, key: &str) -> Result<Vec<String>, String> {
    let Some(item) = value.get(key) else {
        return Ok(Vec::new());
    };
    if matches!(item, Value::Null) {
        return Ok(Vec::new());
    }
    let items = item
        .as_array()
        .ok_or_else(|| format!("mesh request {key} must be a string array"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("mesh request {key} must be a string array"))
        })
        .collect()
}

fn required_mesh_string_array(value: &Value, key: &str) -> Result<Vec<String>, String> {
    let items = optional_mesh_string_array(value, key)?;
    if items.is_empty() || items.iter().any(|item| item.trim().is_empty()) {
        return Err(format!(
            "mesh request {key} must be a non-empty string array"
        ));
    }
    Ok(items)
}

fn optional_mesh_route(value: &Value) -> Result<Option<MeshRoute>, String> {
    match value.get("route") {
        None | Some(Value::Null) => Ok(None),
        Some(route @ Value::Object(_)) => MeshRoute::try_from_value(route).map(Some),
        Some(_) => Err("mesh request route must be an object".to_string()),
    }
}

fn optional_agent_string(value: &Value, path: &str) -> Result<String, String> {
    let key = path.rsplit('.').next().unwrap_or(path);
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Str(item)) => Ok(item.clone()),
        Some(_) => Err(format!("mesh request agentContext {path} must be a string")),
    }
}

fn optional_agent_bool(value: &Value, path: &str) -> Result<bool, String> {
    let key = path.rsplit('.').next().unwrap_or(path);
    match value.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(item)) => Ok(*item),
        Some(_) => Err(format!(
            "mesh request agentContext {path} must be a boolean"
        )),
    }
}

fn optional_agent_string_array(value: &Value, key: &str) -> Result<Vec<String>, String> {
    let Some(item) = value.get(key) else {
        return Ok(Vec::new());
    };
    if matches!(item, Value::Null) {
        return Ok(Vec::new());
    }
    let items = item
        .as_array()
        .ok_or_else(|| format!("mesh request agentContext {key} must be a string array"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("mesh request agentContext {key} must be a string array"))
        })
        .collect()
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn i64_field(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(Value::as_f64)
        .filter(|number| {
            number.is_finite()
                && number.fract() == 0.0
                && *number >= i64::MIN as f64
                && *number < i64::MAX as f64
        })
        .map_or(0, |number| number as i64)
}

fn listener_string_field(value: &Value, key: &str) -> Result<String, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Str(text)) => Ok(text.clone()),
        Some(_) => Err(format!("mesh listener {key} must be a string")),
    }
}

fn listener_object_field(value: &Value, key: &str) -> Result<Vec<(String, Value)>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(members)) => Ok(members.clone()),
        Some(_) => Err(format!("mesh listener {key} must be an object")),
    }
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        context_params, i64_field, AgentHint, MeshBeacon, MeshEvent, MeshLink, MeshRoute,
        MeshStreamRequest, MeshTaskRequest, MeshTaskResult, MAX_MESH_PORT,
    };
    use crate::json::Value;

    #[test]
    fn required_mesh_fields_are_serialized_when_empty() {
        let route = MeshRoute::default().to_value();
        assert!(matches!(route.get("nodes"), Some(Value::Array(nodes)) if nodes.is_empty()));

        let link = MeshLink::default().to_value();
        assert_eq!(link.get("source").and_then(Value::as_str), Some(""));
        assert_eq!(link.get("target").and_then(Value::as_str), Some(""));

        let beacon = MeshBeacon::default().to_value();
        assert_eq!(beacon.get("nodeId").and_then(Value::as_str), Some(""));

        let event = MeshEvent::default().to_value();
        assert_eq!(event.get("kind").and_then(Value::as_str), Some(""));
    }

    #[test]
    fn mesh_context_replaces_non_string_scope_fields() {
        let params = Value::object(vec![
            ("moduleId", Value::from(7_i64)),
            ("runId", Value::Null),
            ("target", Value::from(false)),
            ("destinationHost", Value::from("10.10.0.99")),
        ]);

        let context = context_params("mesh-provider@v1", &params);
        assert_eq!(
            context.get("moduleId").and_then(Value::as_str),
            Some("mesh-provider@v1")
        );
        assert_eq!(context.get("runId").and_then(Value::as_str), Some("mesh"));
        assert_eq!(
            context.get("target").and_then(Value::as_str),
            Some("10.10.0.99")
        );
    }

    #[test]
    fn integer_fields_reject_non_integer_wire_values() {
        for invalid in [
            Value::from(1.5_f64),
            Value::from("7"),
            Value::from(true),
            Value::from(f64::NAN),
            Value::from(f64::INFINITY),
            Value::from(i64::MAX as f64),
        ] {
            let value = Value::object(vec![("field", invalid)]);
            assert_eq!(i64_field(&value, "field"), 0);
        }

        let value = Value::object(vec![("field", Value::from(7_i64))]);
        assert_eq!(i64_field(&value, "field"), 7);
    }

    #[test]
    fn mesh_task_decoder_rejects_missing_and_malformed_fields() {
        let malformed = [
            Value::Object(Vec::new()),
            Value::object(vec![("kind", Value::Bool(false))]),
            Value::object(vec![("kind", Value::from(" "))]),
            Value::object(vec![
                ("kind", Value::from("command")),
                ("runId", Value::from(7_i64)),
            ]),
            Value::object(vec![
                ("kind", Value::from("command")),
                ("destinationPort", Value::from(MAX_MESH_PORT + 1)),
            ]),
            Value::object(vec![
                ("kind", Value::from("command")),
                (
                    "args",
                    Value::Array(vec![Value::from("whoami"), Value::from(1_i64)]),
                ),
            ]),
            Value::object(vec![
                ("kind", Value::from("command")),
                ("route", Value::from("relay-1")),
            ]),
            Value::object(vec![
                ("kind", Value::from("command")),
                ("route", Value::Object(Vec::new())),
            ]),
            Value::object(vec![
                ("kind", Value::from("command")),
                (
                    "route",
                    Value::object(vec![(
                        "nodes",
                        Value::Array(vec![Value::from("relay-1"), Value::from(2_i64)]),
                    )]),
                ),
            ]),
            Value::object(vec![
                ("kind", Value::from("command")),
                (
                    "agentContext",
                    Value::object(vec![("phase", Value::Bool(true))]),
                ),
            ]),
        ];
        for value in malformed {
            assert!(MeshTaskRequest::try_from_value(&value).is_err());
        }

        let valid = Value::object(vec![
            ("kind", Value::from("provider-command")),
            ("destinationPort", Value::from(MAX_MESH_PORT)),
            (
                "config",
                Value::object(vec![(
                    "extension",
                    Value::object(vec![("x", Value::from(1_i64))]),
                )]),
            ),
        ]);
        let request = MeshTaskRequest::try_from_value(&valid).expect("valid mesh task");
        assert_eq!(request.kind, "provider-command");
        assert_eq!(request.destination_port, MAX_MESH_PORT);
        assert!(matches!(
            request.config.iter().find(|(key, _)| key == "extension"),
            Some((_, Value::Object(_)))
        ));
    }

    #[test]
    fn mesh_agent_contracts_are_typed() {
        let request = Value::object(vec![
            ("kind", Value::from("survey")),
            (
                "agentContext",
                Value::object(vec![
                    ("schema", Value::from("hovel.agent_context.v1")),
                    (
                        "entity",
                        Value::object(vec![
                            ("id", Value::from("operator-1")),
                            ("kind", Value::from("web")),
                            ("agent", Value::Bool(true)),
                        ]),
                    ),
                    ("phase", Value::from("execute")),
                    ("resources", Value::Array(vec![Value::from("mesh:node-1")])),
                ]),
            ),
        ]);
        let decoded = MeshTaskRequest::try_from_value(&request).expect("typed request");
        let agent = decoded.agent.expect("agent context");
        assert_eq!(agent.entity.id, "operator-1");
        assert_eq!(agent.entity.kind, "web");
        assert!(agent.entity.agent);
        assert_eq!(agent.resources, vec!["mesh:node-1"]);

        let result = MeshTaskResult {
            agent_hints: vec![AgentHint {
                schema: "hovel.agent_hint.v1".into(),
                phase: "execute".into(),
                audience: "assistant".into(),
                risk: "low".into(),
                applies_to: vec![("nodeId".into(), "node-1".into())],
                text: "Prefer read-only inspection.".into(),
                provenance: vec![("moduleId".into(), "mesh-provider@v1".into())],
            }],
            ..MeshTaskResult::default()
        }
        .to_value(Vec::new());
        let hints = result
            .get("agentHints")
            .and_then(Value::as_array)
            .expect("agent hints");
        assert_eq!(
            hints[0]
                .get("appliesTo")
                .and_then(|value| value.get("nodeId"))
                .and_then(Value::as_str),
            Some("node-1")
        );
    }

    #[test]
    fn mesh_stream_decoder_rejects_malformed_optional_fields() {
        let invalid = Value::object(vec![("config", Value::Array(Vec::new()))]);
        assert!(MeshStreamRequest::try_from_value(&invalid).is_err());
    }
}
