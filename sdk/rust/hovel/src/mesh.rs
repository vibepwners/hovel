//! Node Mesh extension types.
//!
//! A Mesh is broader than a transport or tunnel: it is a provider-owned node
//! operations plane that may expose topology, routes, tasks, streams, triggers,
//! and beacons.

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

pub(crate) const DEFAULT_MESH_RUN_ID: &str = "mesh";
pub(crate) const MESH_RPC_DESCRIBE_METHOD: &str = "mesh.describe";
pub(crate) const MESH_RPC_TOPOLOGY_METHOD: &str = "mesh.topology";
pub(crate) const MESH_RPC_BEACONS_METHOD: &str = "mesh.beacons";
pub(crate) const MESH_RPC_TASK_METHOD: &str = "mesh.task";
pub(crate) const MESH_RPC_OPEN_STREAM_METHOD: &str = "mesh.open_stream";

#[derive(Clone, Debug, Default)]
pub struct MeshNode {
    pub id: String,
    pub parent_id: String,
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
    pub(crate) fn from_value(value: &Value) -> Option<MeshRoute> {
        match value {
            Value::Object(_) => Some(MeshRoute {
                id: string_field(value, "id"),
                nodes: string_array(value, "nodes"),
                links: string_array(value, "links"),
                cost: i64_field(value, "cost"),
                attributes: object_field(value, "attributes"),
            }),
            _ => None,
        }
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
pub struct MeshTrigger {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub node_id: String,
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
pub struct MeshDescriptor {
    pub name: String,
    pub version: String,
    pub summary: String,
    pub capabilities: Vec<String>,
    pub topology: MeshTopology,
    pub tasks: Vec<MeshTaskSpec>,
    pub triggers: Vec<MeshTrigger>,
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
        if !self.triggers.is_empty() {
            members.push((
                "triggers".to_string(),
                Value::Array(self.triggers.iter().map(MeshTrigger::to_value).collect()),
            ));
        }
        push_object(&mut members, "attributes", &self.attributes);
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshDescribeRequest {
    pub agent: Option<Value>,
}

impl MeshDescribeRequest {
    pub(crate) fn from_value(value: &Value) -> MeshDescribeRequest {
        MeshDescribeRequest {
            agent: value.get("agentContext").cloned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTopologyRequest {
    pub root: String,
    pub include_routes: bool,
    pub agent: Option<Value>,
}

impl MeshTopologyRequest {
    pub(crate) fn from_value(value: &Value) -> MeshTopologyRequest {
        MeshTopologyRequest {
            root: string_field(value, "root"),
            include_routes: bool_field(value, "includeRoutes"),
            agent: value.get("agentContext").cloned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshBeaconRequest {
    pub node_id: String,
    pub since: String,
    pub limit: i64,
    pub agent: Option<Value>,
}

impl MeshBeaconRequest {
    pub(crate) fn from_value(value: &Value) -> MeshBeaconRequest {
        MeshBeaconRequest {
            node_id: string_field(value, "nodeId"),
            since: string_field(value, "since"),
            limit: i64_field(value, "limit"),
            agent: value.get("agentContext").cloned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTaskRequest {
    pub run_id: String,
    pub task_id: String,
    pub kind: String,
    pub node_id: String,
    pub target: String,
    pub route: Option<MeshRoute>,
    pub destination_host: String,
    pub destination_port: i64,
    pub protocol: String,
    pub config: Vec<(String, Value)>,
    pub args: Vec<String>,
    pub input_data: String,
    pub input_encoding: String,
    pub agent: Option<Value>,
}

impl MeshTaskRequest {
    pub(crate) fn from_value(value: &Value) -> MeshTaskRequest {
        MeshTaskRequest {
            run_id: string_field(value, "runId"),
            task_id: string_field(value, "taskId"),
            kind: string_field(value, "kind"),
            node_id: string_field(value, "nodeId"),
            target: string_field(value, "target"),
            route: value.get("route").and_then(MeshRoute::from_value),
            destination_host: string_field(value, "destinationHost"),
            destination_port: i64_field(value, "destinationPort"),
            protocol: string_field(value, "protocol"),
            config: object_field(value, "config"),
            args: string_array(value, "args"),
            input_data: string_field(value, "inputData"),
            input_encoding: string_field(value, "inputEncoding"),
            agent: value.get("agentContext").cloned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTaskResult {
    pub task_id: String,
    pub status: String,
    pub summary: String,
    pub node_id: String,
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
    pub agent_hints: Vec<Value>,
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
            members.push(("agentHints".to_string(), Value::Array(self.agent_hints)));
        }
        Value::Object(members)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshEvent {
    pub id: String,
    pub kind: String,
    pub node_id: String,
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
    pub route: Option<MeshRoute>,
    pub destination_host: String,
    pub destination_port: i64,
    pub protocol: String,
    pub config: Vec<(String, Value)>,
    pub agent: Option<Value>,
}

impl MeshStreamRequest {
    pub(crate) fn from_value(value: &Value) -> MeshStreamRequest {
        MeshStreamRequest {
            run_id: string_field(value, "runId"),
            module_id: string_field(value, "moduleId"),
            target: string_field(value, "target"),
            node_id: string_field(value, "nodeId"),
            route: value.get("route").and_then(MeshRoute::from_value),
            destination_host: string_field(value, "destinationHost"),
            destination_port: i64_field(value, "destinationPort"),
            protocol: string_field(value, "protocol"),
            config: object_field(value, "config"),
            agent: value.get("agentContext").cloned(),
        }
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

fn object_field(value: &Value, key: &str) -> Vec<(String, Value)> {
    match value.get(key) {
        Some(Value::Object(members)) => members.clone(),
        _ => Vec::new(),
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
    use super::{context_params, i64_field, MeshBeacon, MeshEvent, MeshLink, MeshRoute};
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
}
