//! The value a module returns from `run`.
//!
//! Named [`Outcome`] to avoid colliding with the standard library's `Result`.
//! It is the Rust equivalent of the Python/Go `Result` type.

use crate::json::Value;
use crate::session::SessionRef;

/// A single observation a module reports.
#[derive(Clone, Debug)]
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub detail: String,
}

impl Finding {
    /// Builds a finding; severity defaults to "info" when empty.
    pub fn new(title: &str, severity: &str, detail: &str) -> Finding {
        Finding {
            title: title.to_string(),
            severity: if severity.is_empty() {
                "info".to_string()
            } else {
                severity.to_string()
            },
            detail: detail.to_string(),
        }
    }

    fn to_value(&self) -> Value {
        Value::object(vec![
            ("title", Value::Str(self.title.clone())),
            ("severity", Value::Str(self.severity.clone())),
            ("detail", Value::Str(self.detail.clone())),
        ])
    }
}

/// A blob a module produces — inline data or a path on disk.
#[derive(Clone, Debug)]
pub struct Artifact {
    pub name: String,
    pub kind: String,
    pub data: String,
    pub path: String,
}

impl Artifact {
    /// An inline artifact carrying data directly (kind is a MIME type).
    pub fn inline(name: &str, kind: &str, data: &str) -> Artifact {
        Artifact {
            name: name.to_string(),
            kind: kind.to_string(),
            data: data.to_string(),
            path: String::new(),
        }
    }

    /// An inline text/plain artifact.
    pub fn text(name: &str, data: &str) -> Artifact {
        Artifact::inline(name, "text/plain", data)
    }

    fn to_value(&self) -> Value {
        let mut members = vec![
            ("name".to_string(), Value::Str(self.name.clone())),
            ("kind".to_string(), Value::Str(self.kind.clone())),
        ];
        if !self.data.is_empty() {
            members.push(("data".to_string(), Value::Str(self.data.clone())));
        }
        if !self.path.is_empty() {
            members.push(("path".to_string(), Value::Str(self.path.clone())));
        }
        Value::Object(members)
    }
}

/// Opaque provider-owned reconnect or cleanup data attached to an installed
/// payload descriptor. Hovel persists the record and routes future payload
/// operations back to the provider; it does not interpret the descriptor.
#[derive(Clone, Debug)]
pub struct PayloadProviderRecord {
    pub provider_id: String,
    pub schema: String,
    pub schema_version: String,
    pub descriptor: Vec<(String, Value)>,
}

impl PayloadProviderRecord {
    /// Builds a provider record with a schema name and opaque descriptor object.
    pub fn new(schema: &str, descriptor: Vec<(String, Value)>) -> PayloadProviderRecord {
        PayloadProviderRecord {
            provider_id: String::new(),
            schema: schema.to_string(),
            schema_version: String::new(),
            descriptor,
        }
    }

    /// Sets the provider id that owns this record.
    pub fn with_provider_id(mut self, provider_id: &str) -> PayloadProviderRecord {
        self.provider_id = provider_id.to_string();
        self
    }

    /// Sets the provider-owned schema version.
    pub fn with_schema_version(mut self, schema_version: &str) -> PayloadProviderRecord {
        self.schema_version = schema_version.to_string();
        self
    }

    fn to_value(&self) -> Value {
        let mut members = Vec::new();
        if !self.provider_id.is_empty() {
            members.push((
                "providerId".to_string(),
                Value::Str(self.provider_id.clone()),
            ));
        }
        if !self.schema.is_empty() {
            members.push(("schema".to_string(), Value::Str(self.schema.clone())));
        }
        if !self.schema_version.is_empty() {
            members.push((
                "schemaVersion".to_string(),
                Value::Str(self.schema_version.clone()),
            ));
        }
        if !self.descriptor.is_empty() {
            members.push((
                "descriptor".to_string(),
                Value::Object(self.descriptor.clone()),
            ));
        }
        Value::Object(members)
    }
}

/// A durable target-side payload instance a module explicitly asks Hovel to
/// track. Modules return this only when they installed or observed a payload
/// instance that should become installed-payload inventory.
#[derive(Clone, Debug)]
pub struct InstalledPayloadDescriptor {
    pub provider: String,
    pub payload_id: String,
    pub payload_version: String,
    pub target: String,
    pub target_id: String,
    pub state: String,
    pub transport: String,
    pub endpoint: String,
    pub instance_key: String,
    pub stamp_id: String,
    pub artifact_ids: Vec<String>,
    pub supports_reconnect: bool,
    pub supports_multiple_sessions: bool,
    pub reconnect: Option<PayloadProviderRecord>,
    pub cleanup: Option<PayloadProviderRecord>,
    pub metadata: Vec<(String, Value)>,
}

impl InstalledPayloadDescriptor {
    /// Builds an installed payload descriptor in the "installed" state.
    pub fn new(provider: &str, payload_id: &str, target: &str) -> InstalledPayloadDescriptor {
        InstalledPayloadDescriptor {
            provider: provider.to_string(),
            payload_id: payload_id.to_string(),
            payload_version: String::new(),
            target: target.to_string(),
            target_id: String::new(),
            state: "installed".to_string(),
            transport: String::new(),
            endpoint: String::new(),
            instance_key: String::new(),
            stamp_id: String::new(),
            artifact_ids: Vec::new(),
            supports_reconnect: false,
            supports_multiple_sessions: false,
            reconnect: None,
            cleanup: None,
            metadata: Vec::new(),
        }
    }

    pub fn with_payload_version(mut self, payload_version: &str) -> InstalledPayloadDescriptor {
        self.payload_version = payload_version.to_string();
        self
    }

    pub fn with_target_id(mut self, target_id: &str) -> InstalledPayloadDescriptor {
        self.target_id = target_id.to_string();
        self
    }

    pub fn with_state(mut self, state: &str) -> InstalledPayloadDescriptor {
        self.state = state.to_string();
        self
    }

    pub fn with_transport(mut self, transport: &str) -> InstalledPayloadDescriptor {
        self.transport = transport.to_string();
        self
    }

    pub fn with_endpoint(mut self, endpoint: &str) -> InstalledPayloadDescriptor {
        self.endpoint = endpoint.to_string();
        self
    }

    pub fn with_instance_key(mut self, instance_key: &str) -> InstalledPayloadDescriptor {
        self.instance_key = instance_key.to_string();
        self
    }

    pub fn with_stamp_id(mut self, stamp_id: &str) -> InstalledPayloadDescriptor {
        self.stamp_id = stamp_id.to_string();
        self
    }

    pub fn with_artifact_id(mut self, artifact_id: &str) -> InstalledPayloadDescriptor {
        self.artifact_ids.push(artifact_id.to_string());
        self
    }

    pub fn with_supports_reconnect(
        mut self,
        supports_reconnect: bool,
    ) -> InstalledPayloadDescriptor {
        self.supports_reconnect = supports_reconnect;
        self
    }

    pub fn with_supports_multiple_sessions(
        mut self,
        supports_multiple_sessions: bool,
    ) -> InstalledPayloadDescriptor {
        self.supports_multiple_sessions = supports_multiple_sessions;
        self
    }

    pub fn with_reconnect(
        mut self,
        reconnect: PayloadProviderRecord,
    ) -> InstalledPayloadDescriptor {
        self.reconnect = Some(reconnect);
        self
    }

    pub fn with_cleanup(mut self, cleanup: PayloadProviderRecord) -> InstalledPayloadDescriptor {
        self.cleanup = Some(cleanup);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: Value) -> InstalledPayloadDescriptor {
        self.metadata.push((key.to_string(), value));
        self
    }

    fn to_value(&self) -> Value {
        let mut members = vec![
            ("provider".to_string(), Value::Str(self.provider.clone())),
            ("payloadId".to_string(), Value::Str(self.payload_id.clone())),
            ("target".to_string(), Value::Str(self.target.clone())),
            ("state".to_string(), Value::Str(self.state.clone())),
        ];
        push_string(&mut members, "payloadVersion", &self.payload_version);
        push_string(&mut members, "targetId", &self.target_id);
        push_string(&mut members, "transport", &self.transport);
        push_string(&mut members, "endpoint", &self.endpoint);
        push_string(&mut members, "instanceKey", &self.instance_key);
        push_string(&mut members, "stampId", &self.stamp_id);
        if !self.artifact_ids.is_empty() {
            members.push((
                "artifactIds".to_string(),
                Value::Array(self.artifact_ids.iter().cloned().map(Value::Str).collect()),
            ));
        }
        if self.supports_reconnect {
            members.push(("supportsReconnect".to_string(), Value::Bool(true)));
        }
        if self.supports_multiple_sessions {
            members.push(("supportsMultipleSessions".to_string(), Value::Bool(true)));
        }
        if let Some(reconnect) = &self.reconnect {
            members.push(("reconnect".to_string(), reconnect.to_value()));
        }
        if let Some(cleanup) = &self.cleanup {
            members.push(("cleanup".to_string(), cleanup.to_value()));
        }
        if !self.metadata.is_empty() {
            members.push(("metadata".to_string(), Value::Object(self.metadata.clone())));
        }
        Value::Object(members)
    }
}

fn push_string(members: &mut Vec<(String, Value)>, key: &str, value: &str) {
    if !value.is_empty() {
        members.push((key.to_string(), Value::Str(value.to_string())));
    }
}

/// What a module returns from `run`. Build it with [`Outcome::ok`] or
/// [`Outcome::failed`] and the chaining `with_*` helpers.
pub struct Outcome {
    pub status: String,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<Artifact>,
    pub outputs: Vec<(String, Value)>,
    pub sessions: Vec<SessionRef>,
    pub installed_payloads: Vec<InstalledPayloadDescriptor>,
    pub agent_hints: Vec<Value>,
}

impl Outcome {
    /// A succeeded outcome carrying the given outputs.
    pub fn ok(outputs: Vec<(String, Value)>) -> Outcome {
        Outcome {
            status: "succeeded".to_string(),
            summary: "module completed".to_string(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            outputs,
            sessions: Vec::new(),
            installed_payloads: Vec::new(),
            agent_hints: Vec::new(),
        }
    }

    /// A failed outcome with the given summary.
    pub fn failed(summary: &str) -> Outcome {
        Outcome {
            status: "failed".to_string(),
            summary: summary.to_string(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            outputs: Vec::new(),
            sessions: Vec::new(),
            installed_payloads: Vec::new(),
            agent_hints: Vec::new(),
        }
    }

    /// Sets the human-readable summary line.
    pub fn with_summary(mut self, summary: &str) -> Outcome {
        self.summary = summary.to_string();
        self
    }

    /// Appends a finding.
    pub fn with_finding(mut self, finding: Finding) -> Outcome {
        self.findings.push(finding);
        self
    }

    /// Appends an artifact.
    pub fn with_artifact(mut self, artifact: Artifact) -> Outcome {
        self.artifacts.push(artifact);
        self
    }

    /// Appends an explicit installed-payload descriptor to the outcome.
    pub fn with_installed_payload(mut self, payload: InstalledPayloadDescriptor) -> Outcome {
        self.installed_payloads.push(payload);
        self
    }

    /// Appends module-authored guidance for agent-aware front ends.
    pub fn with_agent_hint(mut self, hint: Value) -> Outcome {
        self.agent_hints.push(hint);
        self
    }

    pub(crate) fn to_value(&self, extra_sessions: Vec<SessionRef>) -> Value {
        let findings = Value::Array(self.findings.iter().map(Finding::to_value).collect());
        let artifacts = Value::Array(self.artifacts.iter().map(Artifact::to_value).collect());

        let mut seen = Vec::new();
        let mut sessions = Vec::new();
        for session in self.sessions.iter().chain(extra_sessions.iter()) {
            if seen.contains(&session.id) {
                continue;
            }
            seen.push(session.id.clone());
            sessions.push(session.to_value());
        }

        let mut members = vec![
            ("status", Value::Str(self.status.clone())),
            ("summary", Value::Str(self.summary.clone())),
            ("findings", findings),
            ("artifacts", artifacts),
            ("outputs", Value::Object(self.outputs.clone())),
            ("sessions", Value::Array(sessions)),
        ];
        if !self.installed_payloads.is_empty() {
            members.push((
                "installedPayloads",
                Value::Array(
                    self.installed_payloads
                        .iter()
                        .map(InstalledPayloadDescriptor::to_value)
                        .collect(),
                ),
            ));
        }
        if !self.agent_hints.is_empty() {
            members.push(("agentHints", Value::Array(self.agent_hints.clone())));
        }
        Value::object(members)
    }
}
