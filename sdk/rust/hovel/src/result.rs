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
            severity: if severity.is_empty() { "info".to_string() } else { severity.to_string() },
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

/// What a module returns from `run`. Build it with [`Outcome::ok`] or
/// [`Outcome::failed`] and the chaining `with_*` helpers.
pub struct Outcome {
    pub status: String,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<Artifact>,
    pub outputs: Vec<(String, Value)>,
    pub sessions: Vec<SessionRef>,
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

        Value::object(vec![
            ("status", Value::Str(self.status.clone())),
            ("summary", Value::Str(self.summary.clone())),
            ("findings", findings),
            ("artifacts", artifacts),
            ("outputs", Value::Object(self.outputs.clone())),
            ("sessions", Value::Array(sessions)),
        ])
    }
}
