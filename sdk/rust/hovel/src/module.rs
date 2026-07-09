//! The module contract: metadata, configuration schema, and the [`Module`] trait.

use crate::context::Context;
use crate::mesh::{
    MeshBeacon, MeshBeaconRequest, MeshDescriptor, MeshDescribeRequest,
    MeshStreamRequest, MeshTaskRequest, MeshTaskResult, MeshTopology,
    MeshTopologyRequest,
};
use crate::json::Value;
use crate::result::Outcome;
use crate::session::SessionRef;

/// The kind of work a module performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleType {
    /// Gathers facts about a target without changing it.
    Survey,
    /// Performs an offensive action that may open a session.
    Exploit,
    /// Generates payloads for delivery by other modules.
    PayloadProvider,
}

impl ModuleType {
    /// The wire string for this type.
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleType::Survey => "survey",
            ModuleType::Exploit => "exploit",
            ModuleType::PayloadProvider => "payload_provider",
        }
    }
}

/// A single configuration field a module needs.
#[derive(Clone, Debug)]
pub struct Requirement {
    pub key: String,
    pub value_type: String,
    pub required: bool,
    pub default: String,
    pub description: String,
    pub allowed: Vec<String>,
    pub secret: bool,
}

impl Requirement {
    /// Builds a required requirement of the given type.
    pub fn new(key: &str, value_type: &str, description: &str) -> Requirement {
        Requirement {
            key: key.to_string(),
            value_type: value_type.to_string(),
            required: true,
            default: String::new(),
            description: description.to_string(),
            allowed: Vec::new(),
            secret: false,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::object(vec![
            ("key", Value::Str(self.key.clone())),
            ("type", Value::Str(self.value_type.clone())),
            ("required", Value::Bool(self.required)),
            ("default", Value::Str(self.default.clone())),
            ("description", Value::Str(self.description.clone())),
            (
                "allowed",
                Value::Array(self.allowed.iter().cloned().map(Value::Str).collect()),
            ),
            ("secret", Value::Bool(self.secret)),
        ])
    }
}

/// The metadata a module reports during the handshake. `name`, `version`, and
/// `module_type` are required; Hovel treats this handshake as authoritative
/// over any package-manifest hints.
pub struct Info {
    pub name: String,
    pub version: String,
    pub module_type: ModuleType,
    pub summary: String,
    pub description: String,
    pub tags: Vec<String>,
    pub discovery_context: Vec<(String, Value)>,
}

/// The configuration contract a module reports.
#[derive(Default)]
pub struct Schema {
    pub chain_config: Vec<Requirement>,
    pub target_config: Vec<Requirement>,
    pub outputs: Vec<(String, Value)>,
    pub planning_context: Vec<(String, Value)>,
}

/// Implemented by every Hovel module. `info` and `schema` must be cheap and
/// side-effect free; `run` does the work when the module is thrown.
pub trait Module {
    fn info(&self) -> Info;
    fn schema(&self) -> Schema;
    fn run(&self, ctx: &mut Context) -> Outcome;

    fn describe_mesh(
        &self,
        _req: MeshDescribeRequest,
    ) -> Result<MeshDescriptor, String> {
        Err(format!("module {:?} is not a mesh provider", self.info().name))
    }

    fn mesh_topology(
        &self,
        _req: MeshTopologyRequest,
    ) -> Result<MeshTopology, String> {
        Err(format!(
            "module {:?} does not implement mesh.topology",
            self.info().name
        ))
    }

    fn list_mesh_beacons(
        &self,
        _req: MeshBeaconRequest,
    ) -> Result<Vec<MeshBeacon>, String> {
        Err(format!(
            "module {:?} does not implement mesh.beacons",
            self.info().name
        ))
    }

    fn run_mesh_task(
        &self,
        _ctx: &mut Context,
        _req: MeshTaskRequest,
    ) -> Result<MeshTaskResult, String> {
        Err(format!(
            "module {:?} does not implement mesh.task",
            self.info().name
        ))
    }

    fn open_mesh_stream(
        &self,
        _ctx: &mut Context,
        _req: MeshStreamRequest,
    ) -> Result<SessionRef, String> {
        Err(format!(
            "module {:?} does not implement mesh.open_stream",
            self.info().name
        ))
    }
}
