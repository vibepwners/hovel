//! The Rust SDK for writing Hovel modules.
//!
//! A module is a separate process that the Hovel daemon launches and drives over
//! a small JSON-RPC 2.0 protocol carried on stdin/stdout, with each message
//! framed by a `Content-Length` header. Implement [`Module`] and hand it to
//! [`serve`]; this crate takes care of framing, dispatch, logging, and sessions.
//!
//! To stay dependency-free this crate hand-rolls a tiny [`json`] layer and
//! [`base64`] codec instead of pulling in `serde_json`. Real modules are free to
//! use whatever crates they like.
//!
//! ```no_run
//! use hovel::{Context, Info, Module, ModuleType, Outcome, Schema, json::Value};
//!
//! struct Hello;
//!
//! impl Module for Hello {
//!     fn info(&self) -> Info {
//!         Info {
//!             name: "hello-rust".into(),
//!             version: "v0.0.0".into(),
//!             module_type: ModuleType::Survey,
//!             summary: "say hello".into(),
//!             description: String::new(),
//!             tags: vec!["example".into()],
//!             discovery_context: Vec::new(),
//!         }
//!     }
//!     fn schema(&self) -> Schema { Schema::default() }
//!     fn run(&self, ctx: &mut Context) -> Outcome {
//!         ctx.info("hello", &[("target", Value::from(ctx.target.as_str()))]);
//!         Outcome::ok(vec![("greeting".into(), Value::from("hi"))])
//!     }
//! }
//!
//! hovel::serve(Hello);
//! ```

pub mod base64;
pub mod json;

mod context;
mod credential_delivery;
mod credential_provider;
mod framing;
mod mesh;
mod mesh_bridge;
mod module;
mod result;
mod server;
mod session;
mod sha256;

#[cfg(test)]
mod tests;

pub use context::Context;
pub use credential_delivery::{
    CredentialConsumerType, CredentialDeliveryCapability, CredentialDeliveryDescriptor,
    CredentialEndpointRole, CredentialMaterialForm, CredentialMaterialReference,
    CredentialPrivateMaterialPolicy, CredentialProjection, CredentialProviderEncodingSchema,
    CredentialProviderTargetSchema, CredentialPurpose, CredentialSlot, CredentialStampAddressSpace,
    CredentialStampMaterial, CredentialStampPrecondition, CredentialStampRemainderPolicy,
    CredentialStampRequest, CredentialStampTarget, CredentialStampTargetKind,
    ResolvedCredentialMetadata, CREDENTIAL_DELIVERY_SCHEMA_V1,
};
pub use credential_provider::{
    CredentialArtifactContent, CredentialArtifactInput, CredentialArtifactOutput, CredentialBytes,
    CredentialDeliveryReceipt, CredentialDeploymentOutput, CredentialEncodingRequest,
    CredentialEncodingResult, CredentialFile, CredentialFilesRequest, CredentialMaterialValue,
    CredentialOperationScope, CredentialProtectedPath, CredentialProviderTarget,
    CredentialRuntimeRequest, CredentialScopedReference, CredentialSecretReference,
    CredentialStampExecutionRequest, CredentialStampExecutionResult, CredentialStampOutput,
    CredentialStampTargetResolution, CredentialStampedMaterialDigest, ResolvedCredentialMaterial,
    CREDENTIAL_ENCODING_RAW, CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
};
pub use mesh::{
    AgentContext, AgentEntity, AgentHint, MeshBeacon, MeshBeaconRequest, MeshDescribeRequest,
    MeshDescriptor, MeshEvent, MeshLink, MeshListener, MeshListenerListRequest, MeshListenerSpec,
    MeshListenerStartRequest, MeshListenerStopRequest, MeshNode, MeshRoute, MeshStreamRequest,
    MeshTaskRequest, MeshTaskResult, MeshTaskSpec, MeshTopology, MeshTopologyRequest, MeshTrigger,
    MESH_LISTENER_DEPLOYMENT_EMBEDDED, MESH_LISTENER_DEPLOYMENT_SEPARATE,
    MESH_LISTENER_MANAGEMENT_EXTERNAL, MESH_LISTENER_MANAGEMENT_PROVIDER,
    MESH_LISTENER_STATE_ACTIVE, MESH_LISTENER_STATE_FAILED, MESH_LISTENER_STATE_STARTING,
    MESH_LISTENER_STATE_STOPPED, MESH_LISTENER_STATE_STOPPING, MESH_TARGET_DESTINATION,
    MESH_TARGET_NODE, MESH_TARGET_ROUTE, MESH_TASK_COMMAND, MESH_TASK_EXECUTE, MESH_TASK_LOAD,
    MESH_TASK_STATUS_FAILED, MESH_TASK_STATUS_SUCCEEDED, MESH_TASK_STREAM, MESH_TASK_SURVEY,
    MESH_TASK_UPLOAD, MESH_TASK_UPLOAD_EXECUTE,
};
pub use mesh_bridge::{
    connect_mesh_bridge, connect_mesh_bridge_tcp, connect_mesh_bridge_udp, MeshBridgeCapability,
    MeshBridgeConnection, MeshBridgeEndpoint, MeshBridgeNetwork, ParseMeshBridgeNetworkError,
};
pub use module::{Info, Module, ModuleType, Requirement, Schema};
pub use result::{Artifact, Finding, InstalledPayloadDescriptor, Outcome, PayloadProviderRecord};
pub use server::{serve, serve_with};
pub use session::{
    LineShellSession, Session, SessionOptions, SessionRef, SESSION_CAPABILITY_DATAGRAM,
};
