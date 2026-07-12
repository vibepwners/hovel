//! Unit tests for the Rust SDK, run via `rust_test(crate = ":hovel")`.

use std::cell::Cell;
use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use crate::credential_provider::{
    CREDENTIAL_RPC_ENCODE_METHOD, CREDENTIAL_RPC_FILES_METHOD, CREDENTIAL_RPC_RUNTIME_METHOD,
    CREDENTIAL_RPC_STAMP_METHOD,
};
use crate::json::{self, Value};
use crate::{
    base64, serve_with, Context, CredentialArtifactContent, CredentialArtifactOutput,
    CredentialBytes, CredentialConsumerType, CredentialDeliveryCapability,
    CredentialDeliveryDescriptor, CredentialDeliveryReceipt, CredentialEncodingRequest,
    CredentialEncodingResult, CredentialEndpointRole, CredentialFilesRequest,
    CredentialMaterialForm, CredentialMaterialReference, CredentialMaterialValue,
    CredentialPrivateMaterialPolicy, CredentialProjection, CredentialProtectedPath,
    CredentialPurpose, CredentialRuntimeRequest, CredentialSecretReference, CredentialSlot,
    CredentialStampExecutionRequest, CredentialStampExecutionResult, CredentialStampMaterial,
    CredentialStampOutput, CredentialStampPrecondition, CredentialStampRemainderPolicy,
    CredentialStampRequest, CredentialStampTarget, CredentialStampTargetKind,
    CredentialStampTargetResolution, Info, InstalledPayloadDescriptor, LineShellSession,
    MeshBeacon, MeshBeaconRequest, MeshDescribeRequest, MeshDescriptor, MeshLink, MeshListener,
    MeshListenerListRequest, MeshListenerSpec, MeshListenerStartRequest, MeshListenerStopRequest,
    MeshNode, MeshRoute, MeshStreamRequest, MeshTaskRequest, MeshTaskResult, MeshTaskSpec,
    MeshTopology, MeshTopologyRequest, MeshTrigger, Module, ModuleType, Outcome,
    PayloadProviderRecord, ResolvedCredentialMaterial, ResolvedCredentialMetadata, Schema, Session,
    SessionOptions, CREDENTIAL_DELIVERY_SCHEMA_V1, CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
    MESH_LISTENER_DEPLOYMENT_SEPARATE, MESH_LISTENER_MANAGEMENT_PROVIDER,
    MESH_LISTENER_STATE_ACTIVE, MESH_LISTENER_STATE_STOPPED, MESH_TARGET_DESTINATION,
    MESH_TARGET_NODE, MESH_TASK_COMMAND, MESH_TASK_SURVEY, MESH_TASK_UPLOAD_EXECUTE,
};

#[test]
fn json_round_trips() {
    let text = r#"{"a":1,"b":[true,null,"x\n"],"c":{"d":-2.5}}"#;
    let value = json::parse(text).expect("parse");
    assert_eq!(value.get("a").and_then(Value::as_f64), Some(1.0));
    assert_eq!(value.to_string(), text);
}

#[test]
fn base64_round_trips() {
    for sample in ["", "f", "fo", "foo", "hello, world\n"] {
        let encoded = base64::encode(sample.as_bytes());
        let decoded = base64::decode(&encoded).expect("decode");
        assert_eq!(decoded, sample.as_bytes());
    }
}

#[test]
fn base64_rejects_noncanonical_wire_values() {
    let cases = [
        ("missing padding", "Zg"),
        ("whitespace", "Zg==\n"),
        ("padding before final quartet", "Zg==AAAA"),
        ("single-byte non-zero pad bits", "Zh=="),
        ("two-byte non-zero pad bits", "Zm9="),
        ("padding in first position", "=m9v"),
        ("incomplete padding", "Zg=A"),
        ("invalid alphabet", "Zm?="),
    ];
    for (name, value) in cases {
        assert!(base64::decode(value).is_err(), "accepted {name}: {value:?}");
    }
}

#[test]
fn advanced_credential_stamp_contract_uses_canonical_wire_types() {
    let request = CredentialStampRequest {
        assignment_id: "assignment-1".into(),
        capability: CredentialDeliveryCapability::StampAdvanced,
        slot_name: "tls-server".into(),
        target: CredentialStampTarget::BytePattern {
            pattern: vec![0xaa, 0xbb],
            mask: vec![0xff, 0x0f],
            occurrence: 1,
            maximum_length: "18446744073709551615".into(),
            remainder_policy: CredentialStampRemainderPolicy::ZeroFill,
            precondition: CredentialStampPrecondition::Sha256 {
                sha256: "0".repeat(64),
                length: "2".into(),
            },
        },
        material: CredentialStampMaterial::Credential(CredentialMaterialReference {
            projection: CredentialProjection::Bundle,
            form: CredentialMaterialForm::PrivateBytes,
            bundle_id: Some("bundle-1".into()),
            generation_id: None,
            generation_ids: Vec::new(),
            trust_set_generation_id: None,
            crl_generation_ids: Vec::new(),
        }),
        encoded_bytes: 4096,
        credential: ResolvedCredentialMetadata {
            bundle_version: "hovel.pki.bundle/v1".into(),
            purpose: CredentialPurpose::TlsServer,
            consumer_type: CredentialConsumerType::MeshProvider,
            profile_id: "tls-server".into(),
            compatibility_target_id: "mbedtls-3".into(),
        },
    };

    let wire = request.to_value();
    let pattern = wire
        .get("target")
        .and_then(|target| target.get("bytePattern"))
        .expect("byte-pattern target");
    assert_eq!(
        pattern.get("maximumLength").and_then(Value::as_str),
        Some("18446744073709551615")
    );
    assert_eq!(
        pattern.get("pattern").and_then(Value::as_str),
        Some(base64::encode(&[0xaa, 0xbb]).as_str())
    );
    assert_eq!(
        wire.get("material")
            .and_then(|material| material.get("credential"))
            .and_then(|credential| credential.get("bundleId"))
            .and_then(Value::as_str),
        Some("bundle-1")
    );
}

#[test]
fn credential_provider_secrets_are_redacted_from_debug() {
    let secret = CredentialSecretReference::new("capability-secret").unwrap();
    let path = CredentialProtectedPath::new("/secret/private-key.der").unwrap();
    let byte_artifact = CredentialArtifactOutput {
        name: "stamped.bin".into(),
        encoding: "raw".into(),
        content: CredentialArtifactContent::Data(
            CredentialBytes::new(b"private-bytes".to_vec()).unwrap(),
        ),
    };
    let path_artifact = CredentialArtifactOutput {
        name: "stamped-path.bin".into(),
        encoding: "raw".into(),
        content: CredentialArtifactContent::Path(path.clone()),
    };
    let diagnostic = format!("{secret:?} {path:?} {byte_artifact:?} {path_artifact:?}");
    for value in [
        "capability-secret",
        "/secret/private-key.der",
        "private-bytes",
    ] {
        assert!(!diagnostic.contains(value), "debug leaked {value:?}");
    }
}

#[test]
fn credential_provider_secret_wrappers_and_material_reject_invalid_states() {
    assert!(CredentialBytes::new(Vec::new()).is_err());
    assert!(CredentialSecretReference::new("  ").is_err());
    assert!(CredentialProtectedPath::new("").is_err());

    let bytes = CredentialMaterialValue::Bytes(CredentialBytes::new(vec![1]).unwrap());
    assert!(ResolvedCredentialMaterial::new(
        CredentialProjection::Bundle,
        CredentialMaterialForm::PrivateReference,
        "raw",
        "0".repeat(64),
        bytes,
    )
    .is_err());
}

#[test]
fn credential_material_parser_rejects_invalid_union_states() {
    let bytes = Value::from(base64::encode(b"secret").as_str());
    let reference = Value::object(vec![
        ("providerId", Value::from("provider-1")),
        ("reference", Value::from("reference-1")),
    ]);
    let cases = [
        (
            "both variants",
            Value::object(vec![
                ("projection", Value::from("bundle")),
                ("form", Value::from("private-bytes")),
                ("encoding", Value::from("raw")),
                ("sha256", Value::from("0".repeat(64).as_str())),
                ("data", bytes.clone()),
                ("reference", reference.clone()),
            ]),
        ),
        (
            "missing variant",
            Value::object(vec![
                ("projection", Value::from("bundle")),
                ("form", Value::from("private-bytes")),
                ("encoding", Value::from("raw")),
                ("sha256", Value::from("0".repeat(64).as_str())),
            ]),
        ),
        (
            "reference form with bytes",
            Value::object(vec![
                ("projection", Value::from("bundle")),
                ("form", Value::from("private-reference")),
                ("encoding", Value::from("raw")),
                ("sha256", Value::from("0".repeat(64).as_str())),
                ("data", bytes),
            ]),
        ),
        (
            "byte form with reference",
            Value::object(vec![
                ("projection", Value::from("bundle")),
                ("form", Value::from("private-bytes")),
                ("encoding", Value::from("raw")),
                ("sha256", Value::from("0".repeat(64).as_str())),
                ("reference", reference),
            ]),
        ),
    ];
    for (name, material) in cases {
        let request = credential_runtime_request_value(material);
        assert!(
            CredentialRuntimeRequest::from_value(&request).is_err(),
            "accepted {name}"
        );
    }
}

fn credential_runtime_request_value(material: Value) -> Value {
    Value::object(vec![
        (
            "schemaVersion",
            Value::from(CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1),
        ),
        (
            "provider",
            Value::object(vec![
                ("moduleId", Value::from("provider-1")),
                ("providerId", Value::from("provider-1")),
                ("providerVersion", Value::from("v1")),
                ("descriptorSha256", Value::from("0".repeat(64).as_str())),
            ]),
        ),
        ("requestId", Value::from("request-1")),
        ("assignmentId", Value::from("assignment-1")),
        ("slotName", Value::from("tls-server")),
        (
            "credential",
            Value::object(vec![
                ("bundleVersion", Value::from("hovel.pki.bundle/v1")),
                ("purpose", Value::from("tls-server")),
                ("consumerType", Value::from("mesh-listener")),
                ("profileId", Value::from("tls-server")),
                ("compatibilityTargetId", Value::from("portable-x509")),
            ]),
        ),
        ("material", material),
        ("scope", Value::Object(Vec::new())),
    ])
}

#[test]
fn line_shell_answers_commands() {
    let mut shell = LineShellSession::new("mock$ ", true, |command| match command {
        "whoami" => "mock-operator".to_string(),
        other => format!("unknown: {other}"),
    });
    shell.open().unwrap();
    let prompt = shell.read(0).unwrap();
    assert_eq!(prompt, b"mock$ ");
    shell.write(b"whoami\n").unwrap();
    // echo, then output, then a fresh prompt.
    let echo = shell.read(0).unwrap();
    assert_eq!(echo, b"whoami\n");
    let output = shell.read(0).unwrap();
    assert_eq!(output, b"mock-operator\n");
}

#[test]
fn line_shell_handles_backspace() {
    let mut shell = LineShellSession::new("$ ", true, |command| format!("you said: {command}"));
    shell.open().unwrap();
    let _ = shell.read(0).unwrap(); // opening prompt

    // Type "whoamx", press backspace (DEL) to erase the 'x', then "i" + Enter.
    shell.write(b"whoamx").unwrap();
    shell.write(&[0x7f]).unwrap();
    shell.write(b"i\n").unwrap();

    let mut out = Vec::new();
    loop {
        let chunk = shell.read(0).unwrap();
        if chunk.is_empty() {
            break;
        }
        out.extend(chunk);
    }
    let text = String::from_utf8_lossy(&out);
    // The command the handler saw is "whoami", not "whoamxi" or "whoamx\x7fi".
    assert!(
        text.contains("you said: whoami"),
        "command was mangled: {text:?}"
    );
    // The backspace emitted a visual erase sequence.
    assert!(
        out.windows(3).any(|w| w == b"\x08 \x08"),
        "no erase sequence: {out:?}"
    );
}

#[test]
fn line_shell_honors_read_timeout() {
    use std::time::{Duration, Instant};

    let mut shell = LineShellSession::new("$ ", false, |_| String::new());
    shell.open().unwrap();
    assert_eq!(shell.read(0).unwrap(), b"$ "); // opening prompt, non-blocking

    // An idle read with a positive wait blocks for roughly that long, then
    // returns empty — rather than spinning by returning instantly.
    let start = Instant::now();
    let chunk = shell.read(20).unwrap();
    let elapsed = start.elapsed();
    assert!(chunk.is_empty());
    assert!(
        elapsed >= Duration::from_millis(10),
        "idle read returned too fast: {elapsed:?}"
    );

    // wait == 0 stays a non-blocking poll.
    let start = Instant::now();
    assert!(shell.read(0).unwrap().is_empty());
    assert!(start.elapsed() < Duration::from_millis(10));
}

/// A writer that appends to a shared buffer so tests can inspect module output.
#[derive(Clone)]
struct SharedBuf(Rc<RefCell<Vec<u8>>>);

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FakeModule {
    with_session: bool,
}

impl Module for FakeModule {
    fn info(&self) -> Info {
        Info {
            name: "fake-rust".into(),
            version: "v0.0.0-test".into(),
            module_type: ModuleType::Survey,
            summary: "fake".into(),
            description: String::new(),
            tags: vec!["example".into(), "test".into()],
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema {
            target_config: vec![crate::Requirement::new(
                "target.host",
                "host",
                "Target host.",
            )],
            ..Schema::default()
        }
    }

    fn run(&self, ctx: &mut Context) -> Outcome {
        ctx.info("running", &[("target", Value::from(ctx.target.as_str()))]);
        if self.with_session {
            let shell = LineShellSession::new("mock$ ", true, |command| {
                if command == "whoami" {
                    "mock-operator".to_string()
                } else {
                    format!("unknown: {command}")
                }
            });
            let sref = ctx
                .open_session(
                    Box::new(shell),
                    SessionOptions::default().with_name("mock shell"),
                )
                .expect("open session");
            return Outcome::ok(vec![("sessionId".into(), Value::from(sref.id.as_str()))])
                .with_summary("opened session");
        }
        let host = ctx.input_str("target.host", &ctx.target);
        Outcome::ok(vec![("host".into(), Value::from(host.as_str()))])
            .with_summary(&format!("surveyed {host}"))
    }
}

struct MissingVersionModule;

impl Module for MissingVersionModule {
    fn info(&self) -> Info {
        Info {
            name: "missing-version".into(),
            version: String::new(),
            module_type: ModuleType::Survey,
            summary: String::new(),
            description: String::new(),
            tags: Vec::new(),
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema::default()
    }

    fn run(&self, _ctx: &mut Context) -> Outcome {
        Outcome::ok(Vec::new())
    }
}

struct AgentAwareModule;

impl Module for AgentAwareModule {
    fn info(&self) -> Info {
        Info {
            name: "agent-aware-rust".into(),
            version: "v0.0.0-test".into(),
            module_type: ModuleType::Survey,
            summary: "agent aware".into(),
            description: String::new(),
            tags: Vec::new(),
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema::default()
    }

    fn run(&self, ctx: &mut Context) -> Outcome {
        let entity_kind = ctx
            .agent
            .as_ref()
            .and_then(|agent| agent.get("entity"))
            .and_then(|entity| entity.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut outcome = Outcome::ok(vec![
            ("agentPresent".into(), Value::Bool(ctx.agent.is_some())),
            ("entityKind".into(), Value::from(entity_kind)),
        ]);
        if ctx.agent.is_some() {
            outcome = outcome.with_agent_hint(Value::object(vec![
                ("schema", Value::from("hovel.agent_hint.v1")),
                ("phase", Value::from("execute")),
                ("audience", Value::from("assistant")),
                ("risk", Value::from("low")),
                (
                    "text",
                    Value::from("Prefer read-only inspection before changing state."),
                ),
            ]));
        }
        outcome
    }
}

struct FakeMeshModule;

fn fake_credential_delivery_descriptor() -> CredentialDeliveryDescriptor {
    CredentialDeliveryDescriptor {
        capabilities: vec![
            CredentialDeliveryCapability::Runtime,
            CredentialDeliveryCapability::StampStandard,
        ],
        slots: vec![CredentialSlot {
            name: "control-plane-mtls".into(),
            purpose: CredentialPurpose::MtlsServer,
            endpoint_role: CredentialEndpointRole::Server,
            consumer_type: CredentialConsumerType::MeshListener,
            accepted_bundle_versions: vec!["hovel.pki.bundle/v1".into()],
            accepted_profiles: vec!["mtls-server".into()],
            accepted_compatibility_targets: vec!["portable-x509".into()],
            accepted_projections: vec![CredentialProjection::Bundle],
            accepted_material_forms: vec![CredentialMaterialForm::PrivateBytes],
            maximum_encoded_bytes: 16 * 1024,
            remainder_policy: CredentialStampRemainderPolicy::Preserve,
            private_material: CredentialPrivateMaterialPolicy::Allowed,
        }],
        stamp_target_kinds: vec![CredentialStampTargetKind::NamedSlot],
        ..CredentialDeliveryDescriptor::default()
    }
}

impl Module for FakeMeshModule {
    fn info(&self) -> Info {
        Info {
            name: "fake-mesh-rust".into(),
            version: "v0.0.0-test".into(),
            module_type: ModuleType::PayloadProvider,
            summary: "fake node mesh".into(),
            description: String::new(),
            tags: vec!["test".into(), "mesh".into()],
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema::default()
    }

    fn run(&self, _ctx: &mut Context) -> Outcome {
        Outcome::ok(Vec::new()).with_summary("mesh provider execute placeholder")
    }

    fn describe_credential_delivery(&self) -> Result<CredentialDeliveryDescriptor, String> {
        Ok(fake_credential_delivery_descriptor())
    }

    fn describe_mesh(&self, _req: MeshDescribeRequest) -> Result<MeshDescriptor, String> {
        Ok(MeshDescriptor {
            name: "fake-mesh-rust".into(),
            version: "v0.0.0-test".into(),
            summary: "tree-routed test mesh".into(),
            capabilities: vec![
                "topology.tree".into(),
                "task.survey".into(),
                "task.command".into(),
                "stream.tcp".into(),
            ],
            topology: fake_mesh_topology(true),
            tasks: vec![
                MeshTaskSpec {
                    kind: MESH_TASK_SURVEY.into(),
                    summary: "survey a mesh node".into(),
                    read_only: true,
                    target_scopes: vec![MESH_TARGET_NODE.into()],
                    ..MeshTaskSpec::default()
                },
                MeshTaskSpec {
                    kind: MESH_TASK_COMMAND.into(),
                    summary: "run a node command or routed destination command".into(),
                    target_scopes: vec![MESH_TARGET_NODE.into(), MESH_TARGET_DESTINATION.into()],
                    ..MeshTaskSpec::default()
                },
                MeshTaskSpec {
                    kind: MESH_TASK_UPLOAD_EXECUTE.into(),
                    summary: "upload and execute a file".into(),
                    destructive: true,
                    target_scopes: vec![MESH_TARGET_NODE.into(), MESH_TARGET_DESTINATION.into()],
                    ..MeshTaskSpec::default()
                },
            ],
            listener_types: vec![MeshListenerSpec {
                kind: "https".into(),
                summary: "HTTPS rendezvous listener".into(),
                deployments: vec![MESH_LISTENER_DEPLOYMENT_SEPARATE.into()],
                management_modes: vec![MESH_LISTENER_MANAGEMENT_PROVIDER.into()],
                protocols: vec!["https".into()],
                config_schema: vec![("type".into(), Value::from("object"))],
                capabilities: Vec::new(),
            }],
            triggers: vec![MeshTrigger {
                id: "trig-beacon-command".into(),
                kind: "beacon".into(),
                node_id: "node-2".into(),
                state: "armed".into(),
                action_kind: MESH_TASK_COMMAND.into(),
                ..MeshTrigger::default()
            }],
            credential_delivery: Some(fake_credential_delivery_descriptor()),
            attributes: Vec::new(),
        })
    }

    fn mesh_topology(&self, req: MeshTopologyRequest) -> Result<MeshTopology, String> {
        Ok(fake_mesh_topology(req.include_routes))
    }

    fn list_mesh_beacons(&self, req: MeshBeaconRequest) -> Result<Vec<MeshBeacon>, String> {
        let node_id = if req.node_id.is_empty() {
            "node-2"
        } else {
            req.node_id.as_str()
        };
        Ok(vec![MeshBeacon {
            id: "beacon-1".into(),
            node_id: node_id.into(),
            listener_id: "listener-primary".into(),
            time: "2026-07-09T00:00:00Z".into(),
            state: "alive".into(),
            transport: "relay".into(),
            remote_addr: "10.0.0.2:4444".into(),
            interval_seconds: 30,
            fields: vec![("route".into(), Value::from("root>node-1>node-2"))],
        }])
    }

    fn list_mesh_listeners(
        &self,
        req: MeshListenerListRequest,
    ) -> Result<Vec<MeshListener>, String> {
        Ok(vec![MeshListener {
            id: if req.listener_id.is_empty() {
                "listener-primary".into()
            } else {
                req.listener_id
            },
            name: "primary HTTPS listener".into(),
            kind: "https".into(),
            state: MESH_LISTENER_STATE_ACTIVE.into(),
            deployment: MESH_LISTENER_DEPLOYMENT_SEPARATE.into(),
            management: MESH_LISTENER_MANAGEMENT_PROVIDER.into(),
            addresses: vec!["https://127.0.0.1:8443".into()],
            protocols: vec!["https".into()],
            ..MeshListener::default()
        }])
    }

    fn start_mesh_listener(&self, req: MeshListenerStartRequest) -> Result<MeshListener, String> {
        Ok(MeshListener {
            id: req.listener_id,
            name: req.name,
            kind: req.kind,
            state: MESH_LISTENER_STATE_ACTIVE.into(),
            deployment: req.deployment,
            management: req.management,
            addresses: vec!["https://127.0.0.1:8443".into()],
            protocols: vec!["https".into()],
            ..MeshListener::default()
        })
    }

    fn stop_mesh_listener(&self, req: MeshListenerStopRequest) -> Result<MeshListener, String> {
        Ok(MeshListener {
            id: req.listener_id,
            state: MESH_LISTENER_STATE_STOPPED.into(),
            deployment: MESH_LISTENER_DEPLOYMENT_SEPARATE.into(),
            management: MESH_LISTENER_MANAGEMENT_PROVIDER.into(),
            ..MeshListener::default()
        })
    }

    fn load_runtime_credential(
        &self,
        req: CredentialRuntimeRequest,
    ) -> Result<CredentialDeliveryReceipt, String> {
        Ok(CredentialDeliveryReceipt {
            request_id: req.request_id,
            provider_reference: Some("runtime-loaded".into()),
            receipt_sha256: None,
        })
    }

    fn load_credential_files(
        &self,
        req: CredentialFilesRequest,
    ) -> Result<CredentialDeliveryReceipt, String> {
        Ok(CredentialDeliveryReceipt {
            request_id: req.request_id,
            provider_reference: Some("files-loaded".into()),
            receipt_sha256: None,
        })
    }

    fn encode_credential_material(
        &self,
        req: CredentialEncodingRequest,
    ) -> Result<CredentialEncodingResult, String> {
        Ok(CredentialEncodingResult {
            request_id: req.request_id,
            form: req.output_form,
            encoding: "provider-test".into(),
            sha256: "1".repeat(64),
            data: CredentialBytes::new(b"encoded".to_vec()).unwrap(),
        })
    }

    fn stamp_credential(
        &self,
        req: CredentialStampExecutionRequest,
    ) -> Result<CredentialStampExecutionResult, String> {
        let expected_digests = req.expected_digests;
        Ok(CredentialStampExecutionResult {
            stamp_id: req.stamp_id,
            output: CredentialStampOutput::Artifact(CredentialArtifactOutput {
                name: "stamped.bin".into(),
                encoding: "raw".into(),
                content: CredentialArtifactContent::Data(
                    CredentialBytes::new(b"stamped".to_vec()).unwrap(),
                ),
            }),
            target_resolution: CredentialStampTargetResolution::Unchanged,
            resolved_target: req.request.target,
            bytes_written: req.request.encoded_bytes.to_string(),
            material_digests: expected_digests,
        })
    }

    fn run_mesh_task(
        &self,
        ctx: &mut Context,
        req: MeshTaskRequest,
    ) -> Result<MeshTaskResult, String> {
        ctx.info(
            "mesh task",
            &[
                ("kind", Value::from(req.kind.as_str())),
                ("node", Value::from(req.node_id.as_str())),
            ],
        );
        if req.kind != MESH_TASK_SURVEY {
            return Ok(MeshTaskResult {
                task_id: req.task_id,
                status: "failed".into(),
                summary: "unsupported mesh task".into(),
                node_id: req.node_id,
                ..MeshTaskResult::default()
            });
        }
        Ok(MeshTaskResult {
            task_id: req.task_id,
            status: "succeeded".into(),
            summary: format!("surveyed {}", req.node_id),
            node_id: req.node_id,
            outputs: vec![
                ("os".into(), Value::from("linux")),
                ("reachable".into(), Value::Bool(true)),
                ("contextRunId".into(), Value::from(ctx.run_id.as_str())),
                (
                    "contextModuleId".into(),
                    Value::from(ctx.module_id.as_str()),
                ),
                ("contextTarget".into(), Value::from(ctx.target.as_str())),
            ],
            ..MeshTaskResult::default()
        })
    }

    fn open_mesh_stream(
        &self,
        ctx: &mut Context,
        req: MeshStreamRequest,
    ) -> Result<crate::SessionRef, String> {
        let destination = req.destination_host.clone();
        let shell = LineShellSession::new("mesh$ ", true, move |command| {
            format!("routed {command} to {destination}")
        });
        ctx.open_session(
            Box::new(shell),
            SessionOptions {
                name: format!("mesh stream to {}", req.destination_host),
                kind: "stream".into(),
                transport: "mesh-route".into(),
                capabilities: vec![
                    "read".into(),
                    "write".into(),
                    "close".into(),
                    "stream.tcp".into(),
                ],
            },
        )
        .map_err(|err| err.to_string())
    }
}

fn fake_mesh_topology(include_routes: bool) -> MeshTopology {
    let mut topology = MeshTopology {
        root: "root".into(),
        nodes: vec![
            MeshNode {
                id: "root".into(),
                name: "controller".into(),
                kind: "controller".into(),
                state: "online".into(),
                ..MeshNode::default()
            },
            MeshNode {
                id: "node-1".into(),
                parent_id: "root".into(),
                name: "relay".into(),
                kind: "relay".into(),
                state: "online".into(),
                ..MeshNode::default()
            },
            MeshNode {
                id: "node-2".into(),
                parent_id: "node-1".into(),
                name: "leaf".into(),
                kind: "agent".into(),
                state: "online".into(),
                ..MeshNode::default()
            },
        ],
        links: vec![
            MeshLink {
                id: "link-root-node-1".into(),
                source: "root".into(),
                target: "node-1".into(),
                kind: "relay".into(),
                state: "up".into(),
                ..MeshLink::default()
            },
            MeshLink {
                id: "link-node-1-node-2".into(),
                source: "node-1".into(),
                target: "node-2".into(),
                kind: "relay".into(),
                state: "up".into(),
                ..MeshLink::default()
            },
        ],
        ..MeshTopology::default()
    };
    if include_routes {
        topology.routes.push(MeshRoute {
            id: "route-node-2".into(),
            nodes: vec!["root".into(), "node-1".into(), "node-2".into()],
            links: vec!["link-root-node-1".into(), "link-node-1-node-2".into()],
            ..MeshRoute::default()
        });
    }
    topology
}

fn frame(value: Value) -> Vec<u8> {
    let body = value.to_string();
    let mut out = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn request(id: i64, method: &str, params: Value) -> Value {
    Value::object(vec![
        ("jsonrpc", Value::from("2.0")),
        ("id", Value::from(id)),
        ("method", Value::from(method)),
        ("params", params),
    ])
}

#[test]
fn framing_rejects_oversized_frame_before_body_read() {
    let mut cursor = Cursor::new(b"Content-Length: 67108865\r\n\r\n".to_vec());
    let err = crate::framing::read_message(&mut cursor).expect_err("frame should be rejected");
    assert!(err.to_string().contains("exceeds maximum"), "{err}");
}

fn run_session<M: Module>(input: Vec<u8>, module: M) -> Vec<Value> {
    let captured = SharedBuf(Rc::new(RefCell::new(Vec::new())));
    let mut reader = Cursor::new(input);
    serve_with(&module, &mut reader, Box::new(captured.clone())).expect("serve");
    let bytes = captured.0.borrow().clone();
    let mut cursor = Cursor::new(bytes);
    let mut messages = Vec::new();
    while let Some(message) = crate::framing::read_message(&mut cursor).expect("read frame") {
        messages.push(message);
    }
    messages
}

fn responses(messages: &[Value]) -> Vec<&Value> {
    messages.iter().filter(|m| m.get("id").is_some()).collect()
}

#[test]
fn serve_handshake_schema_execute() {
    let mut input = Vec::new();
    input.extend(frame(request(1, "handshake", Value::Object(vec![]))));
    input.extend(frame(request(2, "schema", Value::Object(vec![]))));
    input.extend(frame(request(
        3,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-1")),
            ("target", Value::from("mock://host")),
            (
                "targetConfig",
                Value::object(vec![("target.host", Value::from("example.test"))]),
            ),
        ]),
    )));
    input.extend(frame(request(4, "shutdown", Value::Object(vec![]))));

    let messages = run_session(
        input,
        FakeModule {
            with_session: false,
        },
    );
    let responses = responses(&messages);
    assert_eq!(responses.len(), 4);

    let handshake = responses[0].get("result").unwrap();
    assert_eq!(
        handshake.get("name").and_then(Value::as_str),
        Some("fake-rust")
    );
    assert_eq!(
        handshake.get("moduleType").and_then(Value::as_str),
        Some("survey")
    );

    let execute = responses[2].get("result").unwrap();
    assert_eq!(
        execute.get("status").and_then(Value::as_str),
        Some("succeeded")
    );
    assert_eq!(
        execute.get("summary").and_then(Value::as_str),
        Some("surveyed example.test")
    );
}

#[test]
fn serve_handshake_requires_identity() {
    let input = frame(request(1, "handshake", Value::Object(vec![])));
    let messages = run_session(input, MissingVersionModule);
    let responses = responses(&messages);
    assert_eq!(responses.len(), 1);

    let error = responses[0].get("error").unwrap();
    assert_eq!(
        error.get("message").and_then(Value::as_str),
        Some("module handshake version is required")
    );
}

#[test]
fn serve_execute_exposes_optional_agent_context() {
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-1")),
            ("target", Value::from("mock://host")),
        ]),
    )));
    input.extend(frame(request(
        2,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-2")),
            ("target", Value::from("mock://host")),
            (
                "agentContext",
                Value::object(vec![
                    ("schema", Value::from("hovel.agent_context.v1")),
                    (
                        "entity",
                        Value::object(vec![
                            ("id", Value::from("entity-mcp")),
                            ("kind", Value::from("mcp")),
                            ("displayName", Value::from("Codex")),
                            ("agent", Value::Bool(true)),
                        ]),
                    ),
                    ("phase", Value::from("execute")),
                ]),
            ),
        ]),
    )));
    input.extend(frame(request(3, "shutdown", Value::Object(vec![]))));

    let messages = run_session(input, AgentAwareModule);
    let responses = responses(&messages);
    let without_agent = responses[0].get("result").unwrap();
    assert_eq!(
        without_agent
            .get("outputs")
            .and_then(|outputs| outputs.get("agentPresent"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(without_agent.get("agentHints").is_none());

    let with_agent = responses[1].get("result").unwrap();
    assert_eq!(
        with_agent
            .get("outputs")
            .and_then(|outputs| outputs.get("entityKind"))
            .and_then(Value::as_str),
        Some("mcp")
    );
    let hints = match with_agent.get("agentHints") {
        Some(Value::Array(items)) => items,
        other => panic!("missing agent hints: {other:?}"),
    };
    assert_eq!(
        hints[0].get("schema").and_then(Value::as_str),
        Some("hovel.agent_hint.v1")
    );
}

#[test]
fn serve_mesh_provider_methods() {
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "mesh.describe",
        Value::Object(Vec::new()),
    )));
    input.extend(frame(request(
        2,
        "mesh.topology",
        Value::object(vec![("includeRoutes", Value::Bool(true))]),
    )));
    input.extend(frame(request(
        3,
        "mesh.beacons",
        Value::object(vec![("nodeId", Value::from("node-2"))]),
    )));
    input.extend(frame(request(
        4,
        "mesh.task",
        Value::object(vec![
            ("runId", Value::from("run-mesh-1")),
            ("taskId", Value::from("task-survey-1")),
            ("kind", Value::from(MESH_TASK_SURVEY)),
            ("nodeId", Value::from("node-2")),
        ]),
    )));
    input.extend(frame(request(
        5,
        "mesh.task",
        Value::object(vec![
            ("runId", Value::from(" ")),
            ("moduleId", Value::from(" ")),
            ("target", Value::from(" ")),
            ("destinationHost", Value::from("10.10.0.99")),
            ("kind", Value::from(MESH_TASK_SURVEY)),
        ]),
    )));
    input.extend(frame(request(6, "shutdown", Value::Object(Vec::new()))));

    let messages = run_session(input, FakeMeshModule);
    let responses = responses(&messages);
    assert_eq!(responses.len(), 6);

    let describe = responses[0].get("result").unwrap();
    assert_eq!(
        describe.get("name").and_then(Value::as_str),
        Some("fake-mesh-rust")
    );
    match describe.get("tasks") {
        Some(Value::Array(items)) => {
            assert_eq!(items.len(), 3);
            let scopes = items[2]
                .get("targetScopes")
                .expect("upload_execute target scopes");
            match scopes {
                Value::Array(values) => assert_eq!(values.len(), 2),
                other => panic!("unexpected target scopes: {other:?}"),
            }
        }
        other => panic!("missing mesh tasks: {other:?}"),
    }
    match describe.get("triggers") {
        Some(Value::Array(items)) => assert_eq!(items.len(), 1),
        other => panic!("missing mesh triggers: {other:?}"),
    }
    let credential_delivery = describe
        .get("credentialDelivery")
        .expect("mesh credential delivery descriptor");
    match credential_delivery.get("deliveryCapabilities") {
        Some(Value::Array(items)) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[1].as_str(), Some("stamp-standard"));
        }
        other => panic!("missing credential delivery capabilities: {other:?}"),
    }

    let topology = responses[1].get("result").unwrap();
    match topology.get("nodes") {
        Some(Value::Array(items)) => assert_eq!(items.len(), 3),
        other => panic!("missing mesh nodes: {other:?}"),
    }
    match topology.get("links") {
        Some(Value::Array(items)) => assert_eq!(items.len(), 2),
        other => panic!("missing mesh links: {other:?}"),
    }
    match topology.get("routes") {
        Some(Value::Array(items)) => assert_eq!(items.len(), 1),
        other => panic!("missing mesh routes: {other:?}"),
    }

    let beacons = responses[2].get("result").unwrap();
    let beacon = match beacons.get("beacons") {
        Some(Value::Array(items)) => &items[0],
        other => panic!("missing mesh beacons: {other:?}"),
    };
    assert_eq!(beacon.get("nodeId").and_then(Value::as_str), Some("node-2"));
    assert_eq!(beacon.get("state").and_then(Value::as_str), Some("alive"));

    let task = responses[3].get("result").unwrap();
    assert_eq!(
        task.get("status").and_then(Value::as_str),
        Some("succeeded")
    );
    assert_eq!(
        task.get("summary").and_then(Value::as_str),
        Some("surveyed node-2")
    );
    assert_eq!(
        task.get("outputs")
            .and_then(|outputs| outputs.get("os"))
            .and_then(Value::as_str),
        Some("linux")
    );

    let defaulted = responses[4].get("result").unwrap();
    let outputs = defaulted.get("outputs").expect("defaulted mesh outputs");
    assert_eq!(
        outputs.get("contextRunId").and_then(Value::as_str),
        Some("mesh")
    );
    assert_eq!(
        outputs.get("contextModuleId").and_then(Value::as_str),
        Some("fake-mesh-rust@v0.0.0-test")
    );
    assert_eq!(
        outputs.get("contextTarget").and_then(Value::as_str),
        Some("10.10.0.99")
    );
}

#[test]
fn serve_credential_provider_methods() {
    let credential = Value::object(vec![
        ("bundleVersion", Value::from("hovel.pki.bundle/v1")),
        ("purpose", Value::from("mtls-server")),
        ("consumerType", Value::from("mesh-listener")),
        ("profileId", Value::from("mtls-server")),
        ("compatibilityTargetId", Value::from("portable-x509")),
    ]);
    let material = Value::object(vec![
        ("projection", Value::from("bundle")),
        ("form", Value::from("private-bytes")),
        ("encoding", Value::from("hovel-bundle-json")),
        ("sha256", Value::from("0".repeat(64).as_str())),
        (
            "data",
            Value::from(base64::encode(b"private-bundle").as_str()),
        ),
    ]);
    let provider = Value::object(vec![
        ("moduleId", Value::from("fake-mesh-rust")),
        ("providerId", Value::from("fake-mesh-rust")),
        ("providerVersion", Value::from("v1.0.0")),
        ("descriptorSha256", Value::from("4".repeat(64).as_str())),
    ]);
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        CREDENTIAL_RPC_RUNTIME_METHOD,
        Value::object(vec![
            (
                "schemaVersion",
                Value::from(CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1),
            ),
            ("provider", provider.clone()),
            ("requestId", Value::from("delivery-runtime-1")),
            ("assignmentId", Value::from("assignment-1")),
            ("slotName", Value::from("control-plane-mtls")),
            ("credential", credential.clone()),
            ("material", material.clone()),
            (
                "scope",
                Value::object(vec![("listenerId", Value::from("listener-primary"))]),
            ),
        ]),
    )));
    input.extend(frame(request(
        2,
        CREDENTIAL_RPC_FILES_METHOD,
        Value::object(vec![
            (
                "schemaVersion",
                Value::from(CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1),
            ),
            ("provider", provider.clone()),
            ("requestId", Value::from("delivery-files-1")),
            ("assignmentId", Value::from("assignment-1")),
            ("slotName", Value::from("control-plane-mtls")),
            ("credential", credential.clone()),
            (
                "files",
                Value::Array(vec![Value::object(vec![
                    ("projection", Value::from("certificate-der")),
                    ("form", Value::from("public")),
                    ("mediaType", Value::from("application/pkix-cert")),
                    ("path", Value::from("/provider-input/certificate.der")),
                    ("sha256", Value::from("1".repeat(64).as_str())),
                    ("size", Value::from(512_i64)),
                ])]),
            ),
            ("scope", Value::Object(Vec::new())),
        ]),
    )));
    input.extend(frame(request(
        3,
        CREDENTIAL_RPC_ENCODE_METHOD,
        Value::object(vec![
            (
                "schemaVersion",
                Value::from(CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1),
            ),
            ("provider", provider.clone()),
            ("requestId", Value::from("encoding-1")),
            ("providerId", Value::from("fake-mesh-rust")),
            ("providerSchema", Value::from("v1")),
            ("outputForm", Value::from("private-bytes")),
            ("maximumEncodedBytes", Value::from(4096_i64)),
            ("source", material.clone()),
            ("scope", Value::Object(Vec::new())),
        ]),
    )));
    input.extend(frame(request(
        4,
        CREDENTIAL_RPC_STAMP_METHOD,
        Value::object(vec![
            (
                "schemaVersion",
                Value::from(CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1),
            ),
            ("provider", provider),
            ("stampId", Value::from("credential-stamp-1")),
            (
                "request",
                Value::object(vec![
                    ("assignmentId", Value::from("assignment-1")),
                    ("capability", Value::from("stamp-standard")),
                    ("slotName", Value::from("control-plane-mtls")),
                    (
                        "target",
                        Value::object(vec![
                            ("kind", Value::from("named-slot")),
                            (
                                "namedSlot",
                                Value::object(vec![("name", Value::from("control-plane-mtls"))]),
                            ),
                        ]),
                    ),
                    (
                        "material",
                        Value::object(vec![
                            ("projection", Value::from("bundle")),
                            (
                                "credential",
                                Value::object(vec![
                                    ("projection", Value::from("bundle")),
                                    ("form", Value::from("private-bytes")),
                                    ("bundleId", Value::from("bundle-1")),
                                ]),
                            ),
                        ]),
                    ),
                    ("encodedBytes", Value::from(14_i64)),
                    ("credential", credential),
                ]),
            ),
            (
                "input",
                Value::object(vec![
                    ("id", Value::from("artifact-1")),
                    ("sha256", Value::from("3".repeat(64).as_str())),
                    ("encoding", Value::from("raw")),
                    ("data", Value::from(base64::encode(b"input").as_str())),
                ]),
            ),
            ("resolvedMaterial", material),
            (
                "expectedDigests",
                Value::Array(vec![Value::object(vec![
                    ("projection", Value::from("bundle")),
                    ("reference", Value::from("bundle-1")),
                    ("sha256", Value::from("2".repeat(64).as_str())),
                ])]),
            ),
            (
                "scope",
                Value::object(vec![("runId", Value::from("run-1"))]),
            ),
        ]),
    )));
    input.extend(frame(request(
        5,
        "credential.describe",
        Value::Object(Vec::new()),
    )));
    input.extend(frame(request(6, "shutdown", Value::Object(Vec::new()))));

    let messages = run_session(input, FakeMeshModule);
    let responses = responses(&messages);
    let runtime = responses[0].get("result").expect("runtime result");
    assert_eq!(
        runtime.get("providerReference").and_then(Value::as_str),
        Some("runtime-loaded")
    );
    assert!(runtime.get("material").is_none());
    let files = responses[1].get("result").expect("files result");
    assert_eq!(
        files.get("providerReference").and_then(Value::as_str),
        Some("files-loaded")
    );
    let encoded = responses[2].get("result").expect("encoding result");
    assert_eq!(
        encoded.get("data").and_then(Value::as_str),
        Some(base64::encode(b"encoded").as_str())
    );
    let stamped = responses[3].get("result").expect("stamp result");
    assert_eq!(
        stamped.get("stampId").and_then(Value::as_str),
        Some("credential-stamp-1")
    );
    assert_eq!(
        stamped.get("bytesWritten").and_then(Value::as_str),
        Some("14")
    );
    let descriptor = responses[4].get("result").expect("credential descriptor");
    assert_eq!(
        descriptor.get("schemaVersion").and_then(Value::as_str),
        Some(CREDENTIAL_DELIVERY_SCHEMA_V1)
    );
}

#[test]
fn serve_mesh_listener_lifecycle() {
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "mesh.listeners",
        Value::object(vec![
            ("listenerId", Value::from("  listener-primary  ")),
            ("state", Value::from("  active  ")),
        ]),
    )));
    input.extend(frame(request(
        2,
        "mesh.listener.start",
        Value::object(vec![
            ("listenerId", Value::from("  listener-web  ")),
            ("name", Value::from("web-controlled listener")),
            ("kind", Value::from("https")),
            ("deployment", Value::from("  separate  ")),
            ("management", Value::from("  provider  ")),
            (
                "config",
                Value::object(vec![("token", Value::from("write-only-secret"))]),
            ),
        ]),
    )));
    input.extend(frame(request(
        3,
        "mesh.listener.stop",
        Value::object(vec![("listenerId", Value::from("listener-web"))]),
    )));
    input.extend(frame(request(
        4,
        "mesh.listener.start",
        Value::object(vec![
            ("listenerId", Value::from("listener-invalid")),
            ("config", Value::from("write-only-secret")),
        ]),
    )));
    input.extend(frame(request(5, "shutdown", Value::Object(Vec::new()))));

    let messages = run_session(input, FakeMeshModule);
    let responses = responses(&messages);
    assert_eq!(responses.len(), 5);

    let listed = responses[0].get("result").expect("listed listeners");
    let listener = match listed.get("listeners") {
        Some(Value::Array(items)) => &items[0],
        other => panic!("missing mesh listeners: {other:?}"),
    };
    assert_eq!(
        listener.get("id").and_then(Value::as_str),
        Some("listener-primary")
    );

    let started = responses[1].get("result").expect("started listener");
    assert_eq!(
        started.get("id").and_then(Value::as_str),
        Some("listener-web")
    );
    assert_eq!(started.get("state").and_then(Value::as_str), Some("active"));
    assert_eq!(
        started.get("deployment").and_then(Value::as_str),
        Some("separate")
    );
    assert_eq!(
        started.get("management").and_then(Value::as_str),
        Some("provider")
    );
    assert!(started.get("config").is_none());

    let stopped = responses[2].get("result").expect("stopped listener");
    assert_eq!(
        stopped.get("state").and_then(Value::as_str),
        Some("stopped")
    );

    let malformed = responses[3].get("error").expect("malformed listener error");
    assert!(
        malformed
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("config must be an object")),
        "unexpected listener error: {malformed:?}",
    );
}

#[test]
fn mesh_listener_rejects_blank_ids_before_provider_invocation() {
    struct CountingMeshModule {
        lifecycle_calls: Rc<Cell<usize>>,
    }

    impl Module for CountingMeshModule {
        fn info(&self) -> Info {
            FakeMeshModule.info()
        }

        fn schema(&self) -> Schema {
            FakeMeshModule.schema()
        }

        fn run(&self, ctx: &mut Context) -> Outcome {
            FakeMeshModule.run(ctx)
        }

        fn start_mesh_listener(
            &self,
            req: MeshListenerStartRequest,
        ) -> Result<MeshListener, String> {
            self.lifecycle_calls.set(self.lifecycle_calls.get() + 1);
            FakeMeshModule.start_mesh_listener(req)
        }

        fn stop_mesh_listener(&self, req: MeshListenerStopRequest) -> Result<MeshListener, String> {
            self.lifecycle_calls.set(self.lifecycle_calls.get() + 1);
            FakeMeshModule.stop_mesh_listener(req)
        }
    }

    let lifecycle_calls = Rc::new(Cell::new(0));
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "mesh.listener.start",
        Value::object(vec![("listenerId", Value::from("  "))]),
    )));
    input.extend(frame(request(
        2,
        "mesh.listener.stop",
        Value::Object(Vec::new()),
    )));
    input.extend(frame(request(3, "shutdown", Value::Object(Vec::new()))));

    let messages = run_session(
        input,
        CountingMeshModule {
            lifecycle_calls: Rc::clone(&lifecycle_calls),
        },
    );
    let responses = responses(&messages);
    assert_eq!(responses.len(), 3);
    for response in &responses[..2] {
        let error = response.get("error").expect("blank listener id error");
        assert!(
            error
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("listenerId is required")),
            "unexpected listener error: {error:?}",
        );
    }
    assert_eq!(lifecycle_calls.get(), 0);
}

#[test]
fn serve_mesh_open_stream_creates_session() {
    let session_id = "run-mesh-2-session-1";
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "mesh.open_stream",
        Value::object(vec![
            ("runId", Value::from("run-mesh-2")),
            ("moduleId", Value::from("fake-mesh-rust@v0.0.0-test")),
            ("target", Value::from("mock://mesh")),
            ("nodeId", Value::from("node-2")),
            ("destinationHost", Value::from("10.10.10.10")),
            ("destinationPort", Value::from(443_i64)),
            ("protocol", Value::from("tcp")),
        ]),
    )));
    input.extend(frame(request(
        2,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(
        3,
        "session/write",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            (
                "data",
                Value::from(base64::encode(b"GET / HTTP/1.0\n").as_str()),
            ),
        ]),
    )));
    input.extend(frame(request(
        4,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(
        5,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(6, "shutdown", Value::Object(Vec::new()))));

    let messages = run_session(input, FakeMeshModule);
    let responses = responses(&messages);
    let session = responses[0].get("result").unwrap();
    assert_eq!(session.get("id").and_then(Value::as_str), Some(session_id));
    assert_eq!(session.get("kind").and_then(Value::as_str), Some("stream"));
    assert_eq!(
        session.get("transport").and_then(Value::as_str),
        Some("mesh-route")
    );

    let mut output = Vec::new();
    for response in &responses[1..] {
        if let Some(result) = response.get("result") {
            if let Some(data) = result.get("data").and_then(Value::as_str) {
                output.extend(base64::decode(data).unwrap());
            }
        }
    }
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("mesh$"), "missing prompt in {text:?}");
    assert!(
        text.contains("routed GET / HTTP/1.0 to 10.10.10.10"),
        "missing routed stream output in {text:?}"
    );
}

#[test]
fn outcome_serializes_installed_payload_descriptors() {
    let payload = InstalledPayloadDescriptor::new(
        "squatter",
        "squatter/windows/x86/xp-sp3/tcp-bind/pe-exe",
        "10.0.0.42",
    )
    .with_payload_version("0.1.0")
    .with_transport("tcp-bind")
    .with_endpoint("10.0.0.42:9101")
    .with_instance_key("squatter:10.0.0.42:9101")
    .with_stamp_id("stamp-1")
    .with_artifact_id("artifact-1")
    .with_supports_reconnect(true)
    .with_cleanup(PayloadProviderRecord::new(
        "squatter.cleanup.tcp_bind",
        vec![(
            "remotePath".into(),
            Value::from(r"C:\Windows\Temp\n4x9q2.exe"),
        )],
    ))
    .with_reconnect(
        PayloadProviderRecord::new(
            "squatter.reconnect.tcp_bind",
            vec![
                ("host".into(), Value::from("10.0.0.42")),
                ("port".into(), Value::from(9101_i64)),
            ],
        )
        .with_schema_version("1"),
    )
    .with_metadata("launch_method", Value::from("rust-test"));

    let result = Outcome::ok(vec![("target".into(), Value::from("10.0.0.42"))])
        .with_installed_payload(payload)
        .to_value(Vec::new());

    let installed = match result.get("installedPayloads") {
        Some(Value::Array(items)) => &items[0],
        other => panic!("missing installed payloads: {other:?}"),
    };
    assert_eq!(
        installed.get("provider").and_then(Value::as_str),
        Some("squatter")
    );
    assert_eq!(
        installed.get("payloadId").and_then(Value::as_str),
        Some("squatter/windows/x86/xp-sp3/tcp-bind/pe-exe")
    );
    assert_eq!(
        installed.get("supportsReconnect").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        installed
            .get("reconnect")
            .and_then(|v| v.get("descriptor"))
            .and_then(|v| v.get("port"))
            .and_then(Value::as_f64),
        Some(9101.0)
    );
    assert_eq!(
        installed
            .get("cleanup")
            .and_then(|v| v.get("descriptor"))
            .and_then(|v| v.get("remotePath"))
            .and_then(Value::as_str),
        Some(r"C:\Windows\Temp\n4x9q2.exe")
    );
}

#[test]
fn serve_session_round_trip() {
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-1")),
            ("target", Value::from("mock://host")),
        ]),
    )));
    // The opening prompt plus the whoami exchange are driven by session RPCs.
    let session_id = "run-1-session-1";
    input.extend(frame(request(
        2,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(
        3,
        "session/write",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("data", Value::from(base64::encode(b"whoami\n").as_str())),
        ]),
    )));
    input.extend(frame(request(
        4,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(
        5,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(6, "shutdown", Value::Object(vec![]))));

    let messages = run_session(input, FakeModule { with_session: true });
    let responses = responses(&messages);

    let execute = responses[0].get("result").unwrap();
    let sessions = match execute.get("sessions") {
        Some(Value::Array(items)) => items,
        _ => panic!("missing sessions"),
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].get("id").and_then(Value::as_str),
        Some(session_id)
    );

    // Concatenate all decoded session/read payloads and confirm the shell spoke.
    let mut output = Vec::new();
    for response in &responses[1..] {
        if let Some(result) = response.get("result") {
            if let Some(data) = result.get("data").and_then(Value::as_str) {
                output.extend(base64::decode(data).unwrap());
            }
        }
    }
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("mock$"), "missing prompt in {text:?}");
    assert!(
        text.contains("mock-operator"),
        "missing whoami output in {text:?}"
    );
}
