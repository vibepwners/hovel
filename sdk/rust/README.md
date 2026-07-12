# Rust SDK

The Rust SDK is intentionally small and dependency-light. Use it when you want a
native module binary with the core Hovel module lifecycle, line sessions,
explicit installed-payload result records, and Mesh provider hooks.

For a complete Mesh development path—capability design, tasking, streams,
listening posts, daemon calls, and routing an existing module through a local
bridge—see the [Mesh Provider Development Guide](../../docs/site/spec/mesh-development.html).

The crate name is `hovel` inside this repository.

## Module Shape

```rust
use hovel::json::Value;
use hovel::{Context, Info, Module, ModuleType, Outcome, Requirement, Schema};

struct MyModule;

impl Module for MyModule {
    fn info(&self) -> Info {
        Info {
            name: "my-module-rust".into(),
            version: "v0.1.0".into(),
            module_type: ModuleType::Exploit,
            summary: "Run a scoped module action.".into(),
            description: String::new(),
            tags: vec!["example".into(), "rust".into()],
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema {
            target_config: vec![Requirement::new("target.host", "host", "Target host or IP.")],
            ..Schema::default()
        }
    }

    fn run(&self, ctx: &mut Context) -> Outcome {
        ctx.info("module started", &[("target", Value::from(ctx.target.as_str()))]);
        Outcome::ok(vec![("target".into(), Value::from(ctx.target.as_str()))])
            .with_summary("module completed")
    }
}

fn main() {
    hovel::serve(MyModule);
}
```

Rules that matter in real integrations:

- Never print to stdout. The SDK owns stdout for framed JSON-RPC messages.
- Use `ctx.info` and `ctx.error` for module logs.
- Return `Info` with `name`, `version`, and `module_type`. Hovel uses this
  handshake metadata instead of package-manifest hints.
- Keep `info` and `schema` cheap and side-effect free.
- Return `Outcome::ok` or `Outcome::failed`; attach `Finding`, `Artifact`,
  `SessionRef`, and `InstalledPayloadDescriptor` values explicitly.

## Current Surface

| Need | Use |
| --- | --- |
| Regular module execution | Implement `Module`. |
| Config requirements | `Requirement::new` in `Schema`. |
| Line-oriented post-exploitation sessions | `LineShellSession` opened with `ctx.open_session(...)`. |
| Durable installed payload inventory | `InstalledPayloadDescriptor`, `PayloadProviderRecord`, and `Outcome::with_installed_payload`. |
| Node Mesh provider | Override the `Module` Mesh methods you support, including optional listener list/start/stop lifecycle hooks. |
| Credential delivery | Override `describe_credential_delivery` plus only the runtime/files/encode/stamp methods you advertise. |

Rust dispatches Mesh RPC methods for topology, beacons, tasks, and routed
protocol flows. Mesh task specs can advertise `target_scopes` (`node`, `route`,
or `destination`), and task/stream requests carry `destination_host`, optional
`destination_port`, and provider-defined `protocol` for systems reachable
through a Mesh node. That supports pivoted upload/execute, daemon-owned TCP/UDP
local bridge workflows, or provider-native ICMP/raw/custom protocol flows
without making the Mesh provider implement the exploit module itself.
For UDP bridges, include `SESSION_CAPABILITY_DATAGRAM` in the returned
session's capabilities and preserve one datagram per non-empty `Session::write`
call and `Session::read` result. One bridge keeps one local UDP peer.
Override only the `Module` Mesh methods your provider supports. A minimal
stream Mesh can implement `describe_mesh` and `open_mesh_stream`; a deeper
implant/stager Mesh can also implement topology, beacons, and tasking.
Listener starts use a caller-selected stable ID for idempotent retries. Their
provider-specific config is write-only and must not be copied into returned
`MeshListener` values, logs, or audit records. Long-lived listeners must remain
durable across individual RPC calls because the SDK adapter is not a listener
host.
Use `MESH_TASK_UPLOAD_EXECUTE` for implant copy-then-run flows and
`MESH_TASK_LOAD` for provider-native implant/component loaders. Requests can
carry inline bytes in `input_data`/`input_encoding` or provider-defined artifact
references in `config`.

Consumer modules can authenticate an `OpenMeshBridge` response and then use a
normal `TcpStream`:

```rust,no_run
use hovel::{MeshBridgeCapability, MeshBridgeEndpoint, connect_mesh_bridge_tcp};
use std::time::Duration;

let capability = MeshBridgeCapability::new(bridge.capability)?;
let endpoint = MeshBridgeEndpoint::new(
    bridge.local_host,
    bridge.local_port,
    capability,
)?;
let stream = connect_mesh_bridge_tcp(&endpoint, Some(Duration::from_secs(5)))?;
```

Use `connect_mesh_bridge_udp` for a UDP association. Both helpers send the
bearer capability first. Keep it in memory and out of logs, results, and
durable configuration.

Rust does not currently dispatch `step.*` methods or payload-provider
RPC methods. If you need those extension points today, use the Go SDK. Rust
modules can still return installed-payload descriptors when they install or
observe durable target-side payloads.

## Credential Delivery Providers

`Module::describe_credential_delivery` exposes `credential.describe`
independently of Mesh. A provider may also return the same descriptor in
`MeshDescriptor::credential_delivery`; if both forms are present, they must be
identical.

| RPC method | `Module` method | Advertised contract |
| --- | --- | --- |
| `credential.describe` | `describe_credential_delivery` | `CredentialDeliveryDescriptor`; the SDK emits `CREDENTIAL_DELIVERY_SCHEMA_V1`. |
| `credential.runtime` | `load_runtime_credential` | `CredentialDeliveryCapability::Runtime`; return a matching `CredentialDeliveryReceipt`. |
| `credential.files` | `load_credential_files` | `CredentialDeliveryCapability::Files`; paths are protected and invocation-scoped. |
| `credential.encode` | `encode_credential_material` | A matching `CredentialProviderEncodingSchema`; honor the output form, maximum size, and digest. |
| `credential.stamp` | `stamp_credential` | `StampStandard` or `StampAdvanced`, with matching target kinds and address spaces. |

A non-`None` descriptor needs at least one strict `CredentialSlot`. Override
only advertised operations; every other default method returns an unsupported
error.

This complete provider advertises only in-memory runtime delivery:

```rust
use hovel::{
    Context, CredentialConsumerType, CredentialDeliveryCapability,
    CredentialDeliveryDescriptor, CredentialDeliveryReceipt, CredentialEndpointRole,
    CredentialMaterialForm, CredentialPrivateMaterialPolicy, CredentialProjection,
    CredentialPurpose, CredentialRuntimeRequest, CredentialSlot,
    CredentialStampRemainderPolicy, Info, Module, ModuleType, Outcome, Schema,
};

struct RuntimeCredentialProvider;

impl Module for RuntimeCredentialProvider {
    fn info(&self) -> Info {
        Info {
            name: "runtime-credential-rust".into(),
            version: "v0.1.0".into(),
            module_type: ModuleType::PayloadProvider,
            summary: "Accept runtime TLS credentials.".into(),
            description: String::new(),
            tags: vec!["credential-provider".into()],
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema::default()
    }

    fn run(&self, _ctx: &mut Context) -> Outcome {
        Outcome::ok(Vec::new()).with_summary("credential provider is RPC-driven")
    }

    fn describe_credential_delivery(&self) -> Result<CredentialDeliveryDescriptor, String> {
        Ok(CredentialDeliveryDescriptor {
            capabilities: vec![CredentialDeliveryCapability::Runtime],
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
                maximum_encoded_bytes: 64 << 10,
                remainder_policy: CredentialStampRemainderPolicy::Preserve,
                private_material: CredentialPrivateMaterialPolicy::Allowed,
            }],
            ..CredentialDeliveryDescriptor::default()
        })
    }

    fn load_runtime_credential(
        &self,
        request: CredentialRuntimeRequest,
    ) -> Result<CredentialDeliveryReceipt, String> {
        // Install request.material into provider-owned runtime state here.
        // Never log or retain it beyond the advertised lifecycle.
        Ok(CredentialDeliveryReceipt {
            request_id: request.request_id,
            provider_reference: None,
            receipt_sha256: None,
        })
    }
}

fn main() {
    hovel::serve(RuntimeCredentialProvider);
}
```

`CredentialBytes`, `CredentialSecretReference`, `CredentialProtectedPath`, and
secret-bearing unions redact `Debug`. Accessors such as `as_slice`, `expose`,
and `bytes` still reveal values to provider code. Rust cannot guarantee zeroing
without provider-owned zeroizing storage, so keep values scoped to the call,
avoid logs/errors/stdout, and keep secret values out of Hovel's public execution
ledger. A provider may copy material into its own protected runtime or
installation when its advertised lifecycle requires it, but should return only
non-secret receipts or digests. Hovel's public execution bookkeeping excludes
credential bytes, protected paths, provider references, and deployment
receipts.

The dependency-light Rust SDK has one `Module` trait rather than separate
`CredentialDescriber` and capability traits, so descriptor/method agreement is
validated at discovery and dispatch time, not by trait composition. Wire sizes
use `i64` in this SDK; offsets and addresses that require the full unsigned
64-bit range remain canonical decimal strings.

## Test Loop

Drive `serve_with` with an actual Content-Length frame in contract tests:

```rust
use std::cell::RefCell;
use std::io::{self, Cursor, Write};
use std::rc::Rc;

#[derive(Clone, Default)]
struct Capture(Rc<RefCell<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn credential_provider_framed_contract() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"credential.describe","params":{}}"#;
    let wire = format!("Content-Length: {}\r\n\r\n{body}", body.len());
    let mut input = Cursor::new(wire.into_bytes());
    let output = Capture::default();

    hovel::serve_with(
        &RuntimeCredentialProvider,
        &mut input,
        Box::new(output.clone()),
    )
    .expect("serve framed request");

    let response = String::from_utf8(output.0.borrow().clone()).expect("UTF-8 response");
    assert!(response.contains(hovel::CREDENTIAL_DELIVERY_SCHEMA_V1));
    assert!(response.contains("runtime"));
}
```

Focused checks:

```sh
task sdk:ci
```

Use <code>task sdk:test</code> while iterating on behavior and
<code>task sdk:build</code> for a compile-only check. The root Task wrappers
select the integration workspace and remain the supported entry point.

Copy from these examples first:

- [`../../modules/examples/rust/mock_survey`](../../modules/examples/rust/mock_survey)
- [`../../modules/examples/rust/mock_exploit`](../../modules/examples/rust/mock_exploit)
- [`../../modules/examples/rust/mock_exploit_session`](../../modules/examples/rust/mock_exploit_session)
