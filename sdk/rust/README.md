# Rust SDK

The Rust SDK is intentionally small and dependency-light. Use it when you want a
native module binary with the core Hovel module lifecycle, line sessions,
explicit installed-payload result records, and Mesh provider hooks.

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
| Node Mesh provider | Override `describe_mesh`, `mesh_topology`, `list_mesh_beacons`, `run_mesh_task`, and `open_mesh_stream` on `Module`. |

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
Use `MESH_TASK_UPLOAD_EXECUTE` for implant copy-then-run flows and
`MESH_TASK_LOAD` for provider-native implant/component loaders. Requests can
carry inline bytes in `input_data`/`input_encoding` or provider-defined artifact
references in `config`.

Rust does not currently dispatch `step.*` methods or payload-provider
RPC methods. If you need those extension points today, use the Go SDK. Rust
modules can still return installed-payload descriptors when they install or
observe durable target-side payloads.

## Test Loop

Focused checks:

```sh
task check
```

The Rust SDK and Rust examples are outside the core Bazel workspace after the
partial-checkout split. Restore slice-local test/package tasks before
documenting focused SDK labels or staged example binary builds again.

Copy from these examples first:

- [`../../modules/examples/rust/mock_survey`](../../modules/examples/rust/mock_survey)
- [`../../modules/examples/rust/mock_exploit`](../../modules/examples/rust/mock_exploit)
- [`../../modules/examples/rust/mock_exploit_session`](../../modules/examples/rust/mock_exploit_session)
