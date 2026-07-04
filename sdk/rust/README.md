# Rust SDK

The Rust SDK is intentionally small and dependency-light. Use it when you want a
native module binary with the core Hovel module lifecycle, line sessions, and
explicit installed-payload result records.

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

Rust does not currently dispatch `step.*` methods or payload-provider RPC
methods. If you need those extension points today, use the Go SDK. Rust modules
can still return installed-payload descriptors when they install or observe
durable target-side payloads.

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
