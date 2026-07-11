# Go SDK

The Go SDK is the most complete module-author surface today. Use it for normal
modules, PTY-backed post-exploitation sessions, typed chain-step providers,
payload-provider modules, and Mesh providers.

Import path:

```go
import "github.com/Vibe-Pwners/hovel/sdk/go/hovel"
```

## Module Shape

```go
package main

import "github.com/Vibe-Pwners/hovel/sdk/go/hovel"

type MyModule struct{}

func (MyModule) Info() hovel.Info {
	return hovel.Info{
		Name:    "my-module-go",
		Version: "v0.1.0",
		Type:    hovel.TypeExploit,
		Summary: "Run a scoped module action.",
	}
}

func (MyModule) Schema() hovel.Schema {
	return hovel.Schema{
		TargetConfig: []hovel.Requirement{
			hovel.Req("target.host", "host", "Target host or IP."),
		},
	}
}

func (MyModule) Run(ctx *hovel.Context) (hovel.Result, error) {
	ctx.Log.Info("module started", "target", ctx.Target)
	return hovel.Ok(map[string]any{"target": ctx.Target}, hovel.WithSummary("module completed")), nil
}

func main() {
	hovel.Serve(MyModule{})
}
```

Rules that matter in real integrations:

- Never write to stdout yourself. The SDK owns stdout for JSON-RPC frames.
- Put progress on `ctx.Log`; it becomes structured `module/log` notifications.
- Return `Info` with `Name`, `Version`, and `Type`. Hovel uses this handshake
  metadata instead of package-manifest hints.
- Keep `Info` and `Schema` cheap and side-effect free.
- Return `hovel.Result` with explicit outputs, artifacts, findings, sessions,
  and installed payload descriptors.

## Extension Points

| Need | Use |
| --- | --- |
| Regular module execution | Implement `hovel.Module`. |
| Config requirements | `hovel.Requirement` or `hovel.Req`. |
| Line-oriented session | `hovel.LineShellSession` opened with `ctx.OpenSession(...)`. |
| PTY-backed session | `hovel.PTYSession` opened with `ctx.OpenSession(...)`. |
| Durable installed payload inventory | `hovel.InstalledPayloadDescriptor` and `hovel.WithInstalledPayloads`. |
| Payload provider | Implement `hovel.PayloadProvider`. |
| Node Mesh provider | Implement `hovel.MeshDescriber` plus the optional Mesh operation interfaces you support. Use `hovel.MeshProvider` only for a full-surface provider. |
| Typed chain steps | Implement `hovel.StepProvider`. |
| Provider contract tests | `github.com/Vibe-Pwners/hovel/sdk/go/hoveltest`. |

The provider methods are real RPC endpoints: `list_payloads`,
`resolve_payload`, `prepare_listener`, `generate_payload`, `connect_session`,
`cleanup_payload`, and `read_payload_chunk`. The step methods are also real RPC
endpoints: `step.describe`, `step.prepare`, `step.execute`, and `step.cleanup`.
Mesh providers expose `mesh.describe`, `mesh.topology`, `mesh.beacons`,
`mesh.task`, and `mesh.open_stream` for one-node tools through routed
tree/graph node operations and protocol-specific flows.
The Go SDK intentionally splits those methods into optional interfaces
(`MeshDescriber`, `MeshTopologyProvider`, `MeshBeaconProvider`,
`MeshTaskProvider`, and `MeshStreamProvider`) so a simple stream Mesh does not
need to stub tasking, beacons, or topology.
Use `MeshTaskSpec.TargetScopes` to say whether a task targets a Mesh node,
route, or destination reachable through a node. `MeshTaskRequest` and
`MeshStreamRequest` both carry `DestinationHost`, optional `DestinationPort`,
and provider-defined `Protocol`, which is the contract Hovel needs to run tools
or exploit delivery through a daemon-owned TCP/UDP Mesh bridge or a
provider-native protocol flow without hard-coding the provider internals.
For UDP bridges, include `hovel.CapabilityDatagram` in the returned session's
capabilities and preserve one datagram per non-empty `Session.Write` call and
`Session.Read` result. One bridge keeps one local UDP peer association.
Use `MeshTaskUploadExecute` for implant copy-then-run flows and `MeshTaskLoad`
for provider-native implant/component loaders. The request can carry inline
payload bytes in `InputData`/`InputEncoding` or provider-defined artifact
references in `Config`; the SDK does not implement the loader.

## Test Loop

Use the SDK test helpers when protocol shape matters.

```go
func TestProviderContract(t *testing.T) {
	hoveltest.AssertPayloadProviderContract(t, MyProvider{}, hoveltest.PayloadProviderContract{
		Target:        "lab-1",
		WantFormat:    "pe-exe",
		WantTransport: "tcp",
	})
}
```

Focused checks:

```sh
task sdk:fmt
task check
```

The Go SDK and Go examples are outside the core Bazel workspace after the
partial-checkout split. Restore slice-local test/package tasks before
documenting focused SDK labels or staged example binary builds again.

Copy from these examples first:

- [`../../modules/examples/go/mock_survey`](../../modules/examples/go/mock_survey)
- [`../../modules/examples/go/mock_exploit`](../../modules/examples/go/mock_exploit)
- [`../../modules/examples/go/mock_exploit_session`](../../modules/examples/go/mock_exploit_session)
