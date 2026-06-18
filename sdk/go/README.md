# Go SDK

The Go SDK is the most complete module-author surface today. Use it for normal
modules, PTY-backed post-exploitation sessions, typed chain-step providers, and
payload-provider modules.

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
| Typed chain steps | Implement `hovel.StepProvider`. |
| Provider contract tests | `github.com/Vibe-Pwners/hovel/sdk/go/hoveltest`. |

The provider methods are real RPC endpoints: `list_payloads`,
`resolve_payload`, `prepare_listener`, `generate_payload`, `connect_session`,
`cleanup_payload`, and `read_payload_chunk`. The step methods are also real RPC
endpoints: `step.describe`, `step.prepare`, `step.execute`, and `step.cleanup`.

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
task test -- //sdk/go/hovel:hovel_test
task test -- //sdk/go/hoveltest:hoveltest_test
task test -- //examples/go/...
```

Build staged example binaries:

```sh
task modules:build
```

Full gate:

```sh
task ci
```

Copy from these examples first:

- [`../../examples/go/mock_survey`](../../examples/go/mock_survey)
- [`../../examples/go/mock_exploit`](../../examples/go/mock_exploit)
- [`../../examples/go/mock_exploit_session`](../../examples/go/mock_exploit_session)
