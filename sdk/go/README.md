# Go SDK

The Go SDK is the most complete module-author surface today. Use it for normal
modules, PTY-backed post-exploitation sessions, typed chain-step providers,
payload-provider modules, and Mesh providers.

For a complete Mesh development path—capability design, tasking, streams,
listening posts, daemon calls, and routing an existing module through a local
bridge—see the [Mesh Provider Development Guide](../../docs/site/src/content/spec/mesh-development.html).

Import path:

```go
import "github.com/vibepwners/hovel/sdk/go/hovel"
```

## Module Shape

```go
package main

import "github.com/vibepwners/hovel/sdk/go/hovel"

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
| Credential delivery provider | Implement `hovel.CredentialDescriber` plus only the optional runtime/files/encode/stamp interfaces you advertise. |
| Typed chain steps | Implement `hovel.StepProvider`. |
| Provider contract tests | `github.com/vibepwners/hovel/sdk/go/hoveltest`. |

The provider methods are real RPC endpoints: `list_payloads`,
`resolve_payload`, `prepare_listener`, `generate_payload`, `connect_session`,
`cleanup_payload`, and `read_payload_chunk`. The step methods are also real RPC
endpoints: `step.describe`, `step.prepare`, `step.execute`, and `step.cleanup`.
Mesh providers expose `mesh.describe`, `mesh.topology`, `mesh.beacons`,
`mesh.listeners`, `mesh.listener.start`, `mesh.listener.stop`, `mesh.task`, and
`mesh.open_stream` for one-node tools through routed tree/graph node operations,
listening-post lifecycle, and protocol-specific flows.
The Go SDK intentionally splits those methods into optional interfaces
(`MeshDescriber`, `MeshTopologyProvider`, `MeshBeaconProvider`,
`MeshListenerProvider`, `MeshListenerLifecycleProvider`, `MeshTaskProvider`, and
`MeshStreamProvider`) so a simple stream Mesh does not need to stub listener
lifecycle, tasking, beacons, or topology.
Listener starts use a caller-selected stable ID for idempotent retries. Their
provider-specific config is write-only and must not be copied into returned
`MeshListener` values, logs, or audit records. A long-lived listener must remain
durable across individual RPC calls; the SDK contract does not make the module
subprocess a listener host.
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

Consumer modules can turn an `OpenMeshBridge` response into a normal
authenticated connection without implementing the security preface:

```go
endpoint, err := hovel.NewMeshBridgeEndpoint(
    bridge.LocalHost,
    bridge.LocalPort,
    hovel.MeshBridgeNetwork(bridge.LocalNetwork),
    bridge.Capability,
)
if err != nil {
    return err
}
connection, err := hovel.DialMeshBridge(ctx, endpoint)
if err != nil {
    return err
}
defer connection.Close()
```

The endpoint retains the response's `localNetwork`, so callers cannot
accidentally dial a UDP bridge as TCP or vice versa. The helper sends the bearer
capability first and returns a connection ready for protocol bytes. Keep the
capability in memory; never put it in logs, results, or durable configuration.

## Credential Delivery Providers

`CredentialDescriber` exposes `credential.describe` independently of Mesh. A
module may be a standalone credential provider, a Mesh provider, or both. If it
publishes the descriptor both ways, the standalone and
`MeshDescriptor.CredentialDelivery` values must be identical.

| RPC method | Go interface | Advertised contract |
| --- | --- | --- |
| `credential.describe` | `CredentialDescriber` | `CredentialDeliveryDescriptor` with schema `CredentialDeliverySchemaV1`. |
| `credential.runtime` | `CredentialRuntimeProvider` | `CredentialDeliveryRuntime`; returns a correlated `CredentialDeliveryReceipt`. |
| `credential.files` | `CredentialFilesProvider` | `CredentialDeliveryFiles`; paths are protected and invocation-scoped. |
| `credential.encode` | `CredentialEncodingProvider` | A matching `ProviderEncodingSchemas` entry; output must honor its form, size bound, and digest. |
| `credential.stamp` | `CredentialStampProvider` | `CredentialDeliveryStampStandard` or `CredentialDeliveryStampAdvanced`, with matching target kinds and address spaces. |

Non-`none` descriptors need at least one strict `CredentialSlot`. Advertise
only hooks the provider actually implements: Go dispatches each execution RPC
through its separate optional interface and reports an unsupported method
otherwise.

This complete provider advertises only in-memory runtime delivery:

```go
package main

import (
	"fmt"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

type RuntimeCredentialProvider struct{}

func (RuntimeCredentialProvider) Info() hovel.Info {
	return hovel.Info{
		Name: "runtime-credential-go", Version: "v0.1.0",
		Type: hovel.TypePayloadProvider, Summary: "Accept runtime TLS credentials.",
	}
}

func (RuntimeCredentialProvider) Schema() hovel.Schema { return hovel.Schema{} }

func (RuntimeCredentialProvider) Run(*hovel.Context) (hovel.Result, error) {
	return hovel.Ok(nil, hovel.WithSummary("credential provider is RPC-driven")), nil
}

func (RuntimeCredentialProvider) DescribeCredentialDelivery() (hovel.CredentialDeliveryDescriptor, error) {
	return hovel.CredentialDeliveryDescriptor{
		SchemaVersion: hovel.CredentialDeliverySchemaV1,
		Capabilities:  []hovel.CredentialDeliveryCapability{hovel.CredentialDeliveryRuntime},
		Slots: []hovel.CredentialSlot{{
			Name: "control-plane-mtls-certificate", Purpose: hovel.CredentialPurposeMTLSServer,
			EndpointRole: hovel.CredentialEndpointServer,
			ConsumerType: hovel.CredentialConsumerMeshListener,
			AcceptedBundleVersions: []string{"hovel.pki.bundle/v1"},
			AcceptedProfiles: []string{"mtls-server"},
			AcceptedCompatibilityTargets: []string{"portable-x509"},
			AcceptedProjections: []hovel.CredentialProjection{hovel.CredentialProjectionCertificateDER},
			AcceptedMaterialForms: []hovel.CredentialMaterialForm{hovel.CredentialMaterialPublic},
			MaximumEncodedBytes: 64 << 10,
			RemainderPolicy: hovel.CredentialStampRemainderPreserve,
			PrivateMaterial: hovel.CredentialPrivateMaterialForbidden,
		}, {
			Name: "control-plane-mtls-private-key", Purpose: hovel.CredentialPurposeMTLSServer,
			EndpointRole: hovel.CredentialEndpointServer,
			ConsumerType: hovel.CredentialConsumerMeshListener,
			AcceptedBundleVersions: []string{"hovel.pki.bundle/v1"},
			AcceptedProfiles: []string{"mtls-server"},
			AcceptedCompatibilityTargets: []string{"portable-x509"},
			AcceptedProjections: []hovel.CredentialProjection{hovel.CredentialProjectionPrivateKeyPKCS8},
			AcceptedMaterialForms: []hovel.CredentialMaterialForm{hovel.CredentialMaterialPrivateBytes},
			MaximumEncodedBytes: 64 << 10,
			RemainderPolicy: hovel.CredentialStampRemainderPreserve,
			PrivateMaterial: hovel.CredentialPrivateMaterialRequired,
		}},
	}, nil
}

func (RuntimeCredentialProvider) LoadRuntimeCredential(
	req hovel.CredentialRuntimeRequest,
) (hovel.CredentialDeliveryReceipt, error) {
	material, ok := req.Material.Bytes()
	if !ok {
		return hovel.CredentialDeliveryReceipt{}, fmt.Errorf("slot %q requires bytes", req.SlotName)
	}
	defer clear(material)
	// Install material into provider-owned runtime state here. Do not log it.
	return hovel.CredentialDeliveryReceipt{RequestID: req.RequestID}, nil
}

var _ hovel.CredentialDescriber = RuntimeCredentialProvider{}
var _ hovel.CredentialRuntimeProvider = RuntimeCredentialProvider{}

func main() { hovel.Serve(RuntimeCredentialProvider{}) }
```

`CredentialBytes`, `CredentialSecretReference`, `CredentialProtectedPath`, and
the sealed material/artifact unions redact ordinary formatting and defensively
copy byte slices. Redaction is not erasure: explicit accessors reveal the value
to provider code. Keep it scoped to the call, avoid logs/errors/stdout, clear
temporary copies when practical, and keep secret values out of Hovel's public
execution ledger. A provider may copy material into its own protected runtime
or installation when its advertised lifecycle requires it, but should return
only non-secret receipts or digests. Hovel's public execution bookkeeping
excludes credential bytes, protected paths, provider references, and deployment
receipts.

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

For a credential provider, exercise the real Content-Length framed dispatcher:

```go
func TestCredentialProviderFramedContract(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"credential.describe","params":{}}`)
	var input, output bytes.Buffer
	fmt.Fprintf(&input, "Content-Length: %d\r\n\r\n", len(body))
	input.Write(body)

	if err := hovel.ServeIO(RuntimeCredentialProvider{}, &input, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(hovel.CredentialDeliverySchemaV1)) {
		t.Fatalf("credential descriptor missing from framed response: %q", output.Bytes())
	}
}
```

The test imports `bytes`, `fmt`, `testing`, and
`github.com/vibepwners/hovel/sdk/go/hovel`.

Focused checks:

```sh
task sdk:fmt
task sdk:ci
```

Use <code>task sdk:test</code> while iterating on behavior and
<code>task sdk:build</code> for a compile-only check. The root Task wrappers
select the integration workspace and remain the supported entry point.

Copy from these examples first:

- [`../../modules/examples/go/mock_survey`](../../modules/examples/go/mock_survey)
- [`../../modules/examples/go/mock_exploit`](../../modules/examples/go/mock_exploit)
- [`../../modules/examples/go/mock_exploit_session`](../../modules/examples/go/mock_exploit_session)
