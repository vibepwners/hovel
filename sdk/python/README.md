# Python SDK

The Python SDK is the quickest path for exploit, survey, and post-exploitation
module work. Copy one of the examples in [`../../modules/examples/python`](../../modules/examples/python)
and keep the public boundary small: subclass `HovelModule`, describe cheap
metadata/configuration, then put target interaction in `run` or explicit step
hooks.

For a complete Mesh development path—capability design, tasking, streams,
listening posts, daemon calls, and routing an existing module through a local
bridge—see the [Mesh Provider Development Guide](../../docs/site/src/content/spec/mesh-development.html).

## Module Shape

```python
from hovel_sdk import Context, HovelModule, Requirement, Result, serve


class MyModule(HovelModule):
    name = "my-module"
    version = "v0.1.0"
    module_type = "exploit"
    summary = "Run a scoped module action."
    target_config = (
        Requirement("target.host", "host", description="Target host or IP."),
    )

    def run(self, ctx: Context) -> Result:
        ctx.log.info("module started", extra={"target": ctx.target})
        return Result.ok({"target": ctx.target}, summary="module completed")


if __name__ == "__main__":
    serve(MyModule())
```

Rules that matter in real integrations:

- Never print to stdout. The SDK uses stdout for framed JSON-RPC responses and
  notifications.
- Use `ctx.log` for progress and diagnostics; Hovel turns those into
  `module/log` notifications.
- Set `name`, `version`, and `module_type`. The SDK rejects a handshake without
  them, and Hovel uses that handshake metadata instead of package-manifest
  hints.
- Keep `info()` and `module_schema()` side-effect free. Hovel calls them while
  cataloging modules.
- Use `Result.ok` or `Result.failed`; attach `Finding`, `Artifact`,
  `SessionRef`, and `InstalledPayload` values deliberately.

## Extension Points

| Need | Use |
| --- | --- |
| Regular module execution | `run(ctx) -> Result` or an awaitable `Result`. |
| Config requirements | `Requirement` in `global_config` and `target_config`. |
| Line-oriented post-exploitation sessions | `LineShellSession` opened with `await ctx.open_session(...)`. |
| Durable installed payload inventory | `InstalledPayload` and `PayloadProviderRecord` in a result. |
| Typed chain steps | Override `describe_steps`, `prepare_step`, `execute_step`, and `cleanup_step`. |
| Provider-owned node operations | Override the Mesh methods you support, including optional listener list/start/stop lifecycle hooks. |
| Credential delivery | Override `describe_credential_delivery` plus only the runtime/files/encode/stamp hooks you advertise. |

Mesh is the SDK contract for one-node or routed node-operation providers. A
Mesh may expose topology, routes, beacons, triggers, survey/upload/execute/
command/load tasks, and provider-defined protocol flows. The daemon can bridge
TCP streams or UDP datagrams to a loopback socket; ICMP, raw IP, and custom
protocols remain provider task/session contracts unless Hovel grows an explicit
local adapter. UDP session flows must include
`SESSION_CAPABILITY_DATAGRAM` in their capabilities and preserve exactly one
datagram per non-empty `write` call and `read` result; one bridge keeps one
local UDP peer. The Python SDK only dispatches those contracts; provider code
owns the routing/task behavior, and Hovel guardrails still live above the SDK.
Override only the methods your provider supports. A minimal stream Mesh can
override `describe_mesh` and `open_mesh_stream`; a deeper implant/stager Mesh
can also override topology, beacons, triggers in the descriptor, listener
lifecycle, and tasking. `start_mesh_listener` uses a caller-selected stable ID;
its provider-specific config is write-only and must not be copied into returned
`MeshListener` values, logs, or audit records. Long-lived listeners must remain
durable across individual RPC calls because the SDK adapter is not a listener
host.
Use `MESH_TASK_UPLOAD_EXECUTE` for implant copy-then-run flows and
`MESH_TASK_LOAD` for provider-native implant/component loaders. Requests can
carry inline bytes in `input_data`/`input_encoding` or provider-defined artifact
references in `config`.

Consumer modules can authenticate an `OpenMeshBridge` response and then use a
normal socket:

```python
from hovel_sdk import MeshBridgeEndpoint, MeshBridgeNetwork, connect_mesh_bridge

endpoint = MeshBridgeEndpoint.from_rpc(bridge)
with connect_mesh_bridge(endpoint, timeout=5.0) as connection:
    if endpoint.local_network is MeshBridgeNetwork.UDP:
        connection.send(request_bytes)
    else:
        connection.sendall(request_bytes)
```

`MeshBridgeEndpoint.from_rpc()` validates and retains the daemon response's
`localNetwork`, preventing a TCP/UDP mismatch. The helper sends the bearer
capability first. Keep it in memory and out of logs, results, and durable
configuration. Bridge helpers accept canonical numeric loopback addresses only;
they never resolve hostnames such as `localhost`. Use
`endpoint.capability.reveal()` only at an explicit protocol boundary; ordinary
string, repr, dataclass, and container formatting stays redacted.

Python does not currently dispatch payload-provider RPC methods such as
`list_payloads` or `generate_payload`. Use Go for provider modules today, or
return installed-payload descriptors from a Python exploit when it installs or
observes a durable payload.

## Credential Delivery Providers

`describe_credential_delivery()` exposes `credential.describe` independently
of Mesh. A provider may also put the same descriptor in
`MeshDescriptor.credential_delivery`; if both forms are present, they must be
identical.

| RPC method | `HovelModule` hook | Advertised contract |
| --- | --- | --- |
| `credential.describe` | `describe_credential_delivery()` | `CredentialDeliveryDescriptor` using `CREDENTIAL_DELIVERY_SCHEMA_V1`. |
| `credential.runtime` | `load_runtime_credential(request)` | `CredentialDeliveryCapability.RUNTIME`; return a matching `CredentialDeliveryReceipt`. |
| `credential.files` | `load_credential_files(request)` | `CredentialDeliveryCapability.FILES`; file paths are protected and invocation-scoped. |
| `credential.encode` | `encode_credential_material(request)` | A matching `CredentialProviderEncodingSchema`; honor the output form, maximum size, and digest. |
| `credential.stamp` | `stamp_credential(request)` | `STAMP_STANDARD` or `STAMP_ADVANCED`, with matching target kinds and address spaces. |

A non-`NONE` descriptor needs at least one strict `CredentialSlot`. Override
only advertised operations; inherited hooks raise an unsupported-method error.
Hooks may be synchronous or async, like `run()` and the Mesh hooks.

This complete provider advertises only in-memory runtime delivery:

```python
from hovel_sdk import (
    Context,
    CredentialConsumerType,
    CredentialDeliveryCapability,
    CredentialDeliveryDescriptor,
    CredentialDeliveryReceipt,
    CredentialEndpointRole,
    CredentialMaterialForm,
    CredentialPrivateMaterialPolicy,
    CredentialProjection,
    CredentialPurpose,
    CredentialRuntimeRequest,
    CredentialSlot,
    CredentialStampRemainderPolicy,
    HovelModule,
    Result,
    serve,
)


class RuntimeCredentialProvider(HovelModule):
    name = "runtime-credential-python"
    version = "v0.1.0"
    module_type = "payload_provider"
    summary = "Accept runtime TLS credentials."

    def run(self, _ctx: Context) -> Result:
        return Result.ok(summary="credential provider is RPC-driven")

    def describe_credential_delivery(self) -> CredentialDeliveryDescriptor:
        return CredentialDeliveryDescriptor(
            capabilities=[CredentialDeliveryCapability.RUNTIME],
            slots=[
                CredentialSlot(
                    name="control-plane-mtls-certificate",
                    purpose=CredentialPurpose.MTLS_SERVER,
                    endpoint_role=CredentialEndpointRole.SERVER,
                    consumer_type=CredentialConsumerType.MESH_LISTENER,
                    accepted_bundle_versions=["hovel.pki.bundle/v1"],
                    accepted_profiles=["mtls-server"],
                    accepted_compatibility_targets=["portable-x509"],
                    accepted_projections=[CredentialProjection.CERTIFICATE_DER],
                    accepted_material_forms=[CredentialMaterialForm.PUBLIC],
                    maximum_encoded_bytes=64 << 10,
                    remainder_policy=CredentialStampRemainderPolicy.PRESERVE,
                    private_material=CredentialPrivateMaterialPolicy.FORBIDDEN,
                ),
                CredentialSlot(
                    name="control-plane-mtls-private-key",
                    purpose=CredentialPurpose.MTLS_SERVER,
                    endpoint_role=CredentialEndpointRole.SERVER,
                    consumer_type=CredentialConsumerType.MESH_LISTENER,
                    accepted_bundle_versions=["hovel.pki.bundle/v1"],
                    accepted_profiles=["mtls-server"],
                    accepted_compatibility_targets=["portable-x509"],
                    accepted_projections=[CredentialProjection.PRIVATE_KEY_PKCS8],
                    accepted_material_forms=[CredentialMaterialForm.PRIVATE_BYTES],
                    maximum_encoded_bytes=64 << 10,
                    remainder_policy=CredentialStampRemainderPolicy.PRESERVE,
                    private_material=CredentialPrivateMaterialPolicy.REQUIRED,
                ),
            ],
        )

    def load_runtime_credential(
        self, request: CredentialRuntimeRequest
    ) -> CredentialDeliveryReceipt:
        # Install request.material into provider-owned runtime state here.
        # Never log or retain it beyond the advertised lifecycle.
        return CredentialDeliveryReceipt(request_id=request.request_id)


if __name__ == "__main__":
    serve(RuntimeCredentialProvider())
```

`CredentialBytes`, `CredentialSecretReference`, and
`CredentialProtectedPath` redacts both `str` and `repr`; `CredentialFile.path`
uses that wrapper rather than a raw string. Secret-bearing dataclass fields also
use redaction or `repr=False`. Explicit `.value` or `.reveal()` access still
reveals the secret. Python cannot reliably erase immutable `bytes` or `str` objects, and a
frozen dataclass does not make contained lists immutable. Keep values local to
the hook, avoid logs/exceptions/stdout, and keep secret values out of Hovel's
public execution ledger. A provider may copy material into its own protected
runtime or installation when its advertised lifecycle requires it, but should
return only non-secret receipts or digests. Hovel's public execution
bookkeeping excludes credential bytes, protected paths, provider references,
and deployment receipts.

Python has no separate `CredentialDescriber` protocol or one interface per
execution capability: the typed hooks live on `HovelModule` and default to
unsupported. Descriptor/hook agreement is therefore checked at discovery and
dispatch time rather than by the Python type checker.

## Test Loop

Use `ModuleRPC` to test through the same framed protocol the daemon uses. This
catches broken method names, result shapes, log notifications, and session
round trips without starting `hoveld`.

```python
from hovel_sdk import ModuleRPC


def test_module_executes():
    with ModuleRPC(MyModule()) as rpc:
        result = rpc.call("execute", {"runId": "run-1", "target": "lab-1"})

    assert result["status"] == "succeeded"
```

A credential provider uses the same framed harness:

```python
from hovel_sdk import CREDENTIAL_DELIVERY_SCHEMA_V1, ModuleRPC


def test_credential_provider_contract() -> None:
    with ModuleRPC(RuntimeCredentialProvider()) as rpc:
        descriptor = rpc.call("credential.describe")

    assert descriptor["schemaVersion"] == CREDENTIAL_DELIVERY_SCHEMA_V1
    assert descriptor["deliveryCapabilities"] == ["runtime"]
```

Focused checks:

```sh
task sdk:ci
```

Use <code>task sdk:test</code> while iterating on behavior and
<code>task sdk:lint</code> for Python lint, type, and documentation checks. The
root Task wrappers select the integration workspace and remain the supported
entry point.

For deeper examples, compare:

- [`../../modules/examples/python/mock_survey`](../../modules/examples/python/mock_survey)
- [`../../modules/examples/python/mock_exploit`](../../modules/examples/python/mock_exploit)
- [`../../modules/examples/python/mock_exploit_session`](../../modules/examples/python/mock_exploit_session)
- [`../../modules/examples/python/ms17_010_exploit`](../../modules/examples/python/ms17_010_exploit)
