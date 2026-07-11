# Python SDK

The Python SDK is the quickest path for exploit, survey, and post-exploitation
module work. Copy one of the examples in [`../../modules/examples/python`](../../modules/examples/python)
and keep the public boundary small: subclass `HovelModule`, describe cheap
metadata/configuration, then put target interaction in `run` or explicit step
hooks.

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
| Provider-owned node operations | Override `describe_mesh`, `mesh_topology`, `list_mesh_beacons`, `run_mesh_task`, and `open_mesh_stream`. |

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
can also override topology, beacons, triggers in the descriptor, and tasking.
Use `MESH_TASK_UPLOAD_EXECUTE` for implant copy-then-run flows and
`MESH_TASK_LOAD` for provider-native implant/component loaders. Requests can
carry inline bytes in `input_data`/`input_encoding` or provider-defined artifact
references in `config`.

Python does not currently dispatch payload-provider RPC methods such as
`list_payloads` or `generate_payload`. Use Go for provider modules today, or
return installed-payload descriptors from a Python exploit when it installs or
observes a durable payload.

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

Focused checks:

```sh
task check
```

The Python SDK and Python examples are outside the core Bazel workspace after
the partial-checkout split. Restore a slice-local Python SDK check before
documenting focused SDK labels or Python lint/typecheck tasks again.

For deeper examples, compare:

- [`../../modules/examples/python/mock_survey`](../../modules/examples/python/mock_survey)
- [`../../modules/examples/python/mock_exploit`](../../modules/examples/python/mock_exploit)
- [`../../modules/examples/python/mock_exploit_session`](../../modules/examples/python/mock_exploit_session)
- [`../../modules/examples/python/ms17_010_exploit`](../../modules/examples/python/ms17_010_exploit)
