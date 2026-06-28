# Python SDK

The Python SDK is the quickest path for exploit, survey, and post-exploitation
module work. Copy one of the examples in [`../../examples/python`](../../examples/python)
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
task test -- //sdk/python:hovel_sdk_test
task test -- //examples/python/...
task python:check
```

Full gate:

```sh
task ci
```

For deeper examples, compare:

- [`../../examples/python/mock_survey`](../../examples/python/mock_survey)
- [`../../examples/python/mock_exploit`](../../examples/python/mock_exploit)
- [`../../examples/python/mock_exploit_session`](../../examples/python/mock_exploit_session)
- [`../../examples/python/ms17_010_exploit`](../../examples/python/ms17_010_exploit)
