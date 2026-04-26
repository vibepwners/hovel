# Modules and Services

Modules and services are separate domain concepts with separate lifecycle expectations.

## Module Runtime

The MVP module runtime should optimize for Python ergonomics and debuggability.

Runtime types:

```text
python-rpc        MVP
native-builtin    MVP
process-rpc       later
go-binary-rpc     later
rust-binary-rpc   later
node-rpc          later
```

MVP priority:

1. Python RPC modules.
2. Native built-in Go modules.
3. Generic process fallback only after the Python path is stable.

The host starts module processes, connects to them over a controlled channel, exchanges typed messages, receives structured logs, supervises lifecycle, and persists events.

## Module Lifecycle

```text
discover
validate
start
handshake
configure
execute
stream events
finish
shutdown
```

Every module must provide or emulate:

```text
handshake() -> ModuleInfo
schema() -> ModuleSchema
execute(request: ExecuteRequest) -> ExecuteResult
shutdown() -> ShutdownResult
```

Optional methods:

```text
plan(request: PlanRequest) -> PlanResult
validate(request: ValidateRequest) -> ValidateResult
cancel(request: CancelRequest) -> CancelResult
stream() -> EventStream
```

## Service Runtime

Services are long-lived capabilities managed by Hovel.

A service may be:

1. Built into the Go host.
2. A Go binary launched by Hovel.
3. A Python process launched by Hovel.
4. A Rust binary launched by Hovel.
5. A pre-existing process Hovel connects to.
6. A future remote service.

Services expose typed operations to the Hovel engine.

## Service Lifecycle

```text
discover
validate
start
handshake
configure
health_check
ready
serve
reload
stop
cleanup
```

Service states:

```text
registered
starting
configuring
healthy
degraded
failed
stopping
stopped
```

Start modes:

```text
manual       operator starts explicitly
on_demand    started when a provider or service is requested
run_scoped   started for one run and stopped after cleanup
workspace    started with workspace or daemon
external     Hovel connects to an already running service
```

Every service must implement or emulate:

```text
handshake() -> ServiceInfo
schema() -> ServiceSchema
start(request: StartRequest) -> StartResult
health() -> HealthResult
stop(request: StopRequest) -> StopResult
```

Provider services additionally implement provider-specific methods.

Payload provider service methods:

```text
list_payloads(query) -> []PayloadRef
resolve_payload(query) -> PayloadRef
generate_payload(request) -> PayloadRef
```

Listener service methods:

```text
start_listener(request) -> ListenerRef
stop_listener(listenerRef) -> StopResult
list_sessions(listenerRef) -> []SessionRef
attach_session(sessionRef) -> SessionStream
close_session(sessionRef) -> CloseResult
```

## Protocol Position

The first protocol should optimize for simplicity and observability.

Recommended MVP:

1. JSON-RPC over stdio for Python modules.
2. A small shared envelope for logs, events, requests, and responses.
3. Contract tests before broad runtime support.
4. gRPC or socket-based protocols only after contracts settle.

Module and service processes may eventually share one protocol, but that should not be assumed before contract tests prove the common lifecycle and event needs. The Python module contract should harden first.

MVP stdio framing:

1. Use UTF-8 JSON-RPC 2.0 messages.
2. Frame each message with an LSP-style `Content-Length: <bytes>\r\n\r\n` header.
3. Reserve stdout exclusively for framed protocol messages.
4. Capture Python `print()`, `logging`, and stderr in the SDK and forward them as structured log events.
5. Treat malformed frames, unexpected stdout bytes, and protocol timeouts as module failures with persisted events.
6. Support host-to-module cancellation as a JSON-RPC notification.
7. Add a lightweight heartbeat or health request before supporting long-running modules.

Do not use the same byte stream for both RPC frames and arbitrary module output. Modules that write arbitrary bytes directly to file descriptor 1 are incompatible with stdio RPC and should use a later process mode or a dedicated side-channel transport.

## Python SDK

Python module authors should not have to know about RPC. They should write normal Python with a tiny Hovel SDK surface area.

Minimal module:

```python
from hovel_sdk import module, Context, Result

@module(name="hello")
def run(ctx: Context) -> Result:
    ctx.log.info("hello from module")
    return Result.ok({"message": "done"})
```

Class-based module:

```python
from hovel_sdk import HovelModule, Context, Result

class SSHMemoryModule(HovelModule):
    name = "ssh-memory"

    def run(self, ctx: Context) -> Result:
        target = ctx.input("target")
        payload = ctx.providers.payload.resolve(ctx.input("payload"))
        ctx.log.info("resolved payload", extra={"payload": payload.name})
        return Result.ok({"target": target})
```

Service author experience:

```python
from hovel_sdk import service, ServiceContext

@service(name="picblob-provider")
class PicBlobProvider:
    def generate_payload(self, ctx: ServiceContext, req):
        ctx.log.info("generating PIC payload", extra={"arch": req.arch})
        blob = build_blob(req)
        return ctx.payloads.bytes(blob, kind="pic", arch=req.arch)
```

## Python Packaging

Supported packaging options:

1. Source directory with `pyproject.toml`.
2. PEX file.
3. Zipapp/pyz.
4. Installed Python package.
5. Arbitrary command.

Recommended sequence:

1. Start with local source modules and services.
2. Add PEX support for dependency isolation.
3. Add broader package discovery after the descriptor schema is stable.

Descriptor examples:

```yaml
runtime:
  type: python-rpc
  packaging: source
  entrypoint: python -m hovel_ssh_memory
```

```yaml
runtime:
  type: python-service-rpc
  packaging: pex
  entrypoint: hovel_picblob_service:main
```

## Logging

The Python SDK must install a logging handler that forwards structured logs to the host.

```python
from hovel_sdk import setup_logging

setup_logging()
```

If a module uses the `@module` decorator, `@service` decorator, or Hovel entrypoint, logging setup should happen automatically.
