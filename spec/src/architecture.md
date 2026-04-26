# Architecture

Hovel uses a clean application core with adapters at the edges.

```text
adapters -> app -> domain
infra    -> app -> domain
```

The domain package must not import CLI, TUI, REST, MCP, storage, RPC, concrete module code, or concrete service code.

## Engine

`hoveld` is the local engine and is not optional. User-facing commands may bootstrap it, but execution happens through the daemon.

It owns:

1. Workspace database.
2. Run state.
3. Chain execution.
4. Module process lifecycle.
5. Service lifecycle.
6. Provider registry.
7. Artifact store.
8. Event bus.
9. Logging pipeline.
10. REST/OpenAPI endpoint when enabled.
11. MCP endpoint or adapter when enabled.
12. TUI attachment endpoint.

The CLI must auto-start `hoveld` in local mode if it is not already running.

```text
local mode:  CLI starts or uses a per-user local hoveld
server mode: hoveld is explicitly launched and clients attach
```

MVP should implement local mode first.

## Daemon Contract

Invoking `hovel` must resolve a workspace, locate or start the matching local daemon, wait until it is healthy, then execute the requested command through application services.

MVP daemon rules:

1. One active `hoveld` per workspace.
2. A workspace lock prevents duplicate daemons from owning the same database.
3. The local client transport is an implementation detail, but must support CLI, TUI, REST, and MCP attaching to the same daemon.
4. Unix-like systems should prefer a Unix domain socket under a workspace or runtime directory with filesystem permissions.
5. Windows should use a named pipe when Windows support is implemented.
6. Daemon identity, socket path, PID, start time, and health status should be inspectable with `hovel daemon status`.
7. Tests may use an in-process engine harness, but production commands should exercise the daemon boundary.

## Application Services

Application services are the only things front ends should call.

Initial services:

```text
ModuleService
ManagedServiceService
ProviderService
TargetService
PlanningService
RunService
ArtifactService
EventService
WorkspaceService
ListenerService
SessionService
PolicyService
```

Representative methods:

```text
ListModules(ctx) ([]ModuleDescriptor, error)
InspectModule(ctx, moduleID) (ModuleDescriptor, error)
ListServices(ctx) ([]ServiceDescriptor, error)
StartService(ctx, ServiceStartRequest) (ServiceID, error)
StopService(ctx, ServiceID) error
PlanRun(ctx, RunRequest) (RunPlan, error)
ApproveRun(ctx, RunPlanID, Approval) (ApprovedRun, error)
StartRun(ctx, ApprovedRun) (RunID, error)
StreamEvents(ctx, RunID) (<-chan Event, error)
CancelRun(ctx, RunID) error
ResolvePayload(ctx, PayloadQuery) (PayloadRef, error)
ResolvePayloadBytes(ctx, PayloadQuery) (PayloadBytes, error)
StartListener(ctx, ListenerRequest) (ListenerRef, error)
ListSessions(ctx, RunID) ([]SessionRef, error)
EvaluatePolicy(ctx, ActionRequest) (PolicyDecision, error)
```

`StartRun` must not accept a raw `RunRequest`. A caller first asks for a plan, reviews the policy output, records the approval or confirmation decision, and then starts the approved plan. This keeps CLI, TUI, REST, and MCP on the same safety path.

## Package Layout

Recommended initial Go layout:

```text
hovel/
  cmd/
    hovel/
    hoveld/
  internal/
    app/
      services/
      commands/
      queries/
    domain/
      target/
      module/
      service/
      chain/
      provider/
      payload/
      listener/
      session/
      run/
      artifact/
      event/
    adapters/
      cli/
      tui/
      rest/
      mcp/
      modulerpc/
      servicerpc/
      storage/
      logging/
    infra/
      process/
      rpc/
      sqlite/
      filesystem/
      scheduler/
      supervisor/
      network/
  sdks/
    python/
      hovel_sdk/
  modules/
    builtin/
    examples/
  services/
    examples/
  schemas/
```

## Multi-Client Attach

Multiple clients should be able to observe the same engine state:

1. One operator starts a chain.
2. Another operator attaches with the TUI.
3. MCP tooling inspects the same run.
4. CLI commands query state while the TUI is open.
5. Service logs and run events remain centralized.

## Test Harness

Application services must be constructible in-process for unit, contract, and integration tests. The in-process harness should use the same domain logic, policy checks, event bus contracts, descriptor validation, and storage interfaces as `hoveld`.

Production `hovel` commands should still cross the daemon boundary. Tests may use the in-process harness to keep core behavior fast and deterministic, but daemon-contract tests must verify workspace locking, daemon discovery, health checks, client attachment, and command execution through the local transport.
