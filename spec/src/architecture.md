# Architecture

Hovel uses a clean application core with adapters at the edges.

```text
adapters -> app -> domain
infra    -> app -> domain
```

The domain package must not import CLI, TUI, REST, MCP, storage, RPC, concrete module code, or concrete service code.

## Engine

`hoveld` is the local engine role and is not optional. It is served by the `hovel` mono-binary rather than a separate production binary. User-facing commands may bootstrap it, but execution happens through the daemon role.

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

The primary executable is one `hovel` binary with four top-level roles:

```text
hovel command ...
hovel cli ...
hovel daemon ...
hovel tui ...
```

`cli` and `tui` must auto-start or attach to the daemon role in local mode. `command` mode must not silently auto-start the daemon for ordinary operator commands; daemon-backed command invocations should require an already-running daemon, except for explicit daemon-management commands.

```text
managed local mode: hovel cli or hovel tui starts or uses a local daemon
command mode:       hovel command connects to an existing daemon unless explicitly managing daemon lifecycle
server mode: hovel daemon serve is explicitly launched and clients attach
```

MVP should implement local mode first.

## Daemon Contract

Daemon-backed `hovel` operations must resolve a workspace, locate the matching local daemon, wait until it is healthy, then execute through application services. `cli` and `tui` may start a managed daemon when none exists. `command` mode should require an already-running daemon unless the operator explicitly invokes daemon lifecycle management.

MVP daemon rules:

1. One active `hoveld` per workspace.
2. A workspace lock prevents duplicate daemons from owning the same database.
3. The local client transport is an implementation detail, but must support `command`, `cli`, `tui`, REST, and MCP attaching to the same daemon.
4. Unix-like systems should prefer a Unix domain socket under a workspace or runtime directory with filesystem permissions.
5. Windows should use a named pipe when Windows support is implemented.
6. Daemon identity, socket path, PID, start time, and health status should be inspectable with `hovel daemon status` and from the shared registry as `control daemon status`.
7. Tests may use an in-process engine harness, but production commands should exercise the daemon boundary.
8. The first RPC contract should prove a fully mocked throw flow: `command` mode calls the daemon over local RPC, the daemon invokes a Go mock module through the selected chain, and the result returns through the RPC boundary.
9. Mock exploit modules must not perform network exploitation. They exist to test orchestration, events, artifacts, approvals, and transport boundaries.

Managed daemon ownership rules:

1. If `hovel cli` or `hovel tui` finds an already-running daemon for the workspace, it attaches and leaves that daemon running on exit.
2. If `hovel cli` or `hovel tui` starts the daemon because none is running, that daemon is owned by the interactive session.
3. An owned daemon should shut down when the owning `cli` or `tui` session exits.
4. Ownership must be explicit in tests: started-by-session daemons are stopped on exit; preexisting daemons are not.
5. `hovel command` should not create a session-owned daemon as a side effect of an ordinary command.

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

## Command Registry

Application command definitions live in a central registry. The registry is the single source of truth for command paths, aliases, arguments, switches, options, defaults, required values, validation, help text, completion metadata, output modes, and handler bindings.

The initial operator registry should expose execution through chain and target setup, not a top-level `run` command:

```text
control init
control daemon status
chain create <chain>
chain use <chain-or-module>
chain rename <chain> <name>
chain list
chain inspect
chain delete <chain>
chain logs
targets add <target>
targets clear
throw
```

Chains are durable operator resources, not just a transient prompt variable. The selected chain owns its target set and log topic, and target commands mutate only the active chain. Non-interactive `command` mode must remain scriptable by accepting explicit options such as `hovel command throw --chain mock-exploit --target mock://target`.

Adapters consume the registry differently:

1. `command` mode renders registry definitions as argparse parsers.
2. `cli` mode renders registry definitions as go-prompt completions, contextual help, and validated interactive invocations.
3. `tui` mode may use the registry for command palettes and action metadata.
4. MCP and REST may use the registry metadata where useful, but they must still call application services through typed APIs.

Command handlers receive validated invocation objects from the registry layer. They must not parse raw shell strings or argv themselves.

## Package Layout

Recommended initial Go layout:

```text
hovel/
  cmd/
    hovel/
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
      command/
      cli/
      tui/
      rest/
      mcp/
      modulerpc/
      servicerpc/
      storage/
      logging/
    ui/
      terminaltheme/
      prompt/
    infra/
      daemonmanager/
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

1. One operator creates or activates a chain.
2. Another operator attaches with the TUI.
3. MCP tooling attaches to the same chain.
4. `command` invocations query chain, target, run, and log state while the TUI is open.
5. CLI prompt commands query and control the same daemon-owned chain state.
6. The daemon publishes a chain-owned log topic such as `chain/<chain>/logs`.
7. Clients attached to the same chain see the same chain logs.
8. Clients attached to other chains do not receive those logs by default.
9. Service logs and run events remain centralized and can be correlated back to the owning chain.

## Test Harness

Application services must be constructible in-process for unit, contract, and integration tests. The in-process harness should use the same domain logic, policy checks, event bus contracts, descriptor validation, and storage interfaces as `hoveld`.

Production `hovel command`, `hovel cli`, and `hovel tui` behavior should still cross the daemon boundary for daemon-backed operations. Tests may use the in-process harness to keep core behavior fast and deterministic, but daemon-contract tests must verify workspace locking, daemon discovery, managed daemon ownership, health checks, client attachment, and command execution through the local transport.
