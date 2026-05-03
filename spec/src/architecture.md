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
2. Throw state.
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

The primary executable is one `hovel` binary with these product roles:

```text
hovel cli ...
hovel daemon ...
hovel tui ...
```

`hovel tui` is part of the product contract but may remain an explicit "not implemented yet" role until the TUI milestone. The production operator surface should center on `hovel cli` for stateful work and on a narrow one-shot shell surface for throwing a saved chain file.

`cli` and, once implemented, `tui` must auto-start or attach to the daemon role in local mode. General-purpose `hovel command ...` mode is not part of the product contract. Shell one-shot execution is limited to saved chain files and daemon-management commands.

```text
managed local mode: hovel cli or hovel tui starts or uses a local daemon
one-shot mode:      hovel throw <chain-file> prompts for confirmation unless --now is passed
server mode: hovel daemon serve is explicitly launched and clients attach
```

MVP should implement local mode first.

## Daemon Contract

Daemon-backed `hovel` operations must resolve a workspace, locate the matching local daemon, wait until it is healthy, then execute through application services. `cli` and `tui` may start a managed daemon when none exists. One-shot chain-file execution may start or attach to a local daemon, but it must use the same planning, confirmation, event, artifact, and persistence path as interactive execution.

MVP daemon rules:

1. One active `hoveld` per workspace.
2. A workspace lock prevents duplicate daemons from owning the same database.
3. The local client transport is an implementation detail, but must support `cli`, one-shot chain-file execution, `tui`, REST, and MCP attaching to the same daemon.
4. Unix-like systems should prefer a Unix domain socket under a workspace or runtime directory with filesystem permissions.
5. Windows should use a named pipe when Windows support is implemented.
6. Daemon identity, socket path, PID, start time, and health status should be inspectable with `hovel daemon status` and from the shared registry as `control daemon status`.
7. Tests may use an in-process engine harness, but production commands should exercise the daemon boundary.
8. The first RPC contract should prove a fully mocked throw flow through the daemon boundary.
9. Mock exploit modules must not perform network exploitation. They exist in-tree for tests and examples, should exercise the same module-loading path as ordinary modules where practical, and are not part of the final shipped module catalog.

Managed daemon ownership rules:

1. If `hovel cli` or `hovel tui` finds an already-running daemon for the workspace, it attaches and leaves that daemon running on exit.
2. If `hovel cli` or `hovel tui` starts the daemon because none is running, that daemon is owned by the interactive session.
3. An owned daemon should shut down when the owning `cli` or `tui` session exits.
4. Ownership must be explicit in tests: started-by-session daemons are stopped on exit; preexisting daemons are not.
5. One-shot chain-file execution must not create hidden durable operator session state beyond the throw records, events, artifacts, and logs it explicitly produces.

## Application Services

Application services are the only things front ends should call.

Initial services:

```text
ModuleService
ManagedServiceService
ProviderService
TargetService
PlanningService
ThrowService
ArtifactService
EventService
WorkspaceService
ListenerService
SessionService
GuardrailService
```

Representative methods:

```text
ListModules(ctx) ([]ModuleDescriptor, error)
InspectModule(ctx, moduleID) (ModuleDescriptor, error)
ListServices(ctx) ([]ServiceDescriptor, error)
StartService(ctx, ServiceStartRequest) (ServiceID, error)
StopService(ctx, ServiceID) error
PlanThrow(ctx, ThrowRequest) (ThrowPlan, error)
ConfirmThrow(ctx, ThrowPlanID, Confirmation) (ConfirmedThrow, error)
StartThrow(ctx, ConfirmedThrow) (ThrowID, error)
StreamEvents(ctx, ThrowID) (<-chan Event, error)
CancelThrow(ctx, ThrowID) error
ResolvePayload(ctx, PayloadQuery) (PayloadRef, error)
ResolvePayloadBytes(ctx, PayloadQuery) (PayloadBytes, error)
StartListener(ctx, ListenerRequest) (ListenerRef, error)
ListSessions(ctx, ThrowID) ([]SessionRef, error)
CheckGuardrails(ctx, ActionRequest) (GuardrailResult, error)
```

`StartThrow` must not accept a raw `ThrowRequest`. A caller first asks for a plan, reviews the exact configuration that will be executed, records the explicit confirmation, and then starts the confirmed throw. This keeps CLI, TUI, REST, MCP, and one-shot chain-file execution on the same safety path.

Interactive `throw` behavior:

1. `throw` builds or refreshes the throw plan for the active chain.
2. If a matching confirmation already exists for the exact plan hash, Hovel starts the throw.
3. If no matching confirmation exists, `throw` displays the same review surface as `confirm`, asks the operator to type `yes`, records the confirmation, and then starts the throw.
4. `throw --now` bypasses the prompt but must still persist a confirmation record showing that the bypass was requested.
5. `confirm` displays the same configuration review and records a pre-confirmation without starting execution.

Confirmations do not expire by time. A confirmation is invalidated by any change that changes the plan hash. The confirmation record should stay small: plan hash, timestamp, and client ID are required. Additional fields may be recorded when already available, but should not require heavyweight identity or account systems.

## Command Registry

Application command definitions live in a central registry. The registry is the single source of truth for interactive CLI commands, TUI action metadata, one-shot chain-file execution options, help, validation, output modes, and handler bindings.

The initial operator registry should expose execution through chain and target setup, not a top-level `run` command:

```text
control daemon status
op create <operation>
op use <operation>
op list
op inspect
chain create <chain>
chain use <chain-or-module>
chain add <module>
chain rename <chain> <name>
chain save <file>
chain load <file>
chain list
chain inspect
chain delete <chain>
chain logs
target add <target>
target clear
confirm
throw
throw list
throw inspect <throw>
```

Operations and chains are durable operator resources, not just transient prompt variables. The selected operation owns chains; each client attachment owns its active chain selection. Target commands mutate only the caller's active chain. Saved chain files are the portable representation for shell one-shot execution.

The one-shot shell form is:

```text
hovel throw <chain-file>
hovel throw <chain-file> --now
```

The non-`--now` form must display the same configuration review as interactive `throw` and require the operator to type `yes`.

Adapters consume the registry differently:

1. `cli` mode renders registry definitions as go-prompt completions, contextual help, and validated interactive invocations.
2. `tui` mode may use the registry for command palettes and action metadata.
3. The one-shot chain-file command renders only the options needed to load, review, confirm, and execute a chain file.
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
      throw/
      artifact/
      event/
    adapters/
      oneshot/
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
    in_tree/
    examples/
  services/
    examples/
  schemas/
```

## Multi-Client Attach

Multiple clients should be able to observe the same engine state:

1. One operator creates or activates an operation.
2. One client selects chain `alpha`; another client selects chain `beta` in the same operation.
3. MCP tooling can attach to the same operation and choose either chain.
4. One-shot invocations can import and throw a saved chain file without mutating another client's active chain selection.
5. CLI prompt commands query and control the same daemon-owned operation and chain state.
6. The daemon publishes operation-scoped chain topics such as `operation/<operation>/chain/<chain>/logs`.
7. Clients attached to the same operation and chain see the same chain logs.
8. Clients attached to other chains do not receive those logs by default.
9. Service logs and throw events remain centralized and can be correlated back to the owning operation and chain.

## Workspace Database

Every workspace owns a SQLite database at `<workspace>/workspace.db`. The database is the durable state store for operator session state, operations, chains, targets, steps, config, throw plans, confirmation records, throw records, events, artifact metadata, and final throw state. File directories under the workspace remain for artifacts, logs, modules, services, and other file-shaped data.

Schema changes must go through the formal migration system. Each migration has a contiguous integer version, a stable name, and a checksum recorded in `schema_migrations`. Startup and workspace initialization must apply pending migrations idempotently and reject unknown, renamed, or modified applied migrations.

## Test Harness

Application services must be constructible in-process for unit, contract, and integration tests. The in-process harness should use the same domain logic, guardrail checks, event bus contracts, descriptor validation, and storage interfaces as `hoveld`.

Production `hovel cli`, one-shot chain-file execution, and `hovel tui` behavior should still cross the daemon boundary for daemon-backed operations. Tests may use the in-process harness to keep core behavior fast and deterministic, but daemon-contract tests must verify workspace locking, daemon discovery, managed daemon ownership, health checks, client attachment, and execution through the local transport.
