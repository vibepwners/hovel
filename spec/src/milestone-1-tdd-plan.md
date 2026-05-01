# Milestone 1 TDD Plan

Milestone 1 should establish the Bazel-first Go skeleton, domain vocabulary, workspace initialization, daemon contract, descriptor validation shape, event model, and in-process test harness. It should not include real module execution.

The implementation approach is domain-driven design with test-driven development:

1. Write a failing acceptance or contract test.
2. Add the smallest domain, application, or adapter code that passes.
3. Refactor toward clear bounded contexts and ports.
4. Repeat until the milestone definition of done is satisfied.

## Target Scope

Milestone 1 should deliver:

1. `cmd/hovel`.
2. Mono-binary daemon role through `hovel daemon`.
3. `internal/domain/...`.
4. `internal/app/services/...`.
5. `internal/adapters/cli/...`.
6. `internal/adapters/storage/...`.
7. `internal/infra/...`.
8. Workspace initialization.
9. Daemon status model.
10. Workspace locking contract.
11. Event model.
12. Module and service descriptor schema files.
13. In-process application service test harness.

Milestone 1 should not deliver the Python module runtime, real managed services, provider-backed payload resolution, chain execution, REST, MCP execution, or the TUI.

## Domain Boundaries

Initial bounded contexts:

```text
workspace
event
module
service
throw
guardrail
```

The domain layer must stay pure. Domain packages must not import CLI, Cobra, filesystem adapters, SQLite, sockets, JSON-RPC, YAML parsers, or generated transport code.

Responsibilities:

1. `workspace`: workspace identity, paths, lock ownership, and config concepts.
2. `event`: domain event types, event envelope, and event bus port.
3. `module`: module descriptor identity and validation concepts.
4. `service`: service descriptor identity and validation concepts.
5. `throw`: throw IDs and initial throw-plan placeholders only.
6. `guardrail`: initial scope-check placeholders only.

Adapters translate CLI flags, files, daemon transports, and storage records into application service calls. Application services coordinate domain behavior through ports.

## TDD Sequence

### 1. Repository Shape

Write the failing tests first:

1. `bazel test //...` discovers at least one Go or shell test target.
2. `bazel run //:gazelle -- -mode=diff` succeeds.

Then implement:

1. Empty Go package skeletons.
2. BUILD targets generated or accepted by Gazelle.
3. One smoke test that keeps the test graph non-empty.

### 2. Workspace Domain

Write domain unit tests first:

1. Workspace names validate allowed and rejected values.
2. Default workspace path resolves to `.hovel`.
3. Workspace IDs are non-empty value objects.
4. Workspace identity does not depend on filesystem access.

Then implement `internal/domain/workspace`.

### 3. Workspace Init Service

Write application service tests first:

1. `InitWorkspace` creates the expected workspace metadata model.
2. Re-running `InitWorkspace` is idempotent.
3. `InitWorkspace` emits a domain event.

Write adapter tests with temporary directories:

1. `.hovel/` is created.
2. Workspace config is created.
3. Initial storage directories are created.
4. Existing valid workspace data is preserved.

Then implement `WorkspaceService` and filesystem-backed storage ports.

### 4. CLI `control init`

Write CLI golden tests first:

1. `hovel command control init --workspace <tmp>` prints stable human-readable output.
2. `hovel command control init --workspace <tmp> --json` emits structured JSON.
3. Invalid workspace paths return a non-zero exit and a stable error.

Then implement the minimal CLI adapter. The CLI should call application services only.

### 5. Event Model

Write domain tests first:

1. Events require IDs.
2. Event types are validated.
3. Timestamps are present.
4. Events can carry workspace, throw, module, service, and target references.

Write application tests:

1. Workspace initialization emits `workspace.initialized`.
2. Events are available through an in-memory event sink in tests.

Then implement the event model and in-memory event bus port implementation.

### 6. Descriptor Schema Files

Write schema smoke tests first:

1. Module schema file exists.
2. Service schema file exists.
3. A valid minimal module descriptor passes.
4. An invalid module descriptor fails.
5. A valid minimal service descriptor passes.
6. An invalid service descriptor fails.

Then implement schema files and a validation adapter. The domain should receive validated descriptor structs rather than parsing YAML directly.

### 7. Daemon Identity and Status

Write domain tests first:

1. Daemon identity includes workspace ID or path.
2. Daemon identity includes PID.
3. Daemon identity includes socket path.
4. Daemon identity includes start time.
5. Daemon identity includes health status.

Write application service tests:

1. `DaemonStatus` returns `not_running` before daemon startup.
2. `DaemonStatus` returns the active daemon identity after startup in a harness.

Then implement the daemon status model and service.

### 8. Workspace Locking

Write adapter tests with temporary directories:

1. First lock acquisition succeeds.
2. Second lock acquisition for the same workspace fails.
3. Lock release permits reacquisition.
4. Stale-lock behavior is explicit and conservative.

Then implement the file lock adapter. The domain may model lock ownership, but real locking remains an infrastructure concern.

### 9. `hoveld` Skeleton

Write daemon contract tests first:

1. Start `hoveld` against a temporary workspace.
2. Wait until it reports healthy.
3. `hovel command control daemon status --workspace <tmp>` reports the same daemon identity.
4. Duplicate daemon startup for the same workspace is rejected.

Then implement the minimal daemon lifecycle and local transport. The transport can be narrow in Milestone 1, but production `hovel` commands should exercise the daemon boundary when they claim daemon behavior.

### 10. In-Process Test Harness

Write harness tests first:

1. Application services can be constructed without a daemon process.
2. Fake storage and event sinks are injectable.
3. The harness uses the same domain logic and guardrail checks as production.

Then implement `internal/app/apptest` or an equivalent package.

## Test Layers

Use these layers consistently:

1. Domain unit tests: fast, deterministic, no filesystem.
2. Application service tests: fake ports, no real daemon.
3. Adapter tests: temporary directories and real file operations.
4. CLI golden tests: stable stdout, stderr, exit codes, and JSON.
5. Daemon contract tests: real process or daemon harness, with production CLI crossing the daemon boundary where applicable.

## Definition of Done

Milestone 1 is complete when these commands pass:

```bash
bazel build //...
bazel test //...
bazel run //:gazelle -- -mode=diff
```

The repository should also expose these user-visible flows:

```bash
bazel run //cmd/hovel -- command control init --workspace /tmp/hovel-lab
bazel run //cmd/hovel -- command control daemon status --workspace /tmp/hovel-lab
```

The daemon status may be minimal, but the tests must enforce the domain/application/adapter boundaries and the daemon contract.
