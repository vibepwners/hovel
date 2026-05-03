# Testing and Roadmap

Testing should focus on contracts first. The risk is not only individual functions breaking; it is adapters disagreeing about the same operation, chain, throw, service, provider, or event.

## Go Host Tests

Require:

1. Unit tests for domain logic.
2. Application service tests.
3. Adapter tests with fake services.
4. Module protocol contract tests.
5. Service protocol contract tests.
6. Supervisor tests.
7. Golden tests for one-shot chain-file output.
8. CLI prompt model, completion, and render tests.
9. TUI model/update tests.

## Python SDK Tests

Require:

1. Logging handler tests.
2. RPC protocol tests.
3. Decorator and class module tests.
4. Service decorator tests.
5. Provider client tests.
6. Packaging tests.

## Integration Tests

First-slice integration tests:

1. Host launches Python module.
2. Module handshakes.
3. Module emits logs.
4. Module returns result.
5. Host captures stdout, stderr, and logging as structured events.
6. Host records malformed protocol output as a failed module execution.
7. One-shot chain-file execution displays throw results.
8. `hovel` starts or attaches to `hoveld`.
9. One-shot chain-file execution crosses the daemon boundary.
10. Throw plan, confirmation record, events, artifacts, and final throw state are persisted.
11. Interactive `throw`, `confirm`, and one-shot chain-file execution share the same planning and review path.
12. `throw --now` persists an auditable bypass confirmation record.
13. If `cli` or `tui` starts a managed daemon, it stops that daemon on exit.
14. If `cli` or `tui` attaches to an existing daemon, it leaves that daemon running on exit.
15. A `cli` session can select an operation and chain, add targets, and issue `throw` using attachment state.
16. `chain save <file>` and `chain load <file>` preserve both targetless chain templates and configured chains with target config.
17. Two daemon clients attached to the same operation can use different active chains concurrently without leaking targets, logs, or prompt context.
18. One-shot execution of a saved chain file does not mutate another client's active chain.

Follow-on integration tests:

1. Module requests a provider resource.
2. Host launches managed service.
3. Service handshakes.
4. Service health check passes.
5. Service provides payload or listener resource.
6. MCP can inspect and plan the same throw as one-shot execution and `cli` through shared guardrails.
7. MCP can execute only through the shared confirmation path.
8. TUI consumes event stream.

## Coverage Targets

Initial targets:

```text
Domain: 90%+
Application services: 85%+
Adapters: practical coverage, not vanity coverage
Python SDK: 85%+
```

Eventually:

```text
Strict branch coverage gates for core packages.
```

## Milestones

### Milestone 1: Skeleton

1. Create Go repo skeleton.
2. Add `hovel` mono-binary root.
3. Add `hovel daemon` engine skeleton.
4. Add domain packages.
5. Add event model.
6. Add module descriptor schema.
7. Add service descriptor schema.
8. Add local workspace initialization under `control init`.
9. Add in-process application service test harness.
10. Add daemon status under `control daemon status` and workspace locking contract.

### Milestone 2: Module Runtime

1. Implement JSON-RPC-over-stdio module host with `Content-Length` framing.
2. Implement Python SDK handshake.
3. Implement Python logging handler.
4. Run a toy Python module from Go.
5. Stream logs into one-shot execution and `cli`.
6. Persist module execution events.
7. Treat malformed frames and unexpected stdout bytes as module failures.

### Milestone 3: Throw and Artifact Persistence

1. Implement persisted throw plans.
2. Implement minimal confirmation records keyed by plan hash.
3. Implement throw state persistence.
4. Implement artifact provider.
5. Hash-track artifacts and payload-like bytes, storing large artifact bytes outside SQLite.
6. Inspect throws and artifacts from `cli` and supported API surfaces.

### Milestone 4: Providers

1. Implement payload provider interface.
2. Add local payload registry.
3. Resolve tagged bytes from local or stub providers.
4. Persist payload metadata and hashes before execution when practical.
5. Return payload refs to Python modules.

### Milestone 5: Service Manager

1. Implement supervised service process manager.
2. Implement service descriptor loading.
3. Implement service handshake.
4. Implement service health checks.
5. Implement toy service that emits logs.

### Milestone 6: Chain Thrower

1. Implement simple sequential chain runner.
2. Add phases and steps.
3. Add chain template and configured chain save/load.
4. Add service start/stop steps.
5. Add event stream.
6. Add per-target throw state.
7. Add cancellation hooks.
8. Support only simple input and step-output references at first.

### Milestone 7: Conceptual Chain Demo

1. Implement a survey module against controlled lab inputs.
2. Resolve a tagged byte payload from a local or stub provider.
3. Exercise one managed service placeholder.
4. Implement delivery strategy selection without project-owned exploit code.
5. Capture transcript artifact.
6. Produce full throw result.

### Milestone 8: TUI Alpha

1. Add Bubble Tea app.
2. Add dashboard.
3. Add live throw view.
4. Add log panel.
5. Add service panel.
6. Add listener/session panel.
7. Add target matrix.
8. Add theme selector.
9. Add README demo.
10. Cut alpha release.

## Hard Rules

1. `cli` and one-shot chain-file execution first, TUI second.
2. `hoveld` is mandatory and owns operations, chains, throws, services, modules, events, providers, artifacts, evidence, and sessions.
3. TUI calls application services only.
4. MCP calls application services only.
5. REST calls application services only.
6. MCP has eventual operator parity through the same guardrail and audit model.
7. Throw execution requires a persisted plan and confirmation record.
8. Python module authors should not need to see transport internals.
9. Python service authors should not need to see transport internals.
10. All module logs flow through the host.
11. All service logs flow through the host.
12. Providers are typed.
13. First-slice providers are artifact and payload only.
14. Payload provider outputs are tagged bytes with minimal framework validation.
15. Services are lifecycle-managed.
16. Payloads are content-addressed or hash-tracked.
17. Chain throws are replay-inspectable.
18. Public demos are authorized and lab-safe.
