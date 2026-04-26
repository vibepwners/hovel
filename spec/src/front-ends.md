# Front Ends

Front ends are adapters over application services. They must share validation, planning, execution, event streaming, safety policy, and audit behavior.

## CLI

The CLI is the first interface and should exist before the TUI becomes complex. Invoking `hovel` must start or attach to `hoveld` before executing commands.

Requirements:

1. Human-readable output by default.
2. `--json` for structured automation.
3. `--no-color` for simple terminals.
4. `--verbose` and `--debug`.
5. `--workspace` selection.
6. Shell completion.
7. Module and service inspection.
8. Run planning and execution.
9. Service lifecycle control.
10. Artifact, listener, and session listing.

Recommended command tree:

```text
hovel
  init
  daemon
    start
    stop
    status
  tui
  run <chain-or-module>
  plan <chain-or-module>
  modules
    list
    inspect <module>
    scaffold
    validate <path>
  services
    list
    inspect <service>
    start <service>
    stop <service>
    logs <service>
    scaffold
    validate <path>
  providers
    list
    inspect <provider>
  payloads
    list
    inspect <payload>
    build <payload>
  listeners
    list
    inspect <listener>
    stop <listener>
  sessions
    list
    attach <session>
    close <session>
  targets
    add
    list
    inspect
    import
  runs
    list
    inspect <run>
    logs <run>
    artifacts <run>
  serve
  mcp
```

## TUI

The TUI is the visual identity of the project, but it should remain a client over `hoveld`.

Requirements:

1. Attaches to `hoveld`.
2. Consumes the same event stream as CLI, API, and MCP.
3. Works over SSH.
4. Degrades gracefully on limited terminals.
5. Supports multiple clients attached to the same engine.
6. Uses Bubble Tea, Bubbles, and Lip Gloss.

Initial screens:

```text
Dashboard
Module Browser
Service Browser
Run Planner
Live Run View
Target Matrix
Provider Browser
Payload Browser
Listener Panel
Session Panel
Evidence Viewer
Artifact Viewer
Log Stream
Settings / Theme Selector
```

Live run view should include:

1. Chain phase timeline.
2. Per-target status matrix.
3. Module logs.
4. Service logs.
5. Listener state.
6. Session state.
7. Current step details.
8. Artifact count.
9. Findings count.
10. Error panel.
11. Progress indicators.

## REST/OpenAPI

The REST API should be generated from Go types where possible.

REST should not block the first useful CLI and event-stream loop. It may ship in the first alpha if needed for MCP or external automation, but it must remain an adapter over application services.

Primary uses:

1. TUI testing.
2. MCP adapter.
3. External automation.
4. Future web UI.
5. Chain execution from scripts.
6. Service lifecycle management.
7. Listener and session inspection.

Recommended API groups:

```text
/api/v1/modules
/api/v1/services
/api/v1/providers
/api/v1/payloads
/api/v1/listeners
/api/v1/sessions
/api/v1/targets
/api/v1/runs
/api/v1/artifacts
/api/v1/events
```

Event streaming may use Server-Sent Events or WebSockets.

## MCP Adapter

MCP is another front end over the same application services.

MCP has eventual operator parity: anything a human can do through CLI/TUI/API should be representable through MCP, subject to the same policy checks, confirmations, planning output, and audit trail. The implementation should ship inspection and planning tools before execution tools unless the shared approval and audit path is already complete.

Initial inspection and planning tools:

```text
hovel_list_modules
hovel_inspect_module
hovel_list_services
hovel_get_service_status
hovel_plan_run
hovel_review_policy
hovel_get_run_status
hovel_list_artifacts
hovel_get_artifact
hovel_list_targets
hovel_resolve_payload
hovel_list_listeners
hovel_list_sessions
```

Execution tools should be added only after approval records and policy checks are shared with CLI and REST:

```text
hovel_confirm_action
hovel_start_run
hovel_start_service
hovel_stop_service
hovel_stream_run_events
```

The MCP adapter must not expose raw dangerous operations without the same validation, safety policy, and audit model used by CLI and REST.
