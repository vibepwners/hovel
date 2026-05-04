# Front Ends

Front ends are adapters over application services. They must share validation, planning, execution, structured logging rail subscriptions, scope guardrails, and audit behavior.

Hovel should have multiple first-class operator front ends: `cli` mode for an interactive prompt shell, one-shot chain-file execution for shell workflows, MCP for agentic and tooling workflows, and `tui` mode for a full-screen terminal interface. These surfaces may feel different, but they must attach to the same daemon and use the same application services.

The production entrypoint is the `hovel` mono-binary. Top-level subcommands select the front-end or daemon role:

```text
hovel cli ...
hovel throw <chain-file>
hovel daemon ...
hovel tui ...
```

General-purpose `hovel command ...` mode is not part of the product contract. The shell-facing product surface should be deliberately narrow: daemon management, help, and one-shot execution of a saved chain file.

## Terminology

These terms are normative:

1. `cli` mode is an interactive prompt shell. It takes over the terminal like a REPL, but it is not a full-screen TUI.
2. One-shot mode throws a saved chain file from the shell, prints output, and exits.
3. `tui` mode is the full-screen terminal UI.
4. `daemon` mode runs or inspects the engine role directly.

The old phrase "CLI command mode" should be avoided. Use `cli` for the interactive prompt shell and "one-shot chain-file execution" for shell throws.

## One-Shot Mode

One-shot mode is for scripts, automation, CI, demos, and cases where an operator wants to execute a durable chain definition without entering the interactive prompt.

One-shot rules:

1. Invoked as `hovel throw <chain-file>`.
2. Loads a configured chain YAML file and produces the same throw plan as interactive `throw`.
3. Displays the same final configuration review as interactive `confirm` and `throw`.
4. Requires the operator to type `yes` before execution unless `--now` is passed.
5. Records a confirmation record for both typed confirmations and `--now` bypasses.
6. Persists throw plans, confirmation records, events, artifacts, throw records, and final state.
7. Uses `--json` for structured output.
8. Uses `--no-color` for simple terminals and logs.
9. Does not rely on or mutate another client's active operation or chain selection.

Recommended shell surface:

```text
hovel
  throw <chain-file> [--now] [--workspace <workspace>] [--json] [--no-color]
  daemon
    serve
    status
```

## CLI Mode

`cli` mode is the first rich operator interface and should exist before the full TUI becomes complex. It starts an interactive prompt shell with command history, completions, contextual help, and styled output. It should use `go-prompt` for the prompt and completion loop and Lip Gloss for prompt, table, panel, status, and result styling.

CLI mode should be inspired by what operators like about Metasploit: fast discovery, a stable prompt, contextual commands, readable module options, jobs, sessions, and a workflow that lets an operator stay inside the tool while moving from discovery to planning to execution. It should not clone Metasploit command names or behavior wholesale; Hovel should have its own vocabulary around operations, chains, targets, providers, payloads, listeners, sessions, throws, structured events, and artifacts.

Requirements:

1. Human-readable output by default.
2. `--json` for structured output where useful.
3. `--no-color` for simple terminals.
4. `--verbose` and `--debug`.
5. `--workspace` selection.
6. Shell completion.
7. Module and service inspection.
8. Operation and chain selection, target setup, and throw execution.
9. Service lifecycle control.
10. Artifact, listener, and session listing.
11. Command history, contextual help, and a status-aware prompt.
12. Lip Gloss styling for tables, transcript logs, findings, throw status, and prompt output.
13. A shared theme package with the TUI.
14. go-prompt completion generated from the central command registry.
15. Managed daemon lifecycle: attach to an existing daemon if one is running; otherwise start a background daemon owned by the `cli` session and shut it down on exit.

Recommended top-level shape:

```text
hovel
  cli
```

Root role commands such as `hovel cli`, `hovel daemon`, and `hovel tui` remain explicit role selectors. Product docs should not present broad direct aliases such as `hovel op ...` as the durable shell contract.

Recommended prompt shape:

```text
h0v3l> control init --workspace .hovel
h0v3l> op use redteam-lab
h0v3l [redteam-lab]> chain create mock-exploit
h0v3l [redteam-lab/mock-exploit] > target add mock://target-1
h0v3l [redteam-lab/mock-exploit] > target add mock://target-2
h0v3l [redteam-lab/mock-exploit] > throw
h0v3l [redteam-lab/mock-exploit] > logs
```

Initial interactive commands:

```text
help
control init
control daemon status
op create
op use
op list
op inspect
chain create
chain use
chain rename
chain save
chain load
chain list
chain delete
add
validate
config set
config list
config interactive
inspect
logs
target add
target clear
target config set
target config list
throw
search
info
options
unset
plan
confirm
cancel
events
artifacts
job
session
listener
service
back
exit
```

The prompt should show workspace, active operation, and active chain context, but should only enter modal flows when the mode is visible in the prompt. When a chain is activated with `chain use <chain>` or created with `chain create <chain>`, the prompt includes the selected operation and chain as `h0v3l [<operation>/<chain>] >`; the chain segment should render in cyan. `chain config interactive` remains inside the active go-prompt session, changes the prompt into config-selection or config-value mode, and switches completions to current menu choices or type-aware values for the key being configured. Interactive actions should call application services through validated command invocations.

CLI mode has two discovery contexts:

1. Normal context, with no active chain: root completions focus on setup and navigation, including `control`, `op`, `module`, and chain lifecycle commands such as `chain create`, `chain use`, `chain list`, `chain rename`, and `chain delete`. Active-chain commands such as `chain add`, `chain config`, `chain validate`, `chain inspect`, and `chain logs` are hidden from completion until a chain is active.
2. Chain context, with an active chain: active-chain operations are promoted to root commands. `add <module>`, `config ...`, `validate`, `inspect`, `logs`, and `rename <name>` are CLI aliases over the canonical `chain ...` command handlers. Docs, help, and examples should prefer `chain`.

The canonical interactive execution loop is:

1. Create or enter an operation with `op create <operation>` or `op use <operation>`.
2. Create and immediately enter a chain with `chain create <chain>`, or enter an existing chain with `chain use <chain>`.
3. Add chain steps with `add <module>`.
4. Add one or more targets owned by the active chain with `target add <target>`.
5. Configure and validate the chain with `config ...` and `validate`.
6. Optionally pre-confirm with `confirm`, or rerun an explicit typed review with `review`.
7. Execute the active chain against its owned targets with `throw`.
8. Persist the chain definition with `chain save <file>` when it should be shared or used from one-shot mode.

Targets belong to chains. `target add` and `target clear` operate on the caller's active chain only, and interactive `throw` uses that active chain and that chain's target set. A targetless chain template can be reused and configured later; a configured chain includes target assignments and per-target config and is ready to review and throw.

`review` and `throw` share the same review rendering. `confirm` records a pre-confirmation and stops. `review` always displays the current plan, requires the operator to type `yes`, records or refreshes the confirmation, and stops. `throw` starts execution if the current plan hash already has a matching confirmation; otherwise it shows the review, asks the operator to type `yes`, records the confirmation, and starts execution. Confirmations do not expire by time. They become invalid when the reviewed plan hash changes. `throw --now` skips the prompt but records the bypass in the confirmation record.

Chains own their operation-scoped log topic. A chain topic is addressable as `operation/<operation>/chain/<chain>/logs`, and `chain logs` shows only the logs for the active chain. In multi-client sessions, a `cli`, `tui`, or MCP client attached to an operation and chain subscribes to that chain topic; clients attached to the same operation and chain see the same logs, while clients attached to other chains do not see them by default.

Operational setup commands such as workspace initialization and daemon inspection must be grouped under `control` in the registry exposed to `cli`. The old top-level `run` command should not be the durable operator contract; `throw` is the execution verb for the selected chain and target set.

The visual goal is "1337 af" but maintainable: high contrast, sharp prompt styling, clear context, readable tables, severe/status colors, and deterministic render tests. Styling should be centralized in the shared terminal theme package rather than scattered across command handlers.

## TUI

The TUI is the visual identity of the project, but it should remain a client over `hoveld`.

Requirements:

1. Attaches to `hoveld`.
2. Consumes the same structured logging rail as one-shot execution, `cli`, API, and MCP.
3. Works over SSH.
4. Degrades gracefully on limited terminals.
5. Supports multiple clients attached to the same engine.
6. Uses Bubble Tea, Bubbles, and Lip Gloss.
7. Shares theme tokens with `cli` mode.
8. Presents the same plans, confirmations, throws, sessions, listeners, artifacts, and structured events as `cli`, one-shot execution, and MCP.
9. Managed daemon lifecycle: attach to an existing daemon if one is running; otherwise start a background daemon owned by the `tui` session and shut it down on exit.

Initial screens:

```text
Dashboard
Module Browser
Service Browser
Throw Planner
Live Throw View
Target Matrix
Provider Browser
Payload Browser
Listener Panel
Session Panel
Artifact Viewer
Log Stream
Settings / Theme Selector
```

Live throw view should include:

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

Visual direction:

1. High-contrast operator console, not a generic dashboard.
2. Dense but legible layouts.
3. Lip Gloss borders, tables, tabs, status bars, and severity styling.
4. Built-in themes with a 31337 aesthetic, while preserving accessibility and `--no-color` or low-color fallbacks.
5. Keyboard-first navigation with clear focus states.
6. Motion only where it clarifies live state.

## Shared Command Registry

Hovel must have a central command registry that is the single source of truth for interactive operator commands and shared action metadata.

Registering an operator action once should make it available to:

1. `cli` mode as an interactive command with prompt completion and contextual help.
2. TUI action palettes and key-bound actions where applicable.
3. One-shot chain-file execution only where the action belongs to the saved-file execution workflow.

The registry owns:

1. Command path and aliases.
2. Short and long help text.
3. Positional arguments.
4. Flags, switches, and options.
5. Required and optional values.
6. Value parsers and validation.
7. Completion providers.
8. Output modes, including human output and JSON.
9. Handler binding to application services or daemon RPC calls.
10. Safety and confirmation metadata.

Command handlers must not parse argv directly. They receive a validated command invocation built from registry metadata. CLI mode should adapt registry metadata into go-prompt suggestions, contextual help, and validated invocations. One-shot mode should use the shared planning, confirmation, and throw services rather than reimplementing a parallel shell-only path.

Golden tests should verify CLI help and completion. Contract tests should verify that one-shot chain-file execution and interactive `throw` produce equivalent plans, review surfaces, confirmation records, events, artifacts, throw records, and final state for the same chain file.

## REST/OpenAPI

The REST API should be generated from Go types where possible.

REST should not block the first useful command/CLI and event-stream loop. It may ship in the first alpha if needed for MCP or external automation, but it must remain an adapter over application services.

Primary uses:

1. TUI testing.
2. MCP adapter.
3. External automation.
4. Future web UI.
5. Chain-file execution from scripts.
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
/api/v1/throws
/api/v1/artifacts
/api/v1/events
```

Event streaming may use Server-Sent Events or WebSockets.

## MCP Adapter

MCP is another front end over the same application services.

MCP has eventual operator parity: anything a human can do through `cli`, one-shot execution, TUI, or API should be representable through MCP, subject to the same guardrail checks, confirmations, planning output, and audit trail. The implementation should ship inspection and planning tools before execution tools unless the shared confirmation and audit path is already complete.

MCP should be treated as a peer front end, not as a privileged back door. It may expose workflows optimized for agents, but those workflows must produce the same plans, guardrail results, confirmations, structured events, artifacts, and throw records that a CLI or TUI operator would see.

Initial inspection and planning tools:

```text
hovel_list_modules
hovel_inspect_module
hovel_list_services
hovel_get_service_status
hovel_plan_throw
hovel_check_guardrails
hovel_get_throw_status
hovel_list_artifacts
hovel_get_artifact
hovel_list_targets
hovel_resolve_payload
hovel_list_listeners
hovel_list_sessions
```

Execution tools should be added only after confirmation records and guardrail checks are shared with CLI and REST:

```text
hovel_confirm_action
hovel_start_throw
hovel_start_service
hovel_stop_service
hovel_stream_throw_events
```

The MCP adapter must not expose raw dangerous operations without the same validation, scope guardrails, and audit model used by CLI and REST.
