# Front Ends

Front ends are adapters over application services. They must share validation, planning, execution, event streaming, safety policy, and audit behavior.

Hovel should have multiple first-class operator front ends: MCP for agentic and tooling workflows, `command` mode for normal shell invocations, `cli` mode for an interactive prompt shell, and `tui` mode for a full-screen terminal interface. These surfaces may feel different, but they must attach to the same daemon and use the same application services.

The production entrypoint is the `hovel` mono-binary. Top-level subcommands select the front-end or daemon role:

```text
hovel command ...
hovel cli ...
hovel daemon ...
hovel tui ...
```

For operator ergonomics, the mono-binary also exposes registry-backed direct command aliases such as `hovel chain ...`, `hovel modules ...`, `hovel targets ...`, and `hovel throw ...`. These aliases are part of the shell-facing product surface, but they must be generated from or dispatched through the same central command registry as `hovel command ...`.

## Terminology

These terms are normative:

1. `command` mode is the normal shell command line. It runs one command, prints output, and exits.
2. `cli` mode is an interactive prompt shell. It takes over the terminal like a REPL, but it is not a full-screen TUI.
3. `tui` mode is the full-screen terminal UI.
4. `daemon` mode runs or inspects the engine role directly.

The old phrase "CLI command mode" should be avoided. Use `command` for non-interactive shell invocations and `cli` for the interactive prompt shell.

## Command Mode

`command` mode is for scripts, automation, CI, quick inspection, and normal shell usage. It should include every operation that makes sense outside the interactive `cli` or full-screen `tui` environments.

Command mode rules:

1. Invoked as `hovel command ...` or an equivalent registry-backed direct alias such as `hovel throw ...`.
2. Runs one command and exits.
3. Uses shared command definitions from the central command registry.
4. Uses the same argument, switch, option, help, validation, completion metadata, and handlers as `cli` mode.
5. Uses `--json` for structured automation.
6. Uses `--no-color` for simple terminals and logs.
7. Requires an already-running daemon for daemon-backed operator commands.
8. Provides daemon-management commands such as status and explicit daemon startup where appropriate.
9. Does not silently spawn a managed daemon for ordinary commands. Automatic managed-daemon startup is reserved for `cli` and `tui`.

Recommended command tree:

```text
hovel
  command
    control
      init
      daemon
        status
        stop
    chain
      create <chain>
      use <chain-or-module>
      rename <chain> <name>
      add <module-id>
      remove <step-id>
      move <step-id>
      validate
      config
        set <key> <value>
        unset <key>
        list
        interactive
      list
      inspect
      delete <chain>
      logs
      plan
    targets
      add <target>
      clear
      config
        set <target> <key> <value>
        unset <target> <key>
        list <target>
      list
      inspect
      import
    throw
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
    runs
      list
      inspect <run>
      logs <run>
      artifacts <run>
```

## CLI Mode

`cli` mode is the first rich operator interface and should exist before the full TUI becomes complex. It starts an interactive prompt shell with command history, completions, contextual help, and styled output. It should use `go-prompt` for the prompt and completion loop and Lip Gloss for prompt, table, panel, status, and result styling.

CLI mode should be inspired by what operators like about Metasploit: fast discovery, a stable prompt, contextual commands, readable module options, jobs, sessions, and a workflow that lets an operator stay inside the tool while moving from discovery to planning to execution. It should not clone Metasploit command names or behavior wholesale; Hovel should have its own vocabulary around chains, targets, providers, payloads, listeners, sessions, approvals, throws, events, and artifacts.

Requirements:

1. Human-readable output by default.
2. `--json` for structured automation.
3. `--no-color` for simple terminals.
4. `--verbose` and `--debug`.
5. `--workspace` selection.
6. Shell completion.
7. Module and service inspection.
8. Chain selection, target setup, and throw execution.
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

Direct command aliases are durable only when they remain registry-backed and behaviorally equivalent to the corresponding `hovel command ...` path. Root role commands such as `hovel cli`, `hovel daemon`, and `hovel tui` remain explicit role selectors.

Recommended prompt shape:

```text
h0v3l> control init --workspace .hovel
h0v3l> chain create mock-exploit
h0v3l (mock-exploit) > targets add mock://target-1
h0v3l (mock-exploit) > targets add mock://target-2
h0v3l (mock-exploit) > throw
h0v3l (mock-exploit) > logs
```

Initial interactive commands:

```text
help
control init
control daemon status
chain create
chain use
chain rename
chain list
chain delete
add
validate
config set
config list
config interactive
inspect
logs
targets add
targets clear
targets config set
targets config list
throw
search
info
options
unset
plan
approve
cancel
events
artifacts
jobs
sessions
listeners
services
back
exit
```

The prompt should show workspace and active chain context, but should only enter modal flows when the mode is visible in the prompt. When a chain is activated with `chain use <chain>` or created with `chain create <chain>`, the prompt includes the selected chain as `h0v3l (<chain>) >`; the chain segment should render in cyan. `chain config interactive` remains inside the active go-prompt session, changes the prompt into config-selection or config-value mode, and switches completions to current menu choices or type-aware values for the key being configured. Every interactive action should have an equivalent `command` mode invocation or application service call.

CLI mode has two discovery contexts:

1. Normal context, with no active chain: root completions focus on setup and navigation, including `control`, `modules`, and chain lifecycle commands such as `chain create`, `chain use`, `chain list`, `chain rename`, and `chain delete`. Active-chain commands such as `chain add`, `chain config`, `chain validate`, `chain inspect`, and `chain logs` are hidden from completion until a chain is active.
2. Chain context, with an active chain: active-chain operations are promoted to root commands. `add <module>`, `config ...`, `validate`, `inspect`, `logs`, and `rename <name>` are CLI aliases over the canonical `chain ...` command handlers. The canonical `chain ...` forms remain valid for command mode and for operators who prefer them.

The canonical interactive execution loop is:

1. Create and immediately enter a chain with `chain create <chain>`, or enter an existing chain with `chain use <chain>`.
2. Add chain steps with `add <module>`.
3. Add one or more targets owned by the active chain with `targets add <target>`.
4. Configure and validate the chain with `config ...` and `validate`.
5. Execute the active chain against its owned targets with `throw`.

Targets belong to chains. `targets add` and `targets clear` operate on the active chain only, and `throw` without explicit options uses the active chain and that chain's target set.

Chains own their log topic. A chain topic is addressable as `chain/<chain>/logs`, and `chain logs` shows only the logs for the active chain. In multi-client sessions, a `cli`, `tui`, or MCP client attached to a chain subscribes to that chain topic; clients attached to the same chain see the same logs, while clients attached to other chains do not see them by default.

Operational setup commands such as workspace initialization and daemon inspection must be grouped under `control` in the registry exposed to `cli` and `command`. The old top-level `run` command should not be the durable operator contract; `throw` is the execution verb for the selected chain and target set.

The visual goal is "1337 af" but maintainable: high contrast, sharp prompt styling, clear context, readable tables, severe/status colors, and deterministic render tests. Styling should be centralized in the shared terminal theme package rather than scattered across command handlers.

## TUI

The TUI is the visual identity of the project, but it should remain a client over `hoveld`.

Requirements:

1. Attaches to `hoveld`.
2. Consumes the same event stream as `command`, `cli`, API, and MCP.
3. Works over SSH.
4. Degrades gracefully on limited terminals.
5. Supports multiple clients attached to the same engine.
6. Uses Bubble Tea, Bubbles, and Lip Gloss.
7. Shares theme tokens with `cli` mode.
8. Presents the same plans, approvals, runs, sessions, listeners, artifacts, and events as `cli`, `command`, and MCP.
9. Managed daemon lifecycle: attach to an existing daemon if one is running; otherwise start a background daemon owned by the `tui` session and shut it down on exit.

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

Visual direction:

1. High-contrast operator console, not a generic dashboard.
2. Dense but legible layouts.
3. Lip Gloss borders, tables, tabs, status bars, and severity styling.
4. Built-in themes with a 31337 aesthetic, while preserving accessibility and `--no-color` or low-color fallbacks.
5. Keyboard-first navigation with clear focus states.
6. Motion only where it clarifies live state.

## Shared Command Registry

Hovel must have a central command registry that is the single source of truth for operator commands.

Registering a command once should make it available to both:

1. `command` mode as a normal shell invocation.
2. `cli` mode as an interactive command with prompt completion and contextual help.

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
10. Safety and approval metadata.

Command handlers must not parse argv directly. They receive a validated command invocation built from registry metadata. Command mode should adapt registry metadata into argparse parsers. CLI mode should adapt the same metadata into go-prompt suggestions, contextual help, and validated invocations.

Golden tests should verify that a command registered in the central registry appears in both command mode help and CLI mode completion/help. Contract tests should verify that arguments, switches, default values, required fields, and validation errors are identical across both modes.

## REST/OpenAPI

The REST API should be generated from Go types where possible.

REST should not block the first useful command/CLI and event-stream loop. It may ship in the first alpha if needed for MCP or external automation, but it must remain an adapter over application services.

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

MCP has eventual operator parity: anything a human can do through `command`, `cli`, TUI, or API should be representable through MCP, subject to the same policy checks, confirmations, planning output, and audit trail. The implementation should ship inspection and planning tools before execution tools unless the shared approval and audit path is already complete.

MCP should be treated as a peer front end, not as a privileged back door. It may expose workflows optimized for agents, but those workflows must produce the same plans, policy decisions, approvals, events, and artifacts that a CLI or TUI operator would see.

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
