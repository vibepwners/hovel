# Operator Workflows

The operation is the root object of operator work. A chain is the throw path inside that operation: it is the shared workspace where clients collaborate, configure targets, add modules, validate readiness, and throw.

An entity is any actor connected to `hoveld`: a human operator in `cli`, a TUI session, an MCP client, an AI agent, or another authorized user. Multiple entities may attach to the same operation. Each attachment has its own active chain, while chain state, target sets, configuration, steps, and logs are daemon-owned shared state.

## Operation Collaboration

Every chain owns an operation-scoped log topic:

```text
operation/<operation>/chain/<chain>/logs
```

Every entity attached to the same operation and chain subscribes to the same topic. A log statement for a chain change must be visible to every connected CLI, TUI, and MCP client attached to that chain, but clients working other chains should not receive it by default.

Client-local attachment state:

1. Attached operation.
2. Active chain within that operation.
3. Current prompt mode.
4. Current log cursor.

Daemon-owned shared state:

1. Operation records.
2. Chain records, steps, targets, and config.
3. Throw records.
4. Logs, evidence, artifacts, and findings.

Required chain log events:

1. Chain created, renamed, inspected, deleted, or selected.
2. Entity attached or detached from an operation or chain.
3. Module added, removed, reordered, or configured.
4. Target added, removed, updated, or configured.
5. Chain configuration set or unset.
6. Validation started, completed, or failed.
7. Throw planned, started, progressed, completed, or failed.
8. Survey facts discovered.
9. Payload provider output selected.
10. Exploit step started, completed, or failed.
11. Finding, artifact, evidence, or throw result emitted.

The CLI should render this as a live transcript. The TUI should render the same topic in a log panel. MCP should expose the same stream through a tool or resource optimized for agents.

## Throw Transcript

A throw should look like a live operator transcript, not a JSON blob. The transcript is a terminal rendering of structured log events; JSON, RPC, MCP, files, the CLI, and the eventual TUI must consume the same typed event model rather than parsing terminal text.

Each log event should carry stable structure:

```text
id, time, topic, kind, level, source, message
chain_id, chain_name, run_id, target, module_id
elapsed_seconds
fields
attributes
```

For throw logs, `elapsed_seconds` is seconds since the throw started. The terminal renderer displays it inside the label as fixed-width `000.00` seconds, highlighted separately from the purple label background.

Minimum CLI render:

```text
HOVEL//THROW op/redteam-lab chain/ssh-memory

operation    redteam-lab
chain        ssh-memory
entities     operator:will, agent:planner
targets      3
steps        survey:2 exploit:1 payload_provider:1
status       validating

┃ :: validate 000.01 checking chain configuration
┃ ++ validate 000.02 global config complete
┃ ## validate 000.03 target router-01 missing ssh.username
┃ :: chain    000.04 added module mock-survey as step step-1
┃ :: target   000.05 added mock://router-01
┃ >> stage    000.06 throw started
┃ :: survey   000.07 router-01 os=linux arch=x86_64
┃ $$ payload  000.08 selected payload mock-payload-x86_64-linux
┃ ++ exploit  000.09 router-01 completed mocked exploit flow
┃ ++ throw    000.10 completed 1/1 target(s)
```

The eventual TUI live throw view should split the same state into:

1. Chain header.
2. Attached entity presence.
3. Step timeline.
4. Target matrix.
5. Configuration validation panel.
6. Chain log stream.
7. Findings, artifacts, and evidence panel.

## Module Database

Hovel needs a daemon-owned module database. The initial module types are:

```text
survey
exploit
payload_provider
```

The type set must be expandable later without changing the chain model.

A module database record contains:

1. Module ID.
2. Name.
3. Module type.
4. Version.
5. Summary and description.
6. Tags.
7. Runtime kind.
8. Author or source.
9. Required and optional chain configuration schema.
10. Required and optional target configuration schema.
11. Output schema.
12. Safety labels.
13. Enabled or disabled state.

Initial commands:

```text
module list
module list --type survey
module inspect <module-id>
module search <query>
```

## Chain Steps

Chains contain ordered steps. A step usually references a module from the module database.

Initial CLI commands:

```text
chain add <module-id>
chain remove <step-id>
chain move <step-id> --before <step-id>
chain inspect
```

Adding a module logs to the chain topic. Removing or reordering a step also logs to the chain topic. Step IDs must be stable so validation errors, logs, and UI selection can point at a specific item.

## Configuration

Configuration is a typed key-value dictionary.

Scopes:

```text
chain config       applies globally to the active chain
target config      applies to one target within the active chain
```

Every survey, exploit, payload provider, or future chain item can declare:

1. Required chain configuration keys.
2. Optional chain configuration keys.
3. Required per-target configuration keys.
4. Optional per-target configuration keys.

Built-in value types:

```text
string
secret
bool
int
float
enum
duration
url
host
port
cidr
path
list<string>
map<string,string>
```

Each key definition supports:

1. Name.
2. Type.
3. Required flag.
4. Default.
5. Description.
6. Allowed values for enums.
7. Validation rule.
8. Secret redaction.
9. Scope: `chain` or `target`.

Initial commands:

```text
config set <key> <value>
config unset <key>
config list
config interactive

target config set <target> <key> <value>
target config unset <target> <key>
target config list <target>
```

The CLI and TUI must render secrets as present or missing without revealing their values.

`config interactive` is a guided CLI workflow implemented inside the existing go-prompt loop and backed by the canonical `chain config interactive` command. It first renders the current chain and target configuration as a numbered menu, then changes the prompt into config-selection mode with completions for editable items, continue, and cancel. When the operator continues, Hovel changes the prompt into config-value mode, offers type-aware completions where possible, walks the remaining required chain and per-target keys, validates each typed value as it is entered, and repeats until all required configuration is set or an unfixable validation issue remains.

## Validation

`chain validate` checks whether the active chain is ready to throw.

Validation must evaluate:

1. Active chain exists.
2. Chain has at least one step.
3. Chain has at least one target.
4. Every step references an enabled module in the module database.
5. Required chain configuration keys are set.
6. Required target configuration keys are set for every target.
7. Values parse into their declared types.
8. Enum values are valid.
9. Secrets are present but redacted.
10. Payload provider requirements are satisfiable.
11. Every chain step has a stable ID.

Validation output must be human-first and scriptable with `--json`.

## Mock Modules

The mocked stage should provide enough modules to exercise every UI path without executing real target behavior.

Required example modules:

1. `mock-survey`
   - Type: `survey`.
   - Lives in its own Python project under `examples/python/mock_survey`.
   - Requires target config: `target.host: host`, `target.port: port`.
   - Emits facts and a module log.
   - Tests per-target config, fact output, SDK schema declaration, and stdio JSON-RPC launch.
2. `mock-exploit`
   - Type: `exploit`.
   - Lives in its own Python project under `examples/python/mock_exploit`.
   - Requires chain config: `operator.confirmed_lab: bool`.
   - Requires target config: `target.host: host`, `target.port: port`.
   - Emits an example finding, artifact, result, and module log.
   - Tests throw transcript, final result rendering, SDK schema declaration, and stdio JSON-RPC launch.
   - Tests error rendering and failed throw states.
