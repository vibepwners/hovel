# Hovel context

Hovel is a local, daemon-backed operator platform for authorized red-team
emulation, controlled lab work, defensive validation, and reproducible security
workflows. It coordinates modules, targets, chains, payloads, sessions,
artifacts, and structured events without putting exploit implementation inside
the core.

This file records the product language, architectural boundaries, and
cross-cutting invariants that should remain stable across code, daemon APIs,
SDKs, module packages, commands, and documentation. It is broader than a
glossary, but it is not an exhaustive API reference.

## How to read this file

Statements use these maturity labels when the distinction matters:

- **Implemented** describes behavior present in the current source and wired
  gates.
- **Direction** describes an agreed product or architecture boundary whose full
  runtime is not present yet.
- **Proposed** describes work accepted for planning but not implementation.

Do not describe a direction or proposal as shipped behavior. The source,
schemas, Task graph, machine-readable OpenAPI document, and executable tests
are the authority for current implementation. ADRs explain why durable
decisions were made. The Book explains generic behavior; Modules pages explain
concrete module implementations.

Current decision records are:

- [`ADR-0001`](docs/adr/0001-use-mesh-for-node-operations.md) for Mesh
  terminology and daemon/provider ownership;
- [`ADR-0002`](docs/adr/0002-use-workspace-pki-for-certificate-management.md)
  for the workspace PKI architecture.

### Reading paths

This is a reference, not a tutorial that must be read from top to bottom. Start
with the path that matches the work:

| Reader or task | Start here |
| --- | --- |
| New contributor | Product boundaries, invariants, ubiquitous language, and system architecture. |
| Module or provider author | Module plugin system, package model, SDK model, and relevant workflow. |
| Mesh provider author | Mesh language, Mesh lifecycle, and the Mesh ADR. |
| CLI, API, or web client author | Daemon contract, command registry, operator workflows, and external interfaces. |
| Core maintainer | Aggregate ownership, architecture, persistence, safety, and change checklist. |
| PKI implementer or reviewer | Workspace PKI and credential delivery, then ADR-0002 and the detailed plan. |
| Build or docs maintainer | Repository/build architecture, release model, and documentation architecture. |

### One-minute model

```text
operator or external client
          |
          v
CLI / MCP / daemon API adapters
          |
          v
application use cases -----> durable workspace state and events
          |
          v
module/provider process ----> authorized target, payload, service, or Mesh
```

The daemon owns durable workflow state and audit. Application services own
policy and orchestration. Adapters present the same use cases to different
clients. Modules and providers own target-specific behavior. Plans and exact
confirmations sit between operator intent and mutation.

## Product boundaries

Hovel is:

- an operator workflow engine with a durable local daemon;
- a host for independently packaged red-team modules;
- a planner and thrower with review, confirmation, guardrails, and audit;
- a broker for typed module results, capabilities, artifacts, installed
  payload records, and live sessions;
- a common control surface for human and agent front ends;
- a framework for simple modules and advanced provider-owned Meshes.

Hovel is not:

- a general-purpose remote administration or automation framework;
- a replacement for every exploit, payload builder, implant, or C2 runtime;
- a monolithic C2, tunnel, or transport implementation;
- a reporting/evidence product that tries to own an entire assessment report;
- a proof that third-party modules or package scripts are safe;
- a reason for adapters to bypass application services;
- a reason to parse terminal output as machine state.

The core should know how to plan, validate, invoke, track, and audit a
capability. The module or provider should know how that capability works on a
specific target, protocol, operating system, payload, or implant.

## Non-negotiable invariants

1. A throw cannot start without a persisted plan.
2. A throw cannot start without a recorded confirmation for the exact plan.
3. `--now` skips the typed prompt, not planning, guardrails, persistence, or
   audit; the confirmation records that the bypass was requested.
4. Modules tagged `dangerous` cannot throw without `--allow-dangerous` or the
   equivalent explicit workspace policy.
5. Front ends call application services or the stable daemon contract. They do
   not reach through adapters or mutate workspace storage directly.
6. Module and provider metadata discovery is deterministic, offline, and free
   of target contact or other side effects.
7. Installed payload state comes only from explicit typed provider/module
   descriptors or explicit operator bookkeeping, never from log text or an
   artifact filename.
8. Artifact bytes are materialized or hash-tracked; large bytes do not live in
   SQLite metadata rows.
9. Structured events are the machine-readable observability rail. Terminal
   text is a rendering of state, not the source of truth.
10. Operator-controlled configuration is not silently dropped, rewritten, or
    redacted. A feature that owns secret material may define a separate,
    explicit secret-resolution/export contract.
11. Third-party module installation is a code-trust decision. Hovel records and
    supervises it but does not claim arbitrary code is safe.
12. Build, test, lint, format, docs, demos, and release actions are invoked
    through Task.

## Ubiquitous language

### Workspace

A **Workspace** is the local persistence and process-ownership boundary. It
contains operation state, throw plans and confirmations, throw records,
artifacts, structured events, installed payload inventory, module installs,
logs, and provider-owned files.

One active daemon owns a workspace at a time. A workspace lock prevents two
daemons from owning the same database. Workspace identity is not an operation
or target identity.

### Operation

An **Operation** is the durable top-level operator work context. It owns:

- chains;
- target inventory and per-target configuration;
- target sets/groups;
- throws, artifacts, findings, and event topics;
- entity presence and optional launch-key approval state.

`op` is the preferred command spelling. An attached client works in one
operation at a time, but changing an attachment does not move another client.

### Client attachment

A **Client Attachment** is one client's view of daemon-owned state. The client
may be the CLI, MCP adapter, one-shot command, future TUI, or an external API
integration. The attachment owns transient selection such as the active
operation and active chain. Shared operation and chain resources remain
daemon-owned.

_Avoid_: Treating active chain selection as global workspace state.

### Target

A **Target** is something the operator is authorized to assess. In the current
operator session it is represented by a stable target string plus typed module
configuration. The richer product model allows names, addresses, ports, labels,
facts, and ownership metadata.

Targets belong to an operation. A chain binds operation targets; it does not
copy them. Target configuration follows the target across chains. A target set
or target group is a named selection over the same records, not another target
store.

### Fact

A **Fact** is a typed, source-attributed observation about a target. The richer
fact inventory remains direction; modules currently return observations through
outputs, findings, evidence, and capabilities.

_Avoid_: Treating arbitrary terminal prose as a fact.

### Module

A **Module** is a typed, user-facing unit of bounded functionality executed as
a separate process. Implemented module types are:

- `survey`;
- `exploit`;
- `payload_provider`.

Mesh and step behavior are optional module capabilities, not additional module
types. A reusable sequence of modules is a Chain, not a composition module.

### Service

A **Service** is a long-lived or reusable capability with managed lifecycle.
Service descriptor value objects are implemented. A general service discovery,
launch, health, reload, and stop runtime is direction.

Examples include listening posts, session brokers, credential brokers, artifact
servers, callback listeners, and inventory synchronization.

```text
Module: run this bounded operation.
Service: keep this capability alive and manage its lifecycle.
```

_Avoid_: Claiming that module-backed provider behavior proves the general
service runtime exists.

### Provider

A **Provider** supplies typed resources or operations to modules, chains, or
services without requiring consumers to know the implementation source.

Implemented provider behavior is module-backed:

- Go exposes the complete current payload-provider RPC surface;
- Go and Python expose generic `step.*` provider contracts;
- Go, Python, and Rust expose Mesh contracts;
- Go, Python, and Rust expose strongly typed optional `credential.describe`,
  `credential.runtime`, `credential.files`, `credential.encode`, and
  `credential.stamp` contracts;
- any base module may return explicit installed-payload descriptors.

`ArtifactProvider`, `PayloadProvider`, `FactProvider`, `CredentialProvider`,
`ListenerProvider`, `SessionProvider`, and `MeshProvider` are product roles, not
necessarily one giant interface. Provider capabilities should stay optional and
small.

_Avoid_: A universal provider interface full of unsupported methods.

### Chain

A **Chain** is an ordered workflow inside an operation. It owns stable step IDs,
chain configuration, target bindings, and a chain log topic.

Chain forms are:

- an interactive daemon-owned record;
- a reusable template shape;
- a configured YAML chain file suitable for review, sharing, and one-shot
  execution.

Current chain files use an intentionally small schema: ordered references,
string configuration maps, and target bindings/configuration. They do not
provide an embedded scripting language, loops, arbitrary expressions, or
dynamic graph mutation.

### Step

A **Step** is one stable item in a chain. `uses` selects a module package. An
optional `step` value selects a generic capability-step contract inside that
module.

The generic step lifecycle is:

```text
describe -> prepare -> confirm -> execute -> operate -> cleanup
```

`prepare` must be pure and local. It may validate and derive reviewable values;
it must not touch a target, start a listener, generate final payload bytes, or
create final credentials.

### Capability

A **Capability** is typed machine-consumable chain state produced by one step
and consumed by another. It has a stable ID, schema version, state, producer,
attributes, extensions, and transition history.

Implemented core capability names include:

```text
RemoteExecutionCapability
CredentialCapability
PayloadArtifact
PayloadInstance
TransportEndpoint
MeshNode
MeshRoute
MeshDestination
MeshBeacon
MeshTrigger
SessionRef
CleanupHandle
```

Requirements match concrete type, schema version, required attributes, and
allowed state. Hovel owns core schemas. Modules may use namespaced extension
attributes, but consumers must explicitly opt into those namespaces.

### Evidence, finding, and output

**Evidence** explains what happened during a capability step. A **Finding** is
a human/audit observation returned by a module. An **Output** is explicit
module-produced data. None is automatically a reusable capability.

Failed work may still return partial capabilities and evidence. For example, a
payload may be installed but unreachable; Hovel should preserve the installed
record and warning rather than flattening the whole state to "nothing happened."

### Plan

A **Plan** is the fully resolved, persisted intent reviewed before mutation. It
contains the exact chain, selected targets, configuration, module/step
references, relevant risk and policy data, and a stable hash.

Random or default values that affect execution should be resolved into the plan
once. Applying or re-reading a plan must not silently generate different intent.

### Confirmation

A **Confirmation** is an auditable approval of one exact plan hash. It records
at least time and client/entity identity. It does not expire only because time
passed; any plan-hash change invalidates it.

Optional launch-key policy requires all configured operation entities to
approve the same plan and policy flags.

### Throw

A **Throw** is a confirmed execution of a chain against its planned target
selection. It is the operator-level durable execution record.

_Avoid_: Starting a throw from a raw request or treating a `Run` as proof of
operator confirmation.

### Run

A **Run** is an execution unit beneath a throw, normally scoped to a module and
target or to one aggregate capability-step chain for a target. Runs carry
findings, artifacts, logs, sessions, installed payload descriptors, and agent
hints.

### Artifact

An **Artifact** is a file-like result produced by a throw, run, module, provider,
session, or service. Metadata includes provenance, media/kind, path, size when
known, and hash.

Examples include payloads, captures, transcripts, plans, generated commands,
raw responses, and logs. Small inline module artifacts are materialized into
the workspace artifact store. Large artifacts remain file-shaped.

### Payload

A **Payload** is a provider-described capability that can produce tagged bytes.
Hovel tracks metadata, generation inputs, hashes, artifacts, transport, and
capabilities; it does not need to understand or parse every payload format.

An available payload definition, a generated payload artifact, an installed
payload, and a live session are four different objects.

### Payload stamp

A **Payload Stamp** is Hovel's durable provenance handle for one generated
artifact set. It connects provider identity, payload metadata, target,
transport, generation inputs, hashes, and later installation records.

A stamp does not prove installation.

### Installed payload

An **Installed Payload** is a durable workspace record for a target-side
payload instance. It stores a short operator handle, stable internal identity,
provider/payload identity, target, transport, endpoint summary, state,
provenance, stamp/artifact references, and versioned provider-owned reconnect
or cleanup descriptors.

Implemented current states are:

```text
installed | connected | unreachable | removed
```

Listing reads last-known SQLite state and does not probe targets. Reconnect or
refresh may ask the current provider. A missing provider does not erase the
record. Repeated installs reconcile only with explicit instance/stamp identity;
similar host and port values are not sufficient proof.

### Session

A **Session** is a live or attachable connection produced by a module, payload,
provider, listener, or Mesh stream. It has a stable ID, source run/module,
target, state, transport, optional installed-payload reference, and explicit
capabilities.

The daemon brokers read, write, tail/history, typed session commands, and close.
A long-lived installed payload may create many sessions; the inventory record
answers "what is deployed," while a session answers "what is connected now."

### Listener

A **Listener** is the general product term for a managed endpoint that accepts
connections or rendezvous. The general listener-service/provider runtime is
direction. Do not use it as a synonym for a Mesh Listener or Mesh Bridge.

### Credential capability

A **Credential Capability** is chain state representing target-access material,
such as an account created during an assessment. It is remediation evidence and
may be intentionally visible in operator output. Its `sensitive` metadata
supports export and downstream handling; it does not silently redact operator
workflow data.

This differs from workspace PKI. A target-created `CredentialCapability` is
stored and displayed in plaintext by design so an operator can remediate it.
Workspace PKI owns authorities, immutable certificate generations, trust, and
private keys; private material is envelope-encrypted in SQLite under an
owner-only workspace master-key file and enters provider calls only through
explicit short-lived resolution. Never put workspace private keys in a
`CredentialCapability`, and never describe target-account evidence as a PKI
bundle.

### Cleanup handle

A **Cleanup Handle** is durable, typed, retriable cleanup intent. It identifies
the provider or step that owns removal and the versioned data required to try
again. Cleanup state and attempts are evented.

## Mesh language

### Mesh

A **Mesh** is a provider-owned node operations plane. It may be one node or a
deep tree/graph of controllers, relays, agents, stagers, and implants. It may
support topology, tasking, surveys, uploads, execution, arbitrary commands,
triggers, beacons, streams, datagrams, and provider-defined protocols.

_Avoid_: Using Transport, Tunnel, or C2 as the umbrella term. Those terms may
still be valid for a narrower transport, tunnel, or C2 service.

### Mesh Node

A **Mesh Node** is one operator-addressable participant in a Mesh, such as a
controller, target-side agent, relay, or managed implant.

_Avoid_: Peer or hop when stable node identity matters.

### Mesh Link

A **Mesh Link** is a communication edge between two Mesh Nodes.

### Mesh Route

A **Mesh Route** is an ordered path across Mesh Nodes and Mesh Links.

### Mesh Destination

A **Mesh Destination** is a host or service reachable through a Mesh Node or
Mesh Route but not itself a Mesh Node. This is the pivoted-tooling boundary:
the node/route identifies how traffic or work travels, while destination host,
optional port, and protocol identify what is reached.

_Avoid_: Overloading Target or Node when the pivot and reached system differ.

### Mesh Task

A **Mesh Task** is a requested node, route, or destination operation. Stable
task kinds include survey, upload, execute, upload-execute, command, load, and
stream setup. Providers may define more.

Task descriptors advertise target scopes, configuration schema, whether work is
read-only/destructive, and whether it opens a stream. Providers implement only
the surfaces they support. The SDK contract intentionally models every kind,
but the current direct daemon `RunMeshTask` route dispatches only `survey`.
Command, upload, execute, upload-execute, load, stream-setup, and
provider-defined kinds fail before provider invocation until that route is
bound to the persisted throw plan, confirmation, and dangerous-module policy.

### Mesh Bridge

A **Mesh Bridge** is a daemon-owned loopback socket adapter that connects an
ordinary local client to one provider-owned Mesh session flow.

Implemented bridge adapters support:

- TCP byte streams;
- UDP datagrams when the returned session advertises `datagram`.

Each UDP read/write preserves exactly one datagram, and one bridge accepts one
local peer association. ICMP, raw IP, and arbitrary provider protocols remain
Mesh task/session contracts unless Hovel adds an explicit raw/TUN/TAP-like local
adapter.

A bridge is not a Mesh Listener and does not make the provider own local socket
lifecycle. The loopback socket is a local-user trust boundary, not an
authentication mechanism. Closing a bridge closes its local endpoint first. If
provider-session cleanup fails, the daemon retains the operation/session
selector as a retryable cleanup handle; a successful retry removes the handle
and moves bookkeeping to `closed` without reopening the endpoint.

### Mesh Listener

A **Mesh Listener** is a provider-reported listening post that accepts Mesh Node
rendezvous or beacon traffic. It has stable provider-scoped identity,
deployment, management, protocol, capability, and lifecycle state.

A Mesh Listener may be:

- embedded with or separately deployed from the provider;
- provider-managed or externally managed;
- associated with many Mesh Nodes.

Started listener state must survive an individual module RPC process call.
`embedded` means deployment coupling, not that Hovel keeps the metadata call's
subprocess alive.

_Avoid_: `LP` in public contracts, Mesh Bridge, daemon listener, or Mesh Node.

### Beacon

A **Beacon** is a time-stamped Mesh Node liveness, rendezvous, or work/status
signal. It may reference the Mesh Listener that received it.

_Avoid_: Callback when repeated liveness/status is the intended meaning.

### Trigger

A **Trigger** is a provider-declared condition that can cause Mesh work or a
state transition. It may be scheduled, event-based, or provider-defined.

_Avoid_: Schedule when the condition is not time based.

### Mesh relationships

- A Mesh contains one or more Mesh Nodes.
- A Mesh Node may connect to other nodes through Mesh Links.
- A Mesh Route crosses one or more nodes and zero or more links.
- A Mesh Task targets a node, route, or destination.
- A Mesh Listener belongs to one provider-owned Mesh and may receive many
  nodes.
- Listener IDs are provider-scoped; daemon correlation uses provider module ID
  plus listener ID.
- A Beacon belongs to one node and may reference one listener.
- A Trigger belongs to a Mesh and may reference a node or listener.
- `TransportEndpoint` remains a narrower capability for byte movement.

## Aggregate and ownership map

```text
Workspace
  owns daemon identity and durable local stores
  owns Operations
    own Targets and Target Sets
    own Chains
      own ordered Steps and target bindings
    own Throws
      own planned/confirmed execution records
      correlate Runs, Artifacts, Events, Sessions, and Installed Payloads

Module Package
  owns package identity, launch entries, scripts, and files
Module Process
  owns implementation-specific target behavior
Daemon
  owns process lifecycle, planning, invocation, state, and audit

Mesh Provider Module
  owns Mesh topology and provider-specific operations
Daemon
  owns Mesh operation bookkeeping and optional local bridges

Payload Provider
  owns payload-specific generation/reconnect/cleanup semantics
Hovel Core
  owns artifact materialization, handles, inventory, and provenance
```

The provider owns opaque implementation data. Hovel owns stable IDs, validation,
operator presentation, lifecycle records, policy, and audit.

## System architecture

Hovel uses hexagonal layering with dependencies pointing inward:

```text
adapters -> app -> domain
infra    -> app -> domain
```

### Domain

`core/internal/domain` contains pure value objects and rules for workspace,
daemon, module, service, run, event, operator approval, and Mesh concepts.

Domain code:

- must not import CLI, TUI, MCP, HTTP/RPC, storage, process runtime, or concrete
  modules/services;
- constructs validated values through `New...` constructors;
- should make invalid states difficult to represent;
- defensively copies mutable maps and slices at boundaries.

### Application

`core/internal/app` owns use cases, orchestration, ports, and shared operator
behavior. Current areas include:

- command definitions and validated invocations;
- operator operations/chains/targets and attachment state;
- module catalog and contract validation;
- capability-step runtime;
- workspace and daemon services;
- run, payload, session, and Mesh orchestration;
- launch-key coordination;
- module package installation and resolution;
- structured operator logs and configuration.

Front ends call these services. Application code depends on ports rather than
SQLite, filesystem, JSON-RPC process, or terminal implementations.

### Adapters

`core/internal/adapters` translates external interaction into application use
cases. Implemented adapters include:

- interactive CLI and command-mode output;
- root role dispatch;
- daemon-local attachment and daemon HTTP/JSON RPC;
- MCP;
- descriptor/schema translation;
- filesystem and SQLite storage;
- terminal log and UI catalog rendering.

Huh or any future form library belongs here. UI validation must delegate to the
same domain/application constructors used by non-interactive callers.

### Infrastructure and runtimes

`core/internal/infra` owns daemon process/runtime mechanics.
`core/internal/moduleruntime/pythonrpc` owns module-process launch and the
language-neutral JSON-RPC runtime despite the historical package name.
`core/internal/protocol` owns framing helpers.

Infrastructure may implement application ports. It does not move policy out of
the application layer.

## Process and control topology

The release is one `hovel` mono-binary with multiple roles:

```text
hovel cli / hovel shell      interactive operator attachment
hovel <registry command>     one command
hovel run ...                daemon-backed selected-context command
hovel throw <chain-file>     one-shot planned throw
hovel daemon serve           explicit daemon role
hovel mcp                    agent/control adapter
hovel tui                    reserved; not implemented
```

The local daemon role is often called `hoveld` in prose and logs, but it is not
a separate production binary. It owns the workspace database, module process
lifecycle, plans, confirmations, throws, artifacts, events, installed payloads,
sessions, Mesh operations, and client attachment state. Mesh operation records
are currently an in-memory live-control ledger and are lost when the daemon
restarts; provider-owned listener and node state may outlive that ledger.

Managed local mode starts or attaches to the workspace daemon. A client that
starts an owned daemon shuts it down when its interactive session ends; a
client that attaches to a pre-existing daemon leaves it running. Production
commands should exercise the daemon boundary even when tests also use
in-process harnesses.

## Daemon contract

The implemented stable front-end boundary is HTTP POST with JSON request and
response bodies under `hovel.daemon.v1.DaemonService`. It is available over a
local Unix socket and explicit loopback TCP for integration. Future Windows
support should use a named pipe.

The transports have intentionally different authority. The owner-controlled
Unix socket is the privileged control plane. Loopback TCP exposes only an
explicit set of non-sensitive read projections and rejects every privileged
method with typed `permission-denied`; it is not a substitute for local-user
authentication. Sensitive Mesh topology, beacon, listener, and operation
bookkeeping reads and PKI inventory, assignment, trust, revocation, and
credential-execution reads are privileged despite being non-mutating. Request
actor identifiers provide audit attribution only and never grant transport
authority. A web, Elixir, REST, or remote control surface must use an
authenticated owner-side proxy rather than exposing loopback TCP directly.

The machine-readable contract is
`docs/site/spec/reference/daemon-rpc.openapi.json`. It is the single canonical
source; a Bazel action publishes the Astro static artifact at
`spec/reference/daemon-rpc.openapi.json` in the built site. Contract tests keep
method registration, OpenAPI, and human docs aligned. Current methods cover operator
state, plans/approvals, throws, module execution, payloads, sessions, artifacts,
logs/entities, Mesh operations, and workspace PKI lifecycle/control.

The daemon boundary is not uniformly writable. PKI initialization, authority,
certificate, revocation/CRL, assignment, trust-set, rollover, and bundle-export
use cases have mutation methods. Mesh listeners, tasks, streams, and bridges
also have mutation methods. Credential-stamp and credential-execution methods
are currently list/inspect only. Credential-aware Mesh requests accept
non-secret assignment selectors plus an approved credential context, but no
direct Mesh task request carries a persisted throw-plan/confirmation handle.
MCP registers no PKI or credential delivery tools today.

External web, Elixir, REST, or other clients consume this daemon contract or a
public control SDK. They do not import `core/internal` or speak private module
stdio RPC.

## Shared command registry

The application command registry owns paths, aliases, options, positionals,
help, validation, output modes, and handler bindings. CLI completions,
command-mode invocation, future palettes, and agent metadata project from the
same definitions where appropriate.

Handlers receive validated invocations. They do not reparse raw shell strings.
Interactive-only aliases or wizards may improve UX but must call the same use
cases as one-shot and API clients.

## Module plugin system

The module boundary is the Hovel plugin system. Production modules are not
linked into core. They are installed or linked as packages, launched as
separate processes, and driven through Content-Length-framed JSON-RPC 2.0 over
stdin/stdout.

Base lifecycle:

```text
handshake -> schema -> execute -> optional sessions -> shutdown
```

Optional extensions include:

```text
step.describe / step.prepare / step.execute / step.cleanup
payload-provider operations
mesh.describe / topology / beacons / listeners / tasks / streams
credential.describe / runtime / files / encode / stamp
```

Stdout belongs exclusively to framed RPC. Operator-visible logs use
`module/log`; session data uses session methods; stderr is process diagnostics.
Unknown methods return a JSON-RPC error rather than pretending success.

Metadata calls (`handshake`, `schema`, `step.describe`, `mesh.describe`,
`credential.describe`) must be fast, deterministic, offline, and side-effect
free. They must not contact a target, generate random prepared values, start
listeners, generate payloads, resolve or create credentials, open protected
files, or mutate files.

## Module package and distribution model

A module package is a trusted `.tgz` with required `hovel-module.yaml`. It may
contain multiple host-platform launch entries, native binaries, Python code,
vendored wheels, a bundled interpreter, scripts, docs, and vendor extensions.

Important rules:

- selectors describe the operator host, not the target;
- the most specific matching launch entry wins, and ties fail;
- extraction rejects traversal and escaping symlinks;
- install scripts use argv arrays, not shell command strings;
- packages and scripts run with operator authority and are a trust decision;
- installed state lives in `module-lock.yaml`, not merged into config;
- execution uses installed/linked packages and never auto-downloads a missing
  chain module;
- internet access occurs only for explicit URL/index/runtime install actions;
- daemon startup, catalog inspection, planning, and throwing remain offline.

Workspace installs beat global installs. Exact `name@version` is stable;
ambiguous resolution fails rather than guessing. Linked installs are for
development; release packages are immutable archives with hashes.

## In-repository proving grounds

In-tree implementations exercise contracts but do not become privileged core
paths:

- the Python/Go/Rust mock survey, exploit, and session triads prove base SDK
  parity with benign behavior;
- Squatter proves payload-provider generation, installation provenance,
  reconnect, typed payload/session commands, and cleanup boundaries;
- Picblobs proves replaceable payload generation, position-independent C,
  cross-platform toolchains, Cortex-M/Mbed OS compilation, and encrypted
  bidirectional fixture behavior.

Production execution should take the ordinary package/catalog/RPC path even for
an in-tree module. Tests may use dedicated harnesses but should not create a
hidden built-in module API.

## SDK model

Current module SDKs live outside core:

| Surface | Go | Python | Rust |
| --- | --- | --- | --- |
| Base module lifecycle | yes | yes | yes |
| Sessions | yes | yes | yes |
| Mesh | yes | yes | yes |
| Generic `step.*` | yes | yes | not yet |
| Complete payload-provider RPC | yes | not yet | not yet |

SDKs expose the same wire concepts using idiomatic language shapes. They should
not invent language-specific protocol semantics. Contract fixtures and daemon
integration tests prove parity.

The current SDKs are module/provider-side SDKs. A public daemon control SDK and
C support are proposed as part of PKI/control work; do not conflate those with
the existing stdio module SDK.

## Core operator workflows

### Workspace and daemon

1. Resolve effective workspace and layered config.
2. Find or start the matching daemon.
3. Verify daemon identity/config and health.
4. Attach one client entity/session.
5. Execute typed application use cases.
6. Close attachment; stop only a daemon owned by that session.

### Operation, chain, and targets

1. Create/select an operation.
2. Create/select a chain.
3. Add stable module/step references.
4. Add operation targets and configure them.
5. Bind targets or select a target set/group for the chain.
6. Validate required chain and target configuration.
7. Save/load a configured chain file when portability is needed.

Target sets may skip incompatible members with explicit reasons. An explicitly
selected target remains strict and blocks when incompatible.

### Plan, review, confirm, throw

1. Resolve modules, steps, target source, configuration, risk, and policy.
2. Persist the exact plan and hash.
3. Render the same review through every front end.
4. Record confirmation for that plan (`yes`, `confirm`, or audited `--now`).
5. Enforce dangerous-module and optional launch-key policy.
6. Start the throw from the confirmed plan.
7. Record runs, events, artifacts, sessions, installed payloads, errors, and
   final state.

### Capability-step execution

1. Resolve typed requirements against current capabilities.
2. Call pure `step.prepare`.
3. Execute only after plan confirmation.
4. Validate declared outputs and transitions.
5. Preserve diagnostic evidence separately.
6. Keep sessions/payload instances operable.
7. Execute retriable cleanup handles.

Freezing complete live contract/prepared-value snapshots at confirmation and
blocking drift are direction; do not claim that safeguard is complete until
the source and tests prove it.

### Payload lifecycle

```text
discover definition
  -> generate artifact set
  -> issue payload stamp
  -> materialize/hash artifacts
  -> install through module/provider
  -> accept explicit InstalledPayloadDescriptor
  -> persist inventory and state event
  -> connect/refresh/call typed actions
  -> cleanup or explicitly mark removed
```

Generation does not imply installation. Connection failure after installation
does not erase installed state. Cleanup execution and cleanup bookkeeping are
distinct operator actions.

### Session lifecycle

```text
open/register -> list -> attach/read/write/call -> background/detach -> close
```

The daemon owns session identity, broker state, history/transcript behavior,
and link to source run/installed payload. A provider owns protocol-specific
read/write or typed command semantics.

### Mesh lifecycle

1. Describe static optional capabilities without side effects.
2. List dynamic topology, listeners, beacons, and triggers separately.
3. Start/stop provider listeners idempotently with stable caller IDs.
4. Run read-only survey tasks directly; route execution-capable typed tasks
   through persisted planning and confirmation once that binding exists.
5. Open provider-owned streams for arbitrary protocols.
6. Optionally expose TCP/UDP through a daemon loopback Mesh Bridge.
7. Record daemon Mesh operations for external control and audit.

An ordinary module may use a Mesh simply by connecting to the local bridge
endpoint when that adapter fits. It does not need to understand the provider's
route tree.

## Structured event and logging rail

An Event is a versioned, append-only envelope with ID, type, level, message,
timestamp, topic, references, and small structured fields.

Event types are lowercase dot-separated segments. Hovel owns core namespaces;
modules use module namespaces. References correlate workspace, operation,
chain, throw, run, module, service, target, and session.

The Event Bus fans the same record to independent handlers:

- SQLite persistence;
- terminal rendering;
- in-memory test recording;
- future TUI, NDJSON, or remote streaming.

Corrections are new events. Adapters never scrape terminal labels to recover
state. Logs are structured events optimized for operator observability, not a
separate evidence database product.

## Persistence model

Workspace files include:

```text
workspace.json
workspace.db
module-lock.yaml
artifacts/
logs/
modules/
throws/
services/
secrets/pki-master-keys.json
```

SQLite currently persists:

- operator session state;
- throw plans;
- throw confirmations;
- throw records;
- artifact metadata;
- events;
- installed payload current state and transition events.
- PKI authorities, immutable certificate generations, generation counters,
  encrypted key envelopes, authenticated metadata tags, and PKI audit events;
- PKI assignments and trust sets;
- revocations, CRL generations, and CRL publication/reconciliation state;
- credential stamp plans/results and credential execution plans/results.

Migrations are contiguous, named, checksummed, and transactional. An unknown
version, name mismatch, checksum mismatch, or gap fails closed.

Artifact bytes and provider file state remain in workspace-owned paths. Store
interfaces return defensive copies and do not expose implementation rows as
domain objects.

## Configuration model

Hovel config is YAML with a versioned kind. Effective precedence is:

```text
built-in defaults
  < global config
  < workspace config
  < explicit --config
```

Maps merge, scalar values replace, and lists replace. A running daemon rejects
a client whose effective config does not match; config hot reload is not a v1
assumption.

Chain and target configuration are separate from Hovel runtime config. Module
requirements declare names, types, scope, defaults, allowed values, and
validation. Do not hide target behavior in arbitrary environment variables or
private files.

## Trust and safety model

### Authorized use

Use Hovel only on systems owned by or explicitly authorized for the operator.
Public examples prefer benign, local, non-destructive demonstrations while
still exercising real orchestration contracts.

### Caller trust

Human operators, CLI clients, MCP agents, future TUI/REST clients, and external
control applications use the same planning, guardrails, confirmations, and
audit. Safety does not come from giving agents a weaker hidden API.

Agent context and hints are optional. Module-authored hints are untrusted
context and never bypass policy.

### Code trust

Installed modules and scripts may execute arbitrary code as the operator.
Current isolation is process/runtime separation, not a security sandbox.
Container and remote isolation are future options.

Metadata safety and runtime safety are different: a side-effect-free descriptor
does not make later execution harmless.

### Scope and risk

Plans should surface targets, network reachability, external binds, file writes,
credential use, payload/listener behavior, cleanup, and risk labels. Modules
that may crash systems, write disk, create accounts, execute commands, install
payloads, bind listeners, or maintain access self-identify as dangerous.

### Configuration and secrets

Hovel must not silently redact or omit operator-controlled chain configuration;
operators need exact values for offensive workflow reproducibility. Logs and
normal errors still should not duplicate secrets gratuitously.

Feature-owned secrets are different. A PKI private key, package signing key, or
future credential-broker secret may use explicit policy, encrypted custody, and
audited export because the feature owns the secret lifecycle rather than merely
transporting operator configuration.

## Workspace PKI and credential delivery

The typed domain, built-in Go X.509 backend, local issuance, bundle v1,
hybrid-ML-KEM TLS policy, encrypted SQLite custody, authenticated generation
metadata, owner-only file master-key provider, versioned rewrap, typed audit,
daemon API, imperative commands, assignments and trust sets, renewal/rotation,
revocation/CRLs, and phase-aware authority rollover are implemented on the
current PKI branch. Credential delivery/stamping also has strict domain models,
descriptor and execution validation, non-secret durable bookkeeping, SQLite
persistence, Go/Python/Rust SDK contracts and dispatch, and provider runner
execution. Manifests/Huh/MCP, public control SDK publication, automatic
assignment-to-delivery orchestration, general non-Mesh consumption, and a
production external stamp initiation path remain incomplete. See
`docs/adr/0002-use-workspace-pki-for-certificate-management.md` and
`docs/plans/tls-certificate-management.md`.

The PKI model makes certificate/trust management a daemon-owned workspace
capability rather than a Mesh-only feature or CLI utility.

Stable terms:

- **Authority**: logical root or subordinate CA;
- **Certificate**: logical lineage across renew/rotate;
- **Certificate Generation**: immutable issued bytes and metadata;
- **Profile**: reusable defaults and constraints;
- **Template**: one fully resolved issuance intent;
- **Assignment**: logical consumer slot pointing to active/staged generations;
- **Credential Bundle**: versioned JSON-safe DER/key/chain/trust/CRL contract;
- **Crypto Backend**: selectable key/sign/certificate implementation;
- **Compatibility Target**: consumer library constraints such as Mbed TLS or
  wolfSSL, independent of issuer backend;
- **Key Establishment Policy**: the consumer's TLS negotiation requirement,
  such as classical-compatible, hybrid post-quantum preferred, or hybrid
  post-quantum required. It is independent of certificate signature strength;
- **Hybrid Post-Quantum TLS**: a classical plus ML-KEM key exchange that
  protects session secrets if either component remains secure. Hovel's Go 1.26
  target can require it, but ECDSA/RSA/Ed25519 certificate signatures remain
  classical until a compatible signature backend and consumer are selected;
- **Credential Stamp**: exact credential-generation provenance for an artifact
  or deployment.

Lifecycle terms are strict:

```text
renew    new certificate, existing key
rotate   new certificate, new key
revoke   invalidate one generation and publish revocation material
rollover staged authority/trust replacement with overlap
stamp    bind exact material generations and hashes to an artifact/deployment
```

PKI delivery follows the same optional-capability principle as Mesh. A provider
may implement none, runtime bundles, protected files, strict named slots, or
advanced typed stamping targets such as file offset, virtual address, symbol,
marker, pattern, or versioned provider-defined target. Unsupported capabilities
block only operations that require them.

Strict standard contracts are the seamless path. Advanced stamping binds input
artifact hash, address space, expected existing bytes/hash, bounds, material
projection, capability version, and output hash. Hovel never guesses an address
or records private replacement bytes in ordinary plans/events.

Execution contracts are secret-aware closed unions:

- resolved material is exactly bytes or a provider-scoped reference, consistent
  with its material form;
- credential artifact content is exactly inline data or an invocation-scoped
  protected path;
- stamp output is exactly an artifact or provider-owned deployment;
- runtime/file receipts contain only a matching request ID and optional
  non-secret provider reference/receipt digest;
- durable execution and stamp records keep descriptor, assignment, scope,
  projection, form, size, digest, target, and destination evidence, not private
  bytes, protected paths, or deployment receipts.

For a credential-bearing Mesh mutation, the external request carries only
typed assignment, slot, projection, and form selections plus an authenticated
request context with explicit credential-use approval. The daemon derives the
exact versioned provider target and allowed provider/listener/node consumers,
resolves active assignment material immediately before use, starts one module
process, revalidates that process's handshake and credential descriptor, sends
all `credential.runtime` hooks, and then invokes the consuming listener start,
task, or stream. Separate short-lived RPC calls cannot preserve in-memory
credentials. The first production selector path supports direct runtime DER
projections; protected files, provider encoding, stamping, and non-Mesh
consumption keep their separate contracts.

## External interfaces and future front ends

The daemon API is the stable external control boundary. A web or Elixir client
can initiate ordinary PKI lifecycle mutations and Mesh operations, select
assignment-bound runtime credentials for active Mesh mutations, and
list/inspect credential stamps and execution ledgers without importing module
SDK implementations or core internals. It cannot yet initiate protected-file,
provider-encoding, stamping, or general non-Mesh credential consumption.
Future control surfaces should add those use cases at the application/daemon
boundary rather than exposing module stdio RPC directly.

Public control clients and provider SDKs are different roles:

- a control client calls daemon use cases;
- a module/provider SDK implements stdio plugin contracts;
- an implant consumer reads a portable bundle or generated artifact;
- a privileged PKI crypto-backend SDK implements cryptographic operations.

Do not collapse these into one package with ambient authority.

## Repository and build architecture

The repository is sparse-checkout friendly:

| Path | Role |
| --- | --- |
| `core/` | Go mono-binary, domain/app/adapters/infra, schemas, core tooling. |
| `sdk/` | Go, Python, and Rust module/provider SDKs. |
| `modules/` | Examples, Squatter, Picblobs, packaging, and lab helpers. |
| `docs/` | Book, Modules pages, API docs, VHS demos, and docs tooling. |
| `repo-tools/` | Root dispatcher and repository-quality helpers. |

`Taskfile.yml` is the only supported build entry point. Contributors and agents
do not call Bazel, gofmt, uv, or Lefthook directly. If a needed operation has no
task, add or fix a task.

The root Task graph dispatches to:

- the self-contained `core/` Bazel workspace;
- the root integration workspace for SDKs, modules, Picblobs, and docs;
- host-service docs/demo actions only in explicit host tasks.

`task check` validates slices present in a sparse checkout. `task ci` requires a
full checkout and runs the remote-compatible repository-quality, core, SDK,
modules, Picblobs, and docs gates. Host VHS rendering and complete site staging
remain separate (`task docs:site`/`docs:ci`).

Build/test tools should be Bazel-managed and pinned when practical. Cached work
should have declared inputs/outputs. Do not add shell scripts to the build graph
when Starlark or repository Python tooling is appropriate. Host tools remain
acceptable only for genuine host boundaries such as Docker, Wine, tmux, ttyd,
Chrome, and ffmpeg.

Quality expectations include:

- Go formatting, golangci-lint, Gazelle, and build-time nilness analysis;
- build, unit, race, fuzz-smoke, and coverage ratchets;
- Python ruff, strict mypy, pydoclint, and pytest;
- Rust formatting, build, and tests;
- C formatting/static analysis/complexity and cross-platform Picblobs checks;
- SDK/module protocol fixtures and real daemon behavior tests;
- docs smoke/OpenAPI/demo verification;
- hermeticity, visibility, ownership, and BUILD/Starlark policy checks.

If Go files/imports change, run `task fmt` so Gazelle output is current. Add new
core test targets to `core/BUILD.bazel` suites. Before landing a full-checkout
change, run `task ci`.

## Release and installation model

The primary operator installation is the `hovel` PyPI package. Its
platform-specific wheel contains the matching Go mono-binary and a small Python
launcher; installation and first run do not download the executable. Native
binaries remain GitHub Release artifacts.

The Python module SDK ships separately as `hovel-sdk`. Go and Rust SDKs are
source/module artifacts. Hovel core and official SDK versions move in lockstep,
while module package versions remain independently owned by their packages.

The operator package contains no modules by default. Official and third-party
modules are separate `.tgz` assets and index entries with checksums. Release
workflows also publish module indexes/install sets, SDK distributions,
Picblobs distributions, and checksums through dedicated pipelines.

## Documentation architecture

The Pages site has distinct top-level sections:

- **Book**: generic product concepts, operator workflows, architecture,
  protocols, safety, and developer guides;
- **Modules**: concrete provider/module behavior and module-specific examples;
- **API Docs**: generated language SDK references;
- **Reports**: generated test evidence.

Explain a generic contract once in the Book. Module pages show only concrete
wiring and link back. VHS is presentation, not proof: every standard demo has a
fast non-visual verifier that runs the same behavior without Chrome.

Docs must distinguish implemented behavior from target direction. A green
visual demo alone cannot support a correctness claim.

## Current capability map

Implemented:

- workspace initialization and daemon ownership/status;
- CLI/shell, one-shot commands, daemon RPC, and MCP;
- operations, chains, targets, target sets/groups, configuration, and logs;
- persisted throw plans, confirmations, records, artifacts, and events;
- base Python/Go/Rust module RPC and sessions;
- generic step runtime in Go/Python provider paths;
- Go payload-provider operations and installed payload inventory;
- Go/Python/Rust Mesh descriptors, topology, beacons, listeners, tasks, and
  streams;
- daemon Mesh operation bookkeeping and TCP/UDP loopback bridges;
- workspace PKI custody, Go X.509 backend, issuance, bundles, assignments,
  trust sets, renewal/rotation, revocation/CRLs, authority rollover, daemon RPC,
  and imperative CLI commands;
- Go/Python/Rust credential-provider descriptors and runtime/files/encode/stamp
  dispatch, strict execution unions, secret-free execution/stamp bookkeeping,
  SQLite persistence, assignment-backed runtime selection for Mesh mutations,
  and same-process provider discovery/delivery/operation enforcement;
- Task-wired core, SDK, module, Picblobs/Mbed OS, docs, and repository gates.

Direction or incomplete:

- full general managed-service runtime;
- general fact/target inventory beyond current operator state;
- TUI role;
- complete step-provider parity in Rust;
- complete payload-provider parity in Python/Rust;
- raw IP/ICMP/TUN/TAP local Mesh adapters;
- external protected-file delivery, provider-encoding/stamp initiation, and
  general non-Mesh credential consumption;
- PKI manifests/Huh flows, PKI MCP tools, and published public control SDKs;
- complete contract-snapshot/prepared-value drift blocking;
- broader remote service isolation and authenticated remote control.

Proposed:

- additional selectable crypto backends, broader Mbed TLS/wolfSSL compatibility,
  C consumer/control contracts, and richer external credential orchestration.

## Naming and design constraints

- Prefer domain nouns over implementation nouns.
- Prefer small capability interfaces over feature-wide mandatory interfaces.
- Keep stable IDs separate from human-editable names.
- Use typed enums/value objects for core vocabulary; do not scatter magic
  strings or thresholds across adapters and SDKs.
- Resolve provider-specific flexibility through versioned extension envelopes,
  never unversioned `map[string]any` as the only contract.
- Keep dynamic state out of static descriptors.
- Keep write-only config and private material out of list/inspect read models.
- Use explicit idempotency and caller-selected IDs for retryable lifecycle
  operations.
- Fail closed on unknown versions, changed package digests, unsupported
  capabilities, ambiguous selectors, and invalid state transitions.

## Example dialogue

> **Dev:** "Should the Rust tunnel module be modeled as a Transport?"
>
> **Domain expert:** "No. The module owns a **Mesh**. It may expose a
> **Mesh Route** that Hovel adapts to a local **Mesh Bridge**, but the same Mesh
> can also expose tasks, surveys, listeners, triggers, and beacons. A
> **TransportEndpoint** is only one narrower capability."

> **Dev:** "Can my provider just return a payload path and say it is installed?"
>
> **Domain expert:** "Return the artifact explicitly, then return an
> **Installed Payload Descriptor** only after installation succeeds. Hovel owns
> the inventory record, handle, provenance, and state events."

> **Dev:** "Does every provider need PKI stamping?"
>
> **Domain expert:** "No. Advertise only the delivery or stamp capability you
> implement. Standard named slots provide the seamless path; advanced providers
> may opt into typed offset/address targets, and no-stamp is valid."

## Flagged ambiguities resolved

- **transport vs Mesh**: Mesh is the umbrella; TransportEndpoint is byte
  movement.
- **tunnel vs Mesh Bridge**: a tunnel is generic; Mesh Bridge is the
  daemon-owned local socket adapter.
- **listener vs Mesh Listener**: Listener is general; Mesh Listener is a
  provider-reported listening post; Mesh Bridge is neither.
- **payload vs installed payload vs session**: available definition, generated
  bytes, deployed instance, and live connection are separate objects.
- **module vs service**: bounded execution vs managed long-lived capability.
- **provider vs module type**: provider is an optional capability role; Mesh is
  not a fourth module type.
- **finding/evidence vs capability**: human/audit explanation vs typed reusable
  machine state.
- **operator configuration vs owned secret**: exact caller data is preserved;
  lifecycle-owned private material uses explicit custody/export.
- **module SDK vs control SDK**: implementing a plugin is not controlling the
  daemon.

## Change checklist

When changing a cross-cutting concept, check all affected surfaces:

1. domain constructors and invariants;
2. application services and ports;
3. daemon RPC registration and OpenAPI;
4. command registry, CLI/Huh/MCP adapters, and JSON output;
5. SQLite/filesystem migrations and defensive copying;
6. module wire protocol and Go/Python/Rust SDK parity;
7. provider capability negotiation and unsupported behavior;
8. plan, confirmation, dangerous-policy, and audit paths;
9. Book, Modules, API docs, examples, and non-visual demo verifiers;
10. Task-backed format, lint, build, test, race, fuzz, coverage, and full CI.

If a change alters domain language or a durable architecture decision, update
this file and the relevant ADR rather than letting code, docs, and SDKs drift.
