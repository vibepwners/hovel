# Domain Model

Hovel revolves around these concepts:

```text
Workspace
Operation
Target
Fact
Provider
Service
Module
Payload
Artifact
Chain
Phase
Step
Throw
Run
Job
Event
Evidence
Finding
Transport
Session
Listener
Credential
```

## Workspace

A workspace is the local project/database context for operations, targets, throws, modules, services, artifacts, evidence, and provider state.

MVP storage may be SQLite.

Workspace data:

1. Configuration.
2. Registry metadata.
3. Throw history.
4. Target inventory.
5. Facts.
6. Artifacts.
7. Evidence.
8. Provider cache.
9. Logs.
10. Listener and session state.

## Operation

An operation is the top-level operator context. It is the thing a red teamer picks up, puts down, and comes back to later. Operations own chains, chain logs, target assignments, throws, evidence, and the operator-facing transcript for the work.

`op` is the primary command spelling. `operation` may remain as a readable alias, but product copy and examples should prefer `op`.

Operation responsibilities:

1. Name and describe the active work context.
2. Own one or more chains.
3. Keep each client attachment's active chain separate from the shared chain state.
4. Preserve chain logs and throw records by operation.
5. Keep evidence and findings tied to the operation that produced them.

An attached client can work inside one operation at a time. The operation state is daemon-owned shared state; the active chain selected by a CLI, TUI, REST, or MCP client is client-local attachment state.

## Target

A target represents something the operator is authorized to test.

```yaml
id: target-uuid
name: router-01
addresses:
  - 10.41.32.2
ports:
  - 22/tcp
labels:
  env: lab
  owner: will
facts: []
```

## Fact

Facts are typed observations about a target.

```yaml
type: os.name
value: linux
source: ssh-survey
confidence: 0.95
```

Facts must be mergeable, source-attributed, and queryable.

## Module

A module is a typed user-facing unit of bounded functionality.

Initial module types:

```text
survey
exploit
payload_provider
```

The type set must remain expandable after the first mocked UI stage.

A module may be backed by a process, a built-in Go implementation, or a service call. A reusable composition of modules is a chain, not another module type.

Every module may declare required and optional typed configuration keys. Configuration scopes are `chain` for global chain configuration and `target` for per-target configuration.

## Service

A service is a long-lived or reusable capability managed by Hovel.

Service examples:

1. Payload build service.
2. PIC blob generation service.
3. Listening post.
4. Session broker.
5. Credential broker.
6. Artifact HTTP server.
7. Callback listener.
8. Target inventory sync service.

The key distinction:

```text
Module: run this bounded operation.
Service: start this capability, keep it alive, expose typed operations, manage lifecycle.
```

## Provider

A provider supplies typed resources to modules, chains, and services.

Provider types in the product model:

```text
PayloadProvider
ArtifactProvider
FactProvider
CredentialProvider
ListenerProvider
SessionProvider
```

The first provider implementation should only require `PayloadProvider` and `ArtifactProvider`. Facts may be plain module outputs at first, and credential, listener, and session providers should wait until service lifecycle, policy review, and artifact/event capture are stable.

Future providers may include build, encoder, shellcode, stager, and implant providers.

Payload generation is outside the Hovel core. Hovel resolves payload bytes through provider interfaces, tags them with declared metadata, records hashes and artifacts, then passes the bytes to the next module in the chain.

## Payload

A payload is tagged bytes returned by a provider.

Initial payload kinds:

```text
shell
shellcode
library
executable
```

Payload metadata:

```yaml
id: payload-uuid
name: sshplant-x86_64-linux
kind: elf
arch: x86_64
os: linux
format: bytes
entrypoint: default
size: 123456
sha256: abc123
capabilities:
  - interactive_session
  - stdio_transport
constraints:
  requiresExec: true
  writesDisk: false
requiresPython: false
```

## Listener

A listener or listening post is a managed service that receives callbacks, brokers sessions, serves staged payloads, or controls post-execution sessions.

Lifecycle states:

```text
registered
starting
listening
healthy
degraded
stopping
stopped
failed
```

## Chain

A chain is an operation-owned workflow record and an ordered graph of phases and steps. Chains are CRUD resources: operators can create, select, rename, inspect, list, and delete them through shared application services.

Chain definitions should be modular and loadable. They are collections of module references and chain-scoped configuration, not modules themselves.

Chains own targets for the current workflow. Adding or clearing targets through an operator front end mutates that client's active chain inside the active operation, not a global target scratchpad.

Chains also own their logging topic. The canonical topic shape is `operation/<operation>/chain/<chain>/logs`. A front end only renders logs for the chain selected by its attachment, while daemon-side storage and event streams keep those logs available for other clients attached to the same operation and chain.

Typical phases:

```text
service_prepare
survey
prepare
access
deliver
execute
post
collect
cleanup
service_cleanup
```

## Throw

A throw is the operator-facing execution record for a chain or module against one or more targets. `throw` is both the verb and the singular command root used for listing and inspection.

Throw states:

```text
created
planning
ready
throwing
paused
succeeded
failed
cancelled
partial
cleaning_up
```

Throws must keep the reviewed intent, inputs, targets, chain version, module versions, artifacts, evidence, transcript, errors, and final result.

## Run

A run is an internal runtime execution detail. Operator-facing commands, transcripts, records, and docs should say throw unless the code is describing a low-level module runtime API.

Runtime internals may reuse the throw state machine, but the durable product language remains operation, chain, step, throw, and evidence.
