# Domain Model

Hovel revolves around these concepts:

```text
Workspace
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

A workspace is the local project/database context for targets, runs, modules, services, artifacts, evidence, and provider state.

MVP storage may be SQLite.

Workspace data:

1. Configuration.
2. Registry metadata.
3. Run history.
4. Target inventory.
5. Facts.
6. Artifacts.
7. Evidence.
8. Provider cache.
9. Logs.
10. Listener and session state.

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

Module types:

```text
survey
transport
access
deliver
payload
post_action
cleanup
transform
provider
chain
utility
service_client
```

A module may be backed by a process, a built-in Go implementation, a service call, or a composition of other modules.

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

Payload types:

```text
elf
pe
pic
shellcode
script
command
archive
opaque_blob
implant
loader
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

A chain is an ordered graph of phases and steps.

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

## Run

A run is a concrete execution of a chain or module against one or more targets.

Run states:

```text
created
planning
ready
starting_services
running
paused
succeeded
failed
cancelled
partial
cleaning_up
```
