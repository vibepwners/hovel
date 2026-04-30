# Descriptors and Schemas

Descriptors are the stable boundary between authored content and the Hovel engine. They should be schema-validated and versioned from the beginning.

MVP descriptors should be YAML documents validated against generated JSON Schema. TOML support can be reconsidered after module, service, chain, event, provider, and run-plan schemas are stable.

## Module Descriptor

```yaml
apiVersion: hovel.dev/v1alpha1
kind: Module
metadata:
  name: ssh-memory
  version: 0.1.0
  description: Survey and execute an in-memory payload over SSH in an authorized lab.
  source:
    type: git
    url: https://example.invalid/third-party/ssh-memory
    revision: abc123
  tags:
    - ssh
    - lab
    - payload
spec:
  runtime:
    type: jsonrpc-stdio
    packaging: source
    entrypoint: python -m hovel_ssh_memory
  moduleType: exploit
  inputs:
    target:
      type: targetRef
      required: true
    port:
      type: integer
      default: 22
    username:
      type: string
      required: true
    auth:
      type: credentialRef
      required: true
    payload:
      type: payloadRef
      required: true
  outputs:
    session:
      type: sessionRef
    artifacts:
      type: artifactRef[]
    facts:
      type: fact[]
  requires:
    providers:
      - payload
      - credential
      - artifact
  capabilities:
    - survey
    - deliver
    - execute
  risk:
    network: target
    writesDisk: false
    bindsListener: false
    requiresCredentials: true
```

## Chain Descriptor

Chains are loadable collections of modules and chain-scoped configuration. A chain definition may reference a module as `name@version`; a bare `name` asks the catalog to resolve the latest available version.

```yaml
apiVersion: hovel.dev/v1alpha1
kind: Chain
metadata:
  name: ssh-memory-flow
  version: 0.1.0
  description: Survey a target and run the SSH memory module.
spec:
  steps:
    - id: survey
      module: ssh-survey
    - id: exploit
      module: ssh-memory@0.1.0
  config:
    operator.confirmed_lab:
      type: bool
      required: true
```

## Service Descriptor

```yaml
apiVersion: hovel.dev/v1alpha1
kind: Service
metadata:
  name: picblob-provider
  version: 0.1.0
  description: External provider adapter for PIC payload bytes.
spec:
  runtime:
    type: jsonrpc-stdio
    packaging: source
    entrypoint: python -m hovel_picblob_service
  serviceType: payload_provider
  provides:
    - provider: payload
      kinds:
        - pic
  inputs:
    arch:
      type: string
    os:
      type: string
    format:
      type: string
  lifecycle:
    startMode: on_demand
    healthCheck:
      method: rpc
      interval: 5s
```

Listener service example:

```yaml
apiVersion: hovel.dev/v1alpha1
kind: Service
metadata:
  name: sshplant-lp
  version: 0.1.0
  description: Go listening post for sshplant sessions.
spec:
  runtime:
    type: jsonrpc-stdio
    entrypoint: ./sshplant-lp
  serviceType: listener
  provides:
    - provider: listener
    - provider: session
  inputs:
    bindHost:
      type: string
      default: 127.0.0.1
    bindPort:
      type: integer
      default: 0
  lifecycle:
    startMode: run_scoped
    healthCheck:
      method: http
      path: /healthz
      interval: 2s
```

## Execute Request

```yaml
runId: run-uuid
moduleId: ssh-memory@0.1.0
targets:
  - id: target-uuid
    address: 10.41.32.2
inputs:
  port: 22
  username: user
  payload:
    id: payload:sshplant-x86_64-linux
    kind: elf
    bytes: !!binary |
      AAEC...
    sha256: abc123
providers:
  payload: provider-ref
  artifact: provider-ref
  facts: provider-ref
env:
  HOVEL_RUN_ID: run-uuid
```

## Execute Result

```yaml
status: succeeded
facts:
  - type: os.name
    value: linux
    confidence: 0.95
artifacts:
  - artifact:artifact-uuid
findings: []
outputs:
  session: session-ref
```

## Event Shape

```yaml
id: event-uuid
runId: run-uuid
targetId: target-uuid
moduleId: ssh-survey@0.1.0
type: module.log
level: info
message: detected target architecture
fields:
  arch: x86_64
timestamp: 2026-04-25T18:00:00Z
```

Service event:

```yaml
id: event-uuid
runId: run-uuid
serviceId: service:sshplant-lp
type: service.log
level: info
message: listener started
fields:
  bindHost: 127.0.0.1
  bindPort: 49152
timestamp: 2026-04-25T18:00:00Z
```

Artifact event:

```yaml
type: artifact.created
artifactId: artifact-uuid
name: ssh-transcript.txt
mediaType: text/plain
size: 1234
sha256: abc123
```

## Recommended Schema Files

```text
schemas/
  hovel.module.schema.json
  hovel.service.schema.json
  hovel.chain.schema.json
  hovel.run-plan.schema.json
  hovel.event.schema.json
  hovel.provider.schema.json
```

Run-plan schemas should cover planned steps, resolved descriptor versions, risk labels, required confirmations, requested targets, expected services, expected providers, and the approval record shape used by `StartRun`.
