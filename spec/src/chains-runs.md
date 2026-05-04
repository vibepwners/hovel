# Operations, Chains, and Throws

Operations are the durable work context. Chains are workflows with typed steps inside an operation. Throws are replay-inspectable executions of a chain against targets.

Chains have three related forms:

1. An interactive chain record owned by an operation and edited through `hovel cli`.
2. A chain template, which is a targetless reusable chain definition with steps and configuration schema but without target assignments.
3. A configured chain file, which fully represents a chain, its steps, configuration schema, configured values, target assignments, and target config for review, sharing, and one-shot execution.

Interactive editing and persistent representation are separate concerns. `chain add <module>` remains the fast CLI workflow for building a chain. `chain save <file>` writes the active chain to a YAML file, and `chain load <file>` imports or updates a chain from that file. One-shot shell execution throws a configured chain file rather than relying on prompt session state. Target config is essential to configured chain files because it is part of what the operator reviews and confirms before throwing.

The first chain thrower should be intentionally small. It should support sequential steps, literal inputs, `${inputs.*}` references, `${steps.<id>.output}` references, per-step events, cancellation, and artifact creation. It should not initially support arbitrary expressions, loops, embedded scripting, dynamic graph mutation, or user-defined functions.

Operator-facing chain records are CRUD resources. A chain can be created, selected with `chain use`, renamed, inspected, listed, deleted, and then thrown against the targets it owns. The active chain is client attachment state: it determines that client's prompt context, default targets for `throw`, and log topic subscription without changing another client's active chain.

Targets are owned by chains in the operator workflow. A target added while `alpha` is active belongs to `alpha`; switching that same client to `beta` exposes `beta`'s target set instead. Chain logs follow the same boundary: `chain logs` renders the active chain's operation-scoped topic only, and multi-client front ends attached to the same operation and chain observe the same topic.

## Operation Attachments

Each CLI, TUI, REST, or MCP client attaches to exactly one operation at a time and keeps its own active chain selection.

Concurrency rules:

1. `op use <operation>` changes only the caller's attached operation.
2. `chain use <chain>` changes only the caller's active chain inside the attached operation.
3. `chain add`, `target add`, `chain config`, `target config`, `chain validate`, and `throw` without `--chain` use the caller's active chain.
4. Saved chain-file throws import or execute the file without moving another client's active chain.
5. Mutations to one shared chain are serialized by the daemon and broadcast to subscribers of `operation/<operation>/chain/<chain>/logs`.
6. Different clients may work different chains in the same operation concurrently.

## Chain Definition

Example:

```yaml
apiVersion: hovel.dev/v1alpha1
kind: Chain
metadata:
  name: ssh-memory
spec:
  inputs:
    target:
      type: targetRef
    payload:
      type: payloadRef
  phases:
    - name: service_prepare
      steps:
        - id: start-lp
          uses: service:sshplant-lp.start_listener
          with:
            bindHost: 127.0.0.1
            bindPort: 0
    - name: survey
      steps:
        - id: ssh-survey
          uses: module:ssh-survey
          with:
            target: ${inputs.target}
    - name: prepare
      steps:
        - id: resolve-payload
          uses: provider:payload.resolve
          with:
            payload: ${inputs.payload}
            facts: ${steps.ssh-survey.output.facts}
            listener: ${steps.start-lp.output}
    - name: deliver
      steps:
        - id: ssh-deliver
          uses: module:ssh-deliver
          with:
            target: ${inputs.target}
            payload: ${steps.resolve-payload.output}
    - name: execute
      steps:
        - id: ssh-execute
          uses: module:ssh-execute
          with:
            target: ${inputs.target}
            delivered: ${steps.ssh-deliver.output}
    - name: collect
      steps:
        - id: collect-artifacts
          uses: module:artifact-collect
    - name: service_cleanup
      steps:
        - id: stop-lp
          uses: service:sshplant-lp.stop_listener
          with:
            listener: ${steps.start-lp.output}
```

A chain template records reusable workflow shape:

1. Chain identity and version.
2. Ordered phases and steps.
3. Module references with resolved versions when available.
4. Chain-level and target-level configuration schema.
5. Expected providers, services, listeners, sessions, and artifacts when known.

A configured chain file must contain enough information to reconstruct the review surface without relying on hidden prompt state. At minimum it records:

1. Everything in the chain template.
2. Chain-level configured values.
3. Target list.
4. Per-target configuration values.
5. Risk and confirmation metadata produced by planning.

## First Thrower Requirements

The first thrower must support:

1. Sequential steps.
2. Simple input and step-output references.
3. Per-step status and logging.
4. Artifact creation.
5. Fact propagation as ordinary step output.
6. Cancellation between steps.
7. Persisted throw plans and throw records.
8. Confirmation records, including prompt confirmations and `--now` bypass confirmations.
9. Service start/stop steps once the service manager milestone is complete.

`review` and `throw` share the same planning and review code path. `confirm` stops after recording a pre-confirmation. `review` always displays the reviewed plan, requires the operator to type `yes`, and records or refreshes the confirmation without starting execution. `throw` starts execution only after an existing confirmation, an inline typed `yes`, or an explicit `--now` bypass has produced a confirmation record.

## Eventual Throw Runtime Requirements

The eventual chain runtime should support:

1. Sequential steps.
2. Parallel steps across targets.
3. Conditional branches.
4. Step retries.
5. Timeouts.
6. Cancellation.
7. Service startup.
8. Service teardown.
9. Per-step logging.
10. Per-service logging.
11. Per-target status.
12. Artifact creation.
13. Fact propagation.
14. Listener and session state.

## Productizing PoCs

Hovel exists because productizing proofs of concept is hard. A chain should absorb the work needed to turn a crude one-off script into a repeatable operator workflow:

1. Input validation.
2. Target normalization.
3. Survey and fact collection.
4. Payload selection.
5. Listener startup.
6. Transport selection.
7. Error handling.
8. Artifact and transcript capture.
9. Cleanup.
10. Logging.
11. Multi-target execution.

## Conceptual SSH Memory Chain

This chain is a conceptual example, not an MVP dependency. It uses authenticated SSH as a transport and demonstrates payload delivery/execution in a controlled authorized environment.

The Hovel repository should not need to provide the payload generator, listening post, or target-specific execution components for this example. Those should arrive through providers, managed services, or third-party modules.

Phases:

```text
service_prepare
survey
resolve_payload
prepare_delivery
execute
collect
cleanup
service_cleanup
```

Survey questions:

1. What OS is the target?
2. What architecture is the target?
3. Is `/dev/shm` present?
4. Is `/tmp` memory-backed?
5. Is Python 3 present?
6. What shell is available?
7. Are required environment variables present?
8. What execution constraints exist?

Delivery strategy categories:

```text
stdin_loader
python_ctypes_loader
tmpfs_exec
command_only
```

Public examples should keep payloads benign and lab-oriented.

Expected outputs:

1. Target facts.
2. Started services.
3. Started listeners.
4. Selected strategy.
5. Payload metadata.
6. Execution transcript.
7. Session refs.
8. Artifacts.
9. Result status.
10. Cleanup status.
