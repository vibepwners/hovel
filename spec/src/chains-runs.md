# Chains and Runs

Chains are declarative workflows with typed steps. They should be inspectable before execution and replay-inspectable after execution.

The first chain runner should be intentionally small. It should support sequential steps, literal inputs, `${inputs.*}` references, `${steps.<id>.output}` references, per-step events, cancellation, and artifact creation. It should not initially support arbitrary expressions, loops, embedded scripting, dynamic graph mutation, or user-defined functions.

Operator-facing chain records are CRUD resources. A chain can be created, selected with `chain use`, renamed, inspected, listed, deleted, and then thrown against the targets it owns. The active chain determines the prompt context, the default targets for `throw`, and the log topic that the client is subscribed to.

Targets are owned by chains in the operator workflow. A target added while `alpha` is active belongs to `alpha`; switching to `beta` exposes `beta`'s target set instead. Chain logs follow the same boundary: `chain logs` renders the active chain's topic only, and multi-client front ends attached to the same chain observe the same topic.

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
        - id: collect-evidence
          uses: module:evidence-collect
    - name: service_cleanup
      steps:
        - id: stop-lp
          uses: service:sshplant-lp.stop_listener
          with:
            listener: ${steps.start-lp.output}
```

## First Runner Requirements

The first runner must support:

1. Sequential steps.
2. Simple input and step-output references.
3. Per-step status and logging.
4. Artifact creation.
5. Fact propagation as ordinary step output.
6. Cancellation between steps.
7. Persisted run plans and run records.
8. Service start/stop steps once the service manager milestone is complete.

## Eventual Runtime Requirements

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
8. Evidence capture.
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
