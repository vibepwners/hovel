# ADR-014: Blob Execution Model — One-Shot, No Reuse Guarantees

## Status
Accepted

## Context

Blobs allocate memory, modify process state (TEB, module lists, memory protections), and transfer execution to payloads. The question is whether blobs are designed to be called multiple times, concurrently, or only once.

## Decision

All blobs SHALL be **one-shot**: they are designed to execute once and provide no guarantees about being called again or being called concurrently from multiple threads.

Specifically:

- Blobs MAY use global or static state (e.g., resolved function pointer caches) without synchronization.
- Blobs MAY leave allocated memory, modified page protections, or PEB modifications in place after execution.
- Constructors (ELF `.init_array`) are called once; destructors (`.fini_array`) are not guaranteed to be called.
- Re-entering a blob after it has transferred execution to a payload produces undefined behavior.

## Alternatives Considered

- **Reentrant (callable multiple times, not concurrently)**: Would require cleanup of all allocated state between calls. Adds complexity with no clear use case — callers that need multiple loads should build and inject multiple blobs. Rejected.
- **Thread-safe**: Would require synchronization primitives (mutexes, atomics) in freestanding PIC code. Massively increases complexity and code size. No realistic use case requires concurrent blob execution. Rejected.

## Consequences

- Blob implementation can use the simplest possible patterns: global caches, no cleanup, no locking.
- Documentation and Python API should note that `.build()` produces a single-use blob.
- Test verification only needs to confirm one successful execution per blob.

## Related Requirements
- REQ-007
- REQ-008
- REQ-009
- REQ-010
