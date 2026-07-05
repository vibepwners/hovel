# ADR-013: Runtime Error Handling — Exit Process with Error Code

## Status
Accepted

## Context

Every blob type can encounter runtime failures: `mmap` returning MAP_FAILED, `VirtualAlloc` returning NULL, corrupt ELF/PE headers, socket connection refused, file not found, etc. A consistent error handling strategy is needed across all blob types and all platforms.

## Decision

When a blob encounters a fatal error at runtime, it SHALL terminate the process with a non-zero exit code. Specifically:

- **Linux/FreeBSD**: Call the `exit_group` (Linux) or `exit` (FreeBSD) syscall with a non-zero exit code.
- **Windows**: Call `ExitProcess` (resolved via PEB walk) with a non-zero exit code.

Blobs SHALL NOT:
- Spin, retry, or block indefinitely on failure.
- Return an error code to a caller (blobs are entered via indirect branch, not a function call with a return contract).
- Jump to a configurable error handler.
- Silently continue with corrupt or missing state.

### Error Code Convention

Different failure modes SHOULD use distinct non-zero exit codes to aid debugging:

- `1`: Memory allocation failure (mmap, VirtualAlloc).
- `2`: I/O or network failure (socket, connect, read, open).
- `3`: Format validation failure (bad ELF/PE headers, unsupported features).
- `4`: API resolution failure (PEB walk could not find required function).

These codes are informational and not part of the stable API contract.

## Alternatives Considered

- **Return an error code**: Requires a calling convention contract between the blob entry point and whatever launched it. Blobs are typically injected into arbitrary contexts where no caller is waiting for a return value. Rejected.
- **Configurable error handler address**: Adds config complexity and a second code path. The caller can catch the process exit if needed. Rejected.
- **Silent return**: Leaves the process in an undefined state. Rejected.
- **Retry with backoff**: Adds code size, complexity, and unpredictable timing behavior. The next stage (if any) is responsible for retry logic. Rejected.

## Consequences

- All blob types have a uniform, predictable failure mode.
- Debugging failed blobs is straightforward: non-zero exit code indicates failure, specific code narrows the cause.
- Callers that need error recovery must handle the process exit (e.g., in a child process or thread).

## Related Requirements
- REQ-007
- REQ-008
- REQ-009
- REQ-010
