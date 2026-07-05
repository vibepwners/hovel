# REQ-007: Alloc-and-Jump Blob

## Status
Accepted

## Statement

picblobs SHALL provide an alloc-and-jump blob type for every supported OS/architecture combination. This blob SHALL allocate a region of memory with read-write-execute permissions, copy a user-supplied payload into that region, and transfer execution to the beginning of the copied payload. This is the simplest blob type and serves as the foundational execution primitive.

## Rationale

Alloc-and-jump is the most basic PIC stub pattern: it solves the problem of "I have shellcode bytes and I need to run them in a process that may not have an RWX region available." It is the building block on which more complex blob types are constructed and is the most universally useful blob type.

## Derives From
- VIS-001

## Detailed Requirements

### Linux and FreeBSD Implementation

On Linux and FreeBSD, the blob SHALL:

1. Call `mmap` (or the architecture-appropriate equivalent, e.g., `mmap2` on 32-bit Linux) with:
   - `addr`: NULL (kernel chooses address)
   - `length`: size of the payload (provided via config struct)
   - `prot`: PROT_READ | PROT_WRITE | PROT_EXEC
   - `flags`: MAP_PRIVATE | MAP_ANONYMOUS
   - `fd`: -1
   - `offset`: 0
2. If `mmap` fails (returns MAP_FAILED), the blob SHALL call `exit_group` (Linux) or `exit` (FreeBSD) with a non-zero exit code.
3. Copy the payload from its location (appended after the config struct, or pointed to by a config struct field) into the mmap'd region.
4. Optionally flush the instruction cache if required by the architecture (mandatory on ARM, AArch64, MIPS; not required on x86). On Linux this is the `cacheflush` syscall or `__builtin___clear_cache` equivalent. On FreeBSD, the appropriate mechanism for that architecture SHALL be used.
5. Transfer execution to the beginning of the mmap'd region via an indirect branch.

### Windows Implementation

On Windows, the blob SHALL:

1. Resolve `VirtualAlloc` via PEB walk (REQ-005, REQ-006).
2. Call `VirtualAlloc` with:
   - `lpAddress`: NULL
   - `dwSize`: size of the payload (from config struct)
   - `flAllocationType`: MEM_COMMIT | MEM_RESERVE
   - `flProtect`: PAGE_EXECUTE_READWRITE
3. If `VirtualAlloc` fails (returns NULL), the blob SHALL resolve and call `ExitProcess` with a non-zero exit code.
4. Copy the payload into the allocated region.
5. Flush the instruction cache via `FlushInstructionCache` if required by the architecture (mandatory on aarch64).
6. Transfer execution to the beginning of the allocated region via an indirect branch.

### Config Struct

The alloc-and-jump blob's config struct SHALL contain at minimum:

1. **payload_size**: The size in bytes of the payload to be copied and executed.
2. **payload_data**: The payload bytes themselves, appended immediately after the fixed config fields. This is a variable-length field.

The config struct layout SHALL be defined in a C header per REQ-014.

### Execution Transfer

The blob SHALL transfer execution to the payload using an indirect branch (function pointer call or computed jump). The payload SHALL be entered with:

- A valid stack pointer.
- No specific register state guarantees beyond what the architecture's calling convention provides for a function call (i.e., the payload is entered as if it were a C function with no arguments, though the payload is free to ignore this).

### Size

The alloc-and-jump blob SHALL be as small as possible. It is expected to be the smallest blob type, likely under 200 bytes of machine code on most architectures (excluding the appended payload).

## Acceptance Criteria

1. The blob successfully allocates RWX memory, copies a test payload, and executes it on every supported OS/architecture combination.
2. The blob correctly handles mmap/VirtualAlloc failure by exiting cleanly.
3. Instruction cache is flushed on architectures that require it.
4. The blob binary contains no relocations, no imports, and no absolute addresses.

## Related Decisions
- ADR-006
- ADR-013
- ADR-014
- ADR-015

## Modeled By
- SEQ-001

## Verified By
- TEST-004
