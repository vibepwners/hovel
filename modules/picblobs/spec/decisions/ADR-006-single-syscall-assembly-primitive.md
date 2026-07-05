# ADR-006: Single Syscall Assembly Primitive Per Architecture

## Status
Accepted

## Context

Blobs on Linux and FreeBSD must invoke syscalls to interact with the kernel. The traditional approach in shellcode is to write each OS operation (mmap, socket, connect, read, write, etc.) in assembly. This works but is hard to maintain, audit, and extend — especially across 7+ architectures. We want the codebase to be primarily C.

## Decision

Each supported architecture SHALL have exactly one assembly function: a generic syscall stub that accepts a syscall number and up to six arguments and returns the raw result. All OS-specific operations (memory mapping, file I/O, socket operations, etc.) SHALL be implemented as C functions that call this single primitive with the appropriate syscall number and arguments.

This means:
- **Total assembly in the project** (for Linux/FreeBSD targets): one small function per architecture (approximately 5-20 instructions each depending on the architecture).
- **Everything else is C**: mmap wrappers, socket wrappers, the reflective loader, bootstrap stagers — all pure C.

Windows is a partial exception: the PEB/TEB access requires a small architecture-specific accessor (reading from `gs:` segment on x86_64, or the equivalent on aarch64). This is the only additional piece of architecture-specific code.

## Alternatives Considered

- **Per-syscall assembly**: Write each syscall wrapper in assembly (traditional shellcode approach). Produces slightly more optimized code (no function call overhead) but dramatically increases the assembly surface area. For 7 architectures, each with hundreds of syscalls, this is unmaintainable. Rejected.
- **Inline assembly in C wrappers**: Use GCC inline asm in each wrapper function. Avoids separate assembly files but still spreads architecture-specific assembly across many files. Also fragile: GCC inline assembly is notoriously hard to get right with register constraints. Rejected in favor of a single, clean assembly source file.
- **Compiler intrinsics**: Some compilers offer `__builtin_syscall` or similar. Not portable across GCC versions and not available for all architectures. Rejected.
- **Assembly-only codebase**: Write the entire blob in assembly, no C. Maximum control and minimal size, but unmaintainable across 7 architectures and completely impractical for complex blob types (reflective loaders). Rejected.

## Consequences

- Adding a new architecture requires writing one ~10-line assembly function. This is a major simplification.
- Adding a new syscall wrapper requires writing a C function — no assembly changes.
- There is a small performance overhead (one extra function call per syscall) compared to inline assembly. This is negligible for all practical blob use cases.
- The assembly files are small enough to be fully reviewed and audited by hand.
- `-fomit-frame-pointer` and link-time optimization (`-flto`) can further reduce the call overhead if needed.

## Related Requirements
- REQ-001
- REQ-002
- REQ-003
