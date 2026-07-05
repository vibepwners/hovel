# ADR-015: Instruction Cache Flush via Syscall

## Status
Accepted

## Context

After writing payload bytes to executable memory, architectures with separate instruction and data caches (ARM, AArch64, MIPS) require an explicit instruction cache flush before the CPU can safely execute the written code. x86/x86_64 has coherent I/D caches and does not require this step.

The flush can be implemented as:
1. A syscall to the OS kernel.
2. Inline assembly (e.g., `dc cvau` / `ic ivau` on AArch64).
3. A compiler builtin (`__builtin___clear_cache`).

## Decision

Instruction cache flush SHALL be performed via an **OS syscall** on all platforms:

- **Linux**: The `cacheflush` syscall (or `__ARM_NR_cacheflush` on ARM, or the appropriate syscall for each architecture). On architectures where no dedicated cacheflush syscall exists (e.g., AArch64 Linux), the blob SHALL use the `riscv_flush_icache` pattern or equivalent — typically `mprotect` round-trip or the architecture-specific mechanism exposed by the kernel.
- **FreeBSD**: The equivalent cache flush mechanism for each architecture.
- **Windows**: `FlushInstructionCache` resolved via PEB walk from kernel32.dll.

On **x86 and x86_64**, the flush is a no-op (no syscall emitted). The blob code SHALL use a conditional compilation guard or architecture-specific include to omit the flush on x86.

## Alternatives Considered

- **Inline assembly (`dc cvau` / `ic ivau` on AArch64, etc.)**: Works but requires EL0 permissions for cache maintenance instructions, which is not guaranteed on all kernels/configurations. The syscall delegates to the kernel, which always has the required privilege. Rejected.
- **`__builtin___clear_cache`**: Compiler intrinsic that typically emits the correct syscall or instructions. However, in freestanding mode (`-ffreestanding -nostdlib`), GCC may emit a call to a libgcc helper that doesn't exist. Unreliable in our build environment. Rejected.

## Consequences

- The icache flush uses the existing syscall infrastructure (raw_syscall assembly primitive + C wrappers). No additional assembly stubs are needed.
- On Windows, `FlushInstructionCache` is added to the set of functions resolved via PEB walk (only on AArch64 — x86_64 Windows does not need it).
- Test verification (TEST-004, TEST-006) SHALL confirm that blobs flush icache on architectures that require it.

## Related Requirements
- REQ-007
- REQ-008
- REQ-010
