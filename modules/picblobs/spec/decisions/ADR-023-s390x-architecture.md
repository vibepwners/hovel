# ADR-023: s390x as 8th Linux Architecture

## Status
Accepted

## Context

The original spec listed s390x (IBM Z mainframe) as a "future candidate" in REQ-018. During Sprint 1, the project successfully brought up 7 Linux architectures. s390x was evaluated and found to be a strong addition because:

1. It provides a second big-endian architecture alongside mipsbe32, improving endianness test coverage.
2. It is a 64-bit big-endian architecture, whereas mipsbe32 is 32-bit. This tests the big-endian + 64-bit combination that no other supported architecture provides.
3. Bootlin provides a ready-made s390x glibc toolchain (gcc triple: `s390x-linux-gnu`).
4. QEMU user-static supports s390x well, requiring no special configuration.

s390x has unique syscall characteristics compared to the other 7 architectures:

- **Syscall instruction**: `svc 0`.
- **Calling convention**: syscall number in `r1`, arguments in `r2`-`r7`, return value in `r2`.
- **Uses `old_mmap` (syscall 90)**: unlike other architectures that use `mmap` or `mmap2`, s390x passes a pointer to a struct containing all 6 mmap arguments. The `pic_mmap` wrapper allocates this struct on the stack before invoking the syscall.
- **`MAP_ANONYMOUS` = 0x20**: same as the x86_64 default, no per-architecture override needed.

## Decision

s390x (IBM Z, big-endian, 64-bit) SHALL be added as the 8th supported Linux architecture. Its definition in `tools/registry.py` SHALL include:

- The `uses_old_mmap` trait, indicating that `pic_mmap` must pass mmap arguments via a stack-allocated struct pointer rather than in registers.
- Syscall numbers for the s390x Linux ABI (e.g., `mmap` = 90, `write` = 4, `exit` = 1).
- Bootlin toolchain configuration with gcc triple `s390x-linux-gnu`.
- QEMU binary `qemu-s390x-static`.

The `old_mmap` variant SHALL be implemented as a custom body in the `SyscallDef` for `pic_mmap`, distinct from the `mmap2` variant used by MIPS and i686 and the standard `mmap` used by x86_64, aarch64, riscv64, and ppc64le.

## Alternatives Considered

- **Defer s390x to a later sprint**: The original spec listed it as a future candidate. However, adding it during Sprint 1 was low cost because the registry-driven codegen (ADR-022) made adding architectures mechanical, and the `old_mmap` variant was the only significant new code required.
- **Use a different big-endian 64-bit architecture (e.g., sparc64, ppc64 big-endian)**: sparc64 has limited QEMU user-mode support and no Bootlin toolchain. ppc64 big-endian (non-LE) is largely deprecated in the Linux ecosystem. s390x has the best tooling support.
- **Skip additional big-endian coverage**: One big-endian architecture (mipsbe32) was already present. However, having only 32-bit big-endian coverage leaves a gap: bugs that manifest only with 64-bit big-endian layouts would go undetected.

## Consequences

- Total Linux architectures increases from 7 to 8.
- Total blobs increases from 96 to 102 (6 additional Linux blobs, one per blob type). FreeBSD s390x support is deferred — FreeBSD does not officially support s390x.
- The `uses_old_mmap` trait in the registry introduces a third mmap variant alongside `mmap` (direct) and `mmap2` (page-shifted offset), requiring a distinct code path in the generated `pic_mmap` wrapper.
- CI runtime increases marginally due to one additional QEMU-emulated test suite.
- The 8-architecture matrix now covers: both endiannesses (little and big), both bit-widths (32 and 64), and all three mmap calling conventions (`mmap`, `mmap2`, `old_mmap`).

## Related Requirements
- REQ-001
- REQ-018
