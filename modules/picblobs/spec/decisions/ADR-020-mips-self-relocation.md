# ADR-020: MIPS GOT Self-Relocation via Trampoline

## Status
Accepted

## Context

PIC blobs must work when jumped to at byte zero with no assumptions about register state. On x86_64, aarch64, ARM, and i686, the compiler generates PC-relative data references that work at any load address. On MIPS32, the compiler uses GOT-relative addressing: `.cpload $t9` sets `$gp` from `$t9`, and data is accessed via `lw $reg, %got(sym)($gp)`. GOT entries contain link-time absolute addresses.

When a MIPS blob is loaded at an arbitrary address via mmap, two problems arise:

1. `$t9` is not set to the blob's entry address (nobody guarantees this).
2. GOT entries contain link-time addresses (e.g., 0x60) instead of runtime addresses (e.g., 0x2baad060).

Additionally, MIPS Linux uses different constants from other architectures: `MAP_ANONYMOUS = 0x0800` (not 0x20), and `mmap2` (syscall 4210) must be used instead of `mmap` (syscall 4090, which takes a struct pointer).

## Decision

MIPS blobs SHALL include a self-relocation trampoline at byte 0 that:

1. Uses `bal` (branch-and-link) to discover the runtime PC — the only way to get PC on MIPS without caller cooperation.
2. Uses `.cpload $ra` to set `$gp` from the discovered PC.
3. Loads the link-time address of `_start` from the GOT via `%got(_start)($gp)`.
4. Computes the runtime base: `runtime_base = $ra - 8` (the `bal` is 8 bytes from byte 0).
5. Computes the runtime `_start` address: `$t9 = linktime_start + runtime_base`.
6. Passes `runtime_base` in `$s0` (callee-saved register).
7. Calls `_start` via `jalr $t9` — GCC's `.cpload $t9` prologue now computes `$gp` correctly.

Inside `_start`, `PIC_SELF_RELOCATE()` patches GOT entries:

1. Loads `__got_start` and `__got_end` from the GOT (link-time values, accessible via now-correct `$gp`).
2. Reads `$s0` as the delta (runtime base).
3. Iterates over GOT entries from `__got_start + delta` to `__got_end + delta`.
4. Adds delta to each entry.

After patching, all GOT-relative data accesses resolve to correct runtime addresses.

The trampoline is emitted automatically by `section.h` on MIPS via top-level `__asm__` and placed in `.text.pic_trampoline` (before `.text.pic_entry` in the linker script). On non-MIPS architectures, no trampoline is emitted.

`PIC_SELF_RELOCATE()` is a C macro: inline asm on MIPS, no-op on other architectures.

The linker script defines `__got_start` and `__got_end` symbols around the `.got` section.

## Alternatives Considered

- **Require caller to set $t9**: Not acceptable — blobs must work when jumping to byte zero with no register setup.
- **Compile MIPS with -fno-pic / -mno-abicalls**: Generates absolute addresses (`lui/addiu`) that are equally broken at non-zero load addresses. No benefit.
- **Patch GOT in the test runner**: Works but makes the blob dependent on a smart loader. Blobs must be self-contained.
- **Use MIPS R6 PC-relative instructions**: MIPS R6 has `aluipc`/`addiupc` but we target MIPS32 (R1/R2), not R6.

## Consequences

- MIPS blobs are slightly larger due to the trampoline (~56 bytes).
- `PIC_SELF_RELOCATE()` must be called at the top of `_start` before any global data access.
- The `$s0` register is used as a calling convention between the trampoline and `_start`.
- `PIC_RODATA` works correctly on all 6 architectures.
- MIPS syscall stubs allocate a 32-byte stack frame for args 5-6 (o32 ABI) and restore it after `syscall`.

## Related Requirements
- REQ-001
- REQ-004

## Supersedes
- None
