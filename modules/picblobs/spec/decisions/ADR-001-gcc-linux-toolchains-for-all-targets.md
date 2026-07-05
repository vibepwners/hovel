# ADR-001: Use GCC Linux Cross-Compilers for All Target Platforms

## Status
Accepted

## Context

picblobs targets three operating systems (Linux, FreeBSD, Windows) across many architectures. Normally, targeting Windows requires MSVC or MinGW, and targeting FreeBSD requires a FreeBSD-hosted or FreeBSD-targeting cross-compiler. Maintaining separate toolchains per OS would multiply build complexity and make reproducible builds harder.

## Decision

All blobs — including those targeting Windows and FreeBSD — SHALL be compiled using GCC Linux-hosted cross-compilers (specifically, Bootlin toolchains). This is viable because:

1. The blobs are **freestanding** (`-ffreestanding -nostdlib`): they do not link against any libc, system library, or OS-provided runtime.
2. On Linux and FreeBSD, the blobs interact with the kernel exclusively via raw syscalls (inline assembly). The GCC compiler generates correct machine code for the instruction set regardless of the "target OS."
3. On Windows, the blobs resolve all API functions at runtime via PEB/TEB walk. There are no import tables, no PE headers required — the blob is flat machine code that happens to call Windows API functions discovered at runtime.
4. The custom linker script (ADR-003) produces an ELF that is then extracted to a flat binary. The output is raw bytes of position-independent machine code — it has no OS-specific binary format.

The GCC target triple nominally targets Linux (e.g., `x86_64-linux-gnu`), but since no Linux-specific runtime features are used, the generated machine code is OS-agnostic at the instruction level.

## Alternatives Considered

- **Per-OS toolchains**: Use MSVC/MinGW for Windows, FreeBSD cross-compiler for FreeBSD. Rejected: massively increases toolchain management complexity, makes Bazel hermetic builds harder, and provides no benefit since the blobs are freestanding.
- **Zig cc**: Use Zig's bundled compiler which supports many targets natively. Rejected: Zig's cross-compilation is excellent but Bootlin GCC toolchains are more battle-tested for obscure architectures (armv5, mips), and Bazel has mature GCC toolchain integration.
- **LLVM/Clang**: Use Clang with target triples for each OS. Considered viable but rejected for v1: Bootlin provides ready-made GCC toolchain archives, while Clang would require assembling sysroot-less toolchains manually.

## Consequences

- All blobs are compiled from a single set of toolchains, simplifying the build system.
- The C code MUST NOT reference any OS-specific headers from the toolchain's sysroot (no `<sys/mman.h>`, no `<windows.h>`). All OS-specific constants and types are defined in picblobs' own headers.
- Any GCC builtin that lowers to a libc call (e.g., `memcpy`, `memset` in some cases) must be handled carefully: either use `-fno-builtin` or provide freestanding implementations.
- Testing Windows blobs requires a separate execution environment (not covered by the Linux-hosted GCC), as GCC cannot run Windows code.

## Related Requirements
- REQ-011
