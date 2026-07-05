# REQ-011: Bazel Cross-Compilation with Bootlin Toolchains

## Status
Accepted

## Statement

picblobs SHALL use Bazel as its build system for compiling all C source code into PIC blobs. Cross-compilation toolchains SHALL be sourced from toolchains.bootlin.com and registered as Bazel toolchains. The build system SHALL be capable of producing blobs for every supported OS/architecture combination from a single host machine (Linux x86_64 build host).

## Rationale

Bazel provides hermetic, reproducible builds with first-class cross-compilation support via toolchain resolution. Bootlin provides pre-built GCC cross-compilation toolchains for a wide range of architectures, eliminating the need to build or maintain custom toolchains. Because the blobs use only raw syscalls (Linux/FreeBSD) or PEB-resolved APIs (Windows) and never link against any system library, the Linux-hosted GCC cross-compilers can produce correct code for all targets regardless of the target OS — the blob is a flat binary, not a linked executable targeting a specific OS's dynamic linker.

## Derives From
- VIS-001

## Detailed Requirements

### Bazel Workspace Configuration

The Bazel workspace SHALL:

1. Define a `WORKSPACE` (or `MODULE.bazel` for bzlmod) configuration that fetches Bootlin toolchain archives for each supported architecture.
2. Register each toolchain with Bazel's toolchain resolution system, associating it with the correct `--cpu` / platform constraint.
3. Pin toolchain versions (specific Bootlin archive URLs with SHA256 checksums) for reproducibility.

### Supported Toolchains

The following Bootlin toolchains (or equivalent) SHALL be registered:

| Target Architecture | Bootlin Toolchain | GCC Target Triple |
|---|---|---|
| x86_64 | x86-64 glibc (or musl, or bare) | x86_64-linux-gnu |
| i686 | x86-i686 glibc | i686-linux-gnu |
| aarch64 | aarch64 glibc | aarch64-linux-gnu |
| armv5 | armv5-eabi glibc | arm-linux-gnueabi |
| mipsel32 | mipsel-32 glibc | mipsel-linux-gnu |
| mipsbe32 | mips-32 glibc | mips-linux-gnu |
| s390x | s390x glibc | s390x-linux-gnu |

Note: The exact Bootlin configuration names and glibc/musl/uclibc choice SHALL be determined during implementation. Since the blobs are freestanding (`-ffreestanding -nostdlib`), the libc variant in the toolchain is irrelevant — only the compiler and assembler matter.

### Compilation Flags

All blob compilation SHALL use the following base flags:

- `-ffreestanding`: No hosted environment assumptions.
- `-nostdlib`: Do not link the standard C library.
- `-nostartfiles`: Do not link startup files (crt0, crti, etc.).
- `-fno-builtin`: Do not use compiler builtins that may reference libc (or selectively allow safe builtins like `__builtin_memcpy` if the compiler inlines them).
- `-fPIC` or `-fPIE`: Generate position-independent code.
- `-ffunction-sections -fdata-sections`: Place each function and data object in its own section for dead-code elimination.
- `-Os` or `-Oz`: Optimize for size.
- `-Wall -Werror`: All warnings are errors.
- `-fno-stack-protector`: Prevent references to `__stack_chk_fail_local` which is unavailable in freestanding mode.

Additional per-architecture flags (e.g., `-march=armv5te -marm` for ARM mode, `-march=armv5te -mthumb` for Thumb mode, `-mips32 -EL` for mipsel) SHALL be set in the toolchain definition.

### Build Targets

The Bazel build SHALL define:

1. A `cc_library` target for the syscall abstraction layer (per OS, per architecture).
2. A `cc_library` target for the PEB/TEB walk and DJB2 resolution (Windows only).
3. A `cc_binary` (or custom rule) target for each blob type, per OS, per architecture.
4. A custom Bazel rule or genrule that invokes the linker with the custom linker script (REQ-012) and produces the ELF output.
5. Build-time extraction converts linked `.so` files into runtime `.bin` + `.json` sidecar artifacts via `tools/extract_release.py`.

### Platform Definitions

Bazel platform definitions SHALL be created for each OS/architecture combination:

- `//modules/picblobs/platforms:linux_x86_64`
- `//modules/picblobs/platforms:linux_i686`
- `//modules/picblobs/platforms:linux_aarch64`
- `//modules/picblobs/platforms:linux_armv5_arm`
- `//modules/picblobs/platforms:linux_armv5_thumb`
- `//modules/picblobs/platforms:linux_mipsel32`
- `//modules/picblobs/platforms:linux_mipsbe32`
- `//modules/picblobs/platforms:linux_s390x`
- `//modules/picblobs/platforms:freebsd_x86_64`
- `//modules/picblobs/platforms:freebsd_i686`
- `//modules/picblobs/platforms:freebsd_aarch64`
- `//modules/picblobs/platforms:freebsd_armv5_arm`
- `//modules/picblobs/platforms:freebsd_armv5_thumb`
- `//modules/picblobs/platforms:freebsd_mipsel32`
- `//modules/picblobs/platforms:freebsd_mipsbe32`
- `//modules/picblobs/platforms:windows_x86_64`
- `//modules/picblobs/platforms:windows_aarch64`

### Build-All Target

Blob targets live under `//modules/picblobs/src/payload:` (e.g., `//modules/picblobs/src/payload:hello`). The `tools/stage_blobs.py` script (invoked as `picblobs build`) iterates over all platform configs and runs `bazel build --config={config}` for each, staging outputs into the Python package tree.

## Acceptance Criteria

1. Running `picblobs build` on a Linux x86_64 host produces blob binaries for every supported OS/architecture/blob-type combination.
2. The build is hermetic: no system-installed compilers are required (Bazel fetches Bootlin toolchains automatically).
3. The build is reproducible: the same commit produces bit-for-bit identical blob binaries.
4. Each blob binary is a flat, position-independent code blob with no ELF headers, no relocations, and no absolute addresses.

## Related Decisions
- ADR-002

## Verified By
- TEST-001
