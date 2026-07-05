# REQ-018: Target Architecture and OS Support Matrix

## Status
Accepted

## Statement

picblobs SHALL support the following OS/architecture/blob-type matrix in v1. Each cell in the matrix represents a distinct pre-compiled blob binary. The matrix defines the complete set of blobs that SHALL be built, tested, and shipped in the wheel.

## Rationale

Explicitly defining the support matrix prevents ambiguity about what is and is not supported, ensures the build system produces every required artifact, and gives the test matrix a concrete enumeration to verify against.

## Derives From
- VIS-001
- VIS-002

## Support Matrix

### Blob Type Decomposition

Each OS/architecture combination produces 6 blob variants. The 6 blob types are:

1. **Alloc+Jump** — allocate RWX, copy payload, execute.
2. **Reflective Loader** — parse and load a full ELF (Linux/FreeBSD) or PE (Windows) image from memory. OS-specific: Linux/FreeBSD get Reflective ELF, Windows gets Reflective PE.
3. **Stager TCP** — connect-back TCP channel, read length-prefixed payload, execute.
4. **Stager FD** — read length-prefixed payload from a file descriptor (Linux/FreeBSD) or Windows HANDLE via `ReadFile`.
5. **Stager Pipe** — read from a named pipe: POSIX FIFO (Linux/FreeBSD) or Windows named pipe `\\.\pipe\` (Windows).
6. **Stager Mmap** — map payload from a file: `mmap` (Linux/FreeBSD) or `CreateFileMapping`/`MapViewOfFile` (Windows).

### Linux

| Arch | Alloc+Jump | Reflective ELF | Stager TCP | Stager FD | Stager Pipe | Stager Mmap |
|---|---|---|---|---|---|---|
| x86_64 | YES | YES | YES | YES | YES | YES |
| i686 | YES | YES | YES | YES | YES | YES |
| aarch64 | YES | YES | YES | YES | YES | YES |
| armv5 (ARM) | YES | YES | YES | YES | YES | YES |
| armv5 (Thumb) | YES | YES | YES | YES | YES | YES |
| mipsel32 | YES | YES | YES | YES | YES | YES |
| mipsbe32 | YES | YES | YES | YES | YES | YES |
| s390x | YES | YES | YES | YES | YES | YES |

**Total Linux blobs: 8 architectures x 6 blob types = 48**

### FreeBSD

| Arch | Alloc+Jump | Reflective ELF | Stager TCP | Stager FD | Stager Pipe | Stager Mmap |
|---|---|---|---|---|---|---|
| x86_64 | YES | YES | YES | YES | YES | YES |
| i686 | YES | YES | YES | YES | YES | YES |
| aarch64 | YES | YES | YES | YES | YES | YES |
| armv5 (ARM) | YES | YES | YES | YES | YES | YES |
| armv5 (Thumb) | YES | YES | YES | YES | YES | YES |
| mipsel32 | YES | YES | YES | YES | YES | YES |
| mipsbe32 | YES | YES | YES | YES | YES | YES |

**Total FreeBSD blobs: 7 architectures x 6 blob types = 42**

Note: s390x FreeBSD support is deferred (see ADR-023). FreeBSD does not officially support s390x, so there is no upstream ABI to target.

### Windows

| Arch | Alloc+Jump | Reflective PE | Stager TCP | Stager FD | Stager Pipe | Stager Mmap |
|---|---|---|---|---|---|---|
| x86_64 | YES | YES | YES | YES | YES | YES |
| aarch64 | YES | YES | YES | YES | YES | YES |

**Total Windows blobs: 2 architectures x 6 blob types = 12**

### Grand Total

**102 blob binaries** in the wheel (48 Linux + 42 FreeBSD + 12 Windows).

Note: The reflective loader type differs per OS family (ELF vs PE). There is no Reflective ELF blob for Windows and no Reflective PE blob for Linux/FreeBSD. FreeBSD has 7 architectures (s390x deferred per ADR-023).

### Architecture Details

| Identifier | ISA | Endianness | Word Size | Instruction Mode | Notes |
|---|---|---|---|---|---|
| x86_64 | AMD64 | Little | 64-bit | x86-64 | Primary desktop/server architecture |
| i686 | IA-32 | Little | 32-bit | x86 | Legacy 32-bit x86 |
| aarch64 | ARMv8-A | Little | 64-bit | AArch64 | Modern ARM servers, phones, SBCs |
| armv5_arm | ARMv5TE | Little | 32-bit | ARM | Legacy embedded, routers (ARM mode) |
| armv5_thumb | ARMv5TE | Little | 32-bit | Thumb | Legacy embedded, routers (Thumb mode, 16-bit encoding) |
| mipsel32 | MIPS32 | Little | 32-bit | MIPS | Embedded routers (little-endian MIPS) |
| mipsbe32 | MIPS32 | Big | 32-bit | MIPS | Embedded routers (big-endian MIPS) |
| s390x | z/Architecture | Big | 64-bit | z/Arch | IBM Z mainframes |

### Bare-Metal / Embedded Targets

In addition to the Linux/FreeBSD/Windows blob matrix, picblobs supports hosted-mode blobs compiled for bare-metal Cortex-M4 (Mbed OS). These blobs use the `PIC_PLATFORM_HOSTED` vtable interface and are compiled with the `arm-none-eabi` GCC toolchain.

| Identifier | ISA | Endianness | Word Size | Instruction Mode | Notes |
|---|---|---|---|---|---|
| cortexm4_baremetal | ARMv7E-M | Little | 32-bit | Thumb-2 | Cortex-M4 bare-metal (Mbed OS 5.15) |

Cortex-M4 Thumb-2 blobs are verified by running them under QEMU user-mode via the Linux Thumb hosted runner, proving the compiled code is correct without requiring real hardware.

### Future Architecture Candidates

The following architectures are NOT in v1 but are candidates for future addition:

- RISC-V 64-bit (`riscv64`): Growing in embedded and server spaces.
- RISC-V 32-bit (`riscv32`): Emerging in microcontrollers.
- PowerPC 64-bit (`ppc64`, `ppc64le`): IBM POWER servers.
- MIPS64: High-end network equipment.

Adding a new architecture requires:
1. A Bootlin toolchain registration in Bazel (or arm-none-eabi for bare-metal targets).
2. A syscall assembly stub.
3. Syscall number tables for the supported OSes on that architecture.
4. QEMU user-static support for testing.

## Acceptance Criteria

1. The Bazel build produces exactly 102 blob binaries matching the matrix above.
2. The Python wheel contains all 102 blobs and their metadata.
3. `picblobs.targets()` returns all entries from the matrix.
4. Every cell marked YES passes its verification tests.

## Verified By
- TEST-001
- TEST-008
