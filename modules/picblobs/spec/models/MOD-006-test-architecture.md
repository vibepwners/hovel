# MOD-006: Test Architecture

## Overview

All blob testing runs on a single Linux x86_64 host using QEMU user-static for architecture emulation. Three test runner types handle the three target operating systems, all compiled with the same Bootlin toolchains used for blob compilation.

## Test Runner Matrix

```
Runner Type     | Architectures                                          | Count
----------------|--------------------------------------------------------|------
Linux           | x86_64, i686, aarch64, armv5_arm, armv5_thumb,         |   8
                | s390x, mipsel32, mipsbe32                              |
FreeBSD         | x86_64, i686, aarch64, armv5_arm, armv5_thumb,         |   7
                | mipsel32, mipsbe32                                     |
Windows         | x86_64, aarch64                                        |   2
                                                                   Total:  17
```

## Execution Model

```
┌──────────────────────────────────────────────────────────────┐
│  Linux x86_64 Host                                           │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  QEMU user-static                                       │ │
│  │                                                         │ │
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │ │
│  │  │ Linux Runner  │  │ FreeBSD Runner│  │ Win Runner  │ │ │
│  │  │               │  │               │  │             │ │ │
│  │  │ blob ──────►  │  │ blob ──────►  │  │ blob ────►  │ │ │
│  │  │ real syscalls │  │ shim syscall  │  │ mock PEB    │ │ │
│  │  │ via QEMU      │  │ ──► verify    │  │ ──► verify  │ │ │
│  │  │ ──► real OS   │  │     args +    │  │     hashes +│ │ │
│  │  │     effects   │  │     numbers   │  │     control │ │ │
│  │  │               │  │               │  │     flow    │ │ │
│  │  └───────────────┘  └───────────────┘  └─────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Linux Test Runner

The Linux test runner is a minimal freestanding binary that:

1. Loads the blob binary into memory.
2. Appends the config struct with test-specific parameters.
3. Transfers execution to the blob entry point.
4. The blob executes using real Linux syscalls, emulated by QEMU user-static for non-native architectures.

Verification: Capture stdout, stderr, and exit code. Compare against expected values.

This runner provides **end-to-end integration testing** — the blob runs exactly as it would on real hardware.

## FreeBSD Test Runner (Test-Mode Build with Shim)

FreeBSD blobs are built in two modes:

- **Test-mode**: The bottom-level syscall handler is compiled to jump to a fixed address instead of executing a real syscall instruction. A test-specific linker script places a verification shim at that exact address.
- **Release-mode**: Real FreeBSD syscall instructions. These are the blobs shipped in the wheel. They are structurally verified (correct layout, no ELF headers, correct metadata) but not runtime-tested.

The test-mode shim at the fixed address:

1. Receives the FreeBSD syscall number and up to 6 arguments.
2. Logs the syscall number and arguments to a verification buffer.
3. Validates the syscall number matches the expected FreeBSD number for the intended operation (e.g., FreeBSD `mmap` = 477, not Linux `mmap` = 9 on x86_64).
4. Validates argument layout matches FreeBSD calling convention:
   - i686: arguments on stack (not in registers as Linux i686 expects).
   - All architectures: error returns via carry flag convention (shim verifies the blob handles the return format correctly).
5. Returns canned success values appropriate to the syscall.

Test-mode blobs share all C-level source code with release-mode blobs; only the syscall dispatch path differs. This ensures all control flow, argument preparation, and error handling logic is exercised. Test-mode binaries do NOT ship in the wheel.

Verification: After blob execution, inspect the verification buffer to confirm the correct sequence of FreeBSD syscalls with correct arguments.

## Windows Test Runner (Mock TEB/PEB)

The Windows test runner is a Linux binary that constructs a synthetic Windows environment:

### Fake TEB/PEB Setup

1. Allocate memory for TEB, PEB, PEB_LDR_DATA, and LDR_DATA_TABLE_ENTRY structures.
2. Populate structure fields at the correct offsets:
   - TEB+0x60 → PEB pointer
   - PEB+0x18 → PEB_LDR_DATA pointer
   - PEB_LDR_DATA+0x20 → InMemoryOrderModuleList head
3. Create mock module entries for:
   - kernel32.dll (DJB2 hash of "kernel32.dll")
   - ntdll.dll (DJB2 hash of "ntdll.dll")
   - ws2_32.dll (DJB2 hash of "ws2_32.dll")
4. Each mock module entry contains a fake PE header with a valid export directory pointing to mock export tables with DJB2-matched function names.

### TEB Access Setup

- **x86_64**: Set the `gs` segment base to point to the fake TEB (via `arch_prctl(ARCH_SET_GS, teb_addr)`).
- **aarch64**: Set register `x18` to the fake TEB address before transferring control to the blob. (Under QEMU user-static, x18 is a general-purpose register without OS-level semantics, so it can be freely set.)

### Mock API Functions

Each resolved function pointer points to a mock implementation that:

1. Records the call (function hash, arguments) to a verification log.
2. Performs a minimal real operation where needed for the blob to continue:
   - `VirtualAlloc` → calls `mmap` with equivalent protections, returns the real pointer.
   - `VirtualProtect` → calls `mprotect`, returns success.
   - `VirtualFree` → calls `munmap`, returns success.
   - `ExitProcess` → calls `exit`.
   - `LoadLibraryA` → records the DLL name, returns a fake handle (pointer to a mock module).
   - `GetProcAddress` → returns mock function pointer.
   - Socket functions → return canned values or operate on real Linux sockets.
   - `FlushInstructionCache` → no-op (QEMU handles this).
3. Returns a canned success value.

### Verification

After blob execution, inspect the verification log to confirm:
- The blob resolved the correct DJB2 hashes in the correct order.
- The blob called the expected API functions with plausible arguments.
- Control flow proceeded as specified in the sequence diagrams (SEQ-001, SEQ-002, SEQ-003).

## Test Payload Binaries

Test payloads are minimal PIC programs compiled with the same Bootlin toolchains, using the project's Linux syscall layer:

- **"PASS" payload**: Calls `write(1, "PASS", 4)` then `exit_group(0)`. Used by alloc-jump and stager tests.
- **Exit-code payload**: Calls `exit_group(42)`. Used for verifying execution transfer.
- **"LOADED" payload**: Writes "LOADED" to stdout. Used by reflective loader tests.
- **TCP/FD/PIPE/MMAP payloads**: Write channel-specific markers ("TCP_OK", "FD_OK", etc.) and exit.
- **Test ELFs**: Minimal static PIE ELFs with relocations, BSS, and constructors for reflective ELF loader testing.
- **Test PEs**: Minimal DLLs and EXEs for reflective PE loader testing (only needed for control-flow verification in mock environment).

## Test Harness Orchestration

A Python test harness orchestrates all test execution:

1. For each (runner_type, architecture, blob_type) combination:
   a. Select the appropriate test runner binary.
   b. Prepare the blob binary with test-specific config.
   c. Start any required infrastructure (TCP listener for stager tests, FIFO for pipe tests, etc.).
   d. Invoke `qemu-{arch}-static ./test_runner <blob_binary>`.
   e. Capture stdout, stderr, exit code.
   f. For shim/mock runners: parse the verification log from a shared memory region or output file.
   g. Assert expected results.

2. The harness manages QEMU user-static invocation, including:
   - Architecture-specific QEMU binary selection (qemu-aarch64-static, qemu-s390x-static, qemu-mipsel-static, etc.).
   - Library path setup (Bootlin sysroot for dynamic test binaries, though most are freestanding).
   - Network configuration for stager tests (host-accessible loopback).
