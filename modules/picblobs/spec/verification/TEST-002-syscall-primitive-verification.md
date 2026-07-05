# TEST-002: Syscall Primitive and Wrapper Verification

## Status
Accepted

## Verifies
- REQ-001
- REQ-002
- REQ-003
- REQ-004

## Goal

Demonstrate that the single-assembly syscall primitive and the C syscall wrappers correctly invoke kernel syscalls on every supported architecture, for both Linux and FreeBSD.

## Preconditions

- QEMU user-static is installed for all supported architectures.
- Bazel build produces test binaries (small freestanding C programs that invoke syscalls and report results).
- Per ADR-010: Linux tests execute real syscalls via QEMU. FreeBSD tests use an alternate `raw_syscall` shim that verifies syscall numbers and arguments against FreeBSD conventions and returns canned success values.

## Procedure

### Test 2.1: Syscall Primitive — Basic Invocation

For each architecture:

1. Build a minimal test blob that calls `raw_syscall()` with the `write` syscall number, writing a known string to stdout (fd 1).
2. Execute under QEMU user-static.
3. Capture stdout and verify the expected string appears.
4. Verify the exit code is 0.

### Test 2.2: Syscall Primitive — Six Arguments

For each architecture:

1. Build a test blob that calls `raw_syscall()` with a syscall requiring six arguments (e.g., `mmap` on x86_64: addr, length, prot, flags, fd, offset).
2. Verify the syscall returns a valid address (not MAP_FAILED).
3. Write to the mapped memory and read it back to confirm the mapping works.

### Test 2.3: Syscall Primitive — Error Return

For each architecture:

1. Build a test blob that calls `raw_syscall()` with an invalid syscall number or invalid arguments (e.g., mmap with an invalid fd).
2. Verify the return value is negative (Linux) or that the error convention for the architecture/OS is correctly reported.

### Test 2.4: Syscall Number Tables — Spot Check

For each OS/architecture combination:

1. Verify that at least 20 critical syscall numbers match the authoritative source:
   - `read`, `write`, `open`/`openat`, `close`, `mmap`/`mmap2`, `mprotect`, `munmap`, `socket`, `connect`, `exit`/`exit_group`, `getpid`, `fork`/`clone`, `execve`, `dup2`/`dup3`, `pipe`/`pipe2`, `kill`, `brk`, `ioctl`, `fcntl`, `stat`/`fstat`.
2. Compare against the cited kernel version's header file.

### Test 2.5: C Wrapper Integration

For each OS/architecture combination:

1. Build a test blob that uses the C wrapper API (e.g., calls `mmap()`, `write()`, `close()` through the wrapper headers, not via raw_syscall directly).
2. Execute under QEMU user-static.
3. Verify correct behavior: mmap returns a valid pointer, write outputs to stdout, close succeeds.

### Test 2.6: FreeBSD Calling Convention — i686

Specifically for FreeBSD i686 (stack-based argument passing):

1. Build a test blob that calls a 3+ argument syscall (e.g., `write(fd, buf, len)`) using the FreeBSD syscall wrappers.
2. Link against the FreeBSD `raw_syscall` shim (per ADR-010) that captures the arguments as passed.
3. Execute under QEMU user-static.
4. Verify the shim's verification log confirms arguments were passed on the stack per FreeBSD i686 convention (not in registers as Linux i686 expects).

### Test 2.7: MIPS Stack Arguments

For mipsel32 and mipsbe32:

1. Build a test blob that calls `mmap` (requires arguments 5 and 6 on the stack per o32 ABI).
2. Verify mmap succeeds and the mapped memory is usable.

## Expected Results

- Every architecture's syscall primitive correctly invokes syscalls and returns results.
- Six-argument syscalls work on all architectures (including MIPS stack arguments and i686 FreeBSD stack convention).
- Error returns are correctly propagated.
- Syscall number tables match authoritative sources.
- C wrappers correctly translate typed arguments to raw_syscall invocations.
