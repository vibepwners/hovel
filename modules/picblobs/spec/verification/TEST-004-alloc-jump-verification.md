# TEST-004: Alloc-and-Jump Blob Verification

## Status
Accepted

## Verifies
- REQ-007

## Goal

Demonstrate that the alloc-and-jump blob correctly allocates RWX memory, copies a payload, and transfers execution to it on every supported OS/architecture.

## Preconditions

- QEMU user-static for all supported architectures.
- Per ADR-010: Linux tests verify end-to-end behavior via real syscalls. FreeBSD tests use the `raw_syscall` shim to verify correct FreeBSD syscall usage. Windows tests use the mock TEB/PEB harness to verify correct API resolution and control flow.
- A set of test payloads: minimal PIC programs that write a known magic value to stdout and exit (compiled with Bootlin toolchains using the project's Linux syscall layer).

## Procedure

### Test 4.1: Successful Execution (Linux, all architectures)

For each Linux architecture:

1. Create a test payload for that architecture: a minimal PIC blob that calls `write(1, "PASS", 4)` then `exit_group(0)`.
2. Use the Python API to build an alloc-jump blob with the test payload.
3. Extract the blob and execute it under QEMU user-static.
4. Verify stdout contains "PASS" and exit code is 0.

### Test 4.2: Successful Execution (FreeBSD, all architectures)

For each FreeBSD architecture:

1. Build a FreeBSD alloc-jump blob linked against the `raw_syscall` shim (per ADR-010).
2. Execute under QEMU user-static.
3. Verify the shim's verification log confirms the blob called `mmap` with the correct FreeBSD syscall number and RWX protection flags, followed by a copy and branch to the allocated region.

### Test 4.3: Successful Execution (Windows x86_64 and aarch64)

For each Windows architecture:

1. Build a Windows alloc-jump blob and execute it in the mock TEB/PEB test runner (per ADR-010).
2. Execute under QEMU user-static.
3. Verify the mock verification log confirms the blob:
   a. Resolved VirtualAlloc from mock kernel32.dll via DJB2 hash.
   b. Called mock VirtualAlloc with MEM_COMMIT|MEM_RESERVE and PAGE_EXECUTE_READWRITE.
   c. Copied payload bytes to the allocated region.
   d. Branched to the allocated region.

### Test 4.4: Allocation Failure Handling

1. Build an alloc-jump blob with an absurdly large payload_size (e.g., 0xFFFFFFFFFFFFFFFF on 64-bit).
2. Execute the blob.
3. Verify the blob exits cleanly with a non-zero exit code (not a crash or hang).

### Test 4.5: Instruction Cache Coherency

For ARM and MIPS architectures:

1. Build an alloc-jump blob with a test payload.
2. Verify execution succeeds (this implicitly verifies the icache flush, since without it the payload would likely crash or produce wrong results on these architectures).

### Test 4.6: Blob Size

For each architecture:

1. Measure the alloc-jump blob binary size (excluding payload).
2. Verify it fits within a 512-byte budget.

## Expected Results

- Test payloads execute correctly on all OS/architecture combinations.
- Allocation failure produces a clean exit, not a crash.
- Instruction cache flush works on architectures that require it.
- Blob sizes are minimal.
