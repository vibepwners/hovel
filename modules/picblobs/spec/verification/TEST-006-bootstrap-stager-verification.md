# TEST-006: Bootstrap Stager Verification

## Status
Accepted

## Verifies
- REQ-010

## Goal

Demonstrate that each bootstrap stager channel type correctly establishes its channel, receives a payload, and executes it on every supported OS/architecture.

## Preconditions

- QEMU user-static for all supported architectures.
- Per ADR-010: Linux tests verify end-to-end behavior (real sockets, real file I/O) via QEMU. FreeBSD tests use the `raw_syscall` shim to verify correct FreeBSD syscall sequences. Windows tests use the mock TEB/PEB harness to verify correct API resolution and control flow.
- Python test harness orchestrates payload serving (TCP listener, pipe writer, file creator) for Linux end-to-end tests.

## Procedure

### Test 6.1: TCP Connect-Back (Linux, all architectures)

For each Linux architecture:

1. Start a TCP listener on the test host that:
   a. Accepts a connection.
   b. Sends a 4-byte little-endian payload length.
   c. Sends a test payload (PIC that writes "TCP_OK" to stdout and exits).
2. Build a TCP stager blob configured to connect to the listener's address and port.
3. Execute under QEMU user-static (with network access to the host).
4. Verify stdout contains "TCP_OK" and exit code is 0.

### Test 6.2: TCP Connect-Back — IPv6

Same as Test 6.1 but using an IPv6 address (::1 loopback).

### Test 6.3: TCP Connect-Back — Connection Refused

1. Build a TCP stager blob targeting a port with no listener.
2. Execute and verify the blob exits cleanly with non-zero exit code (no hang, no crash).

### Test 6.4: FD/Stdin Stager (Linux, all architectures)

For each Linux architecture:

1. Build an FD stager blob configured for fd 0 (stdin).
2. Pipe a payload into the blob's stdin: 4-byte length prefix + test payload.
3. Execute under QEMU user-static with piped input.
4. Verify stdout contains "FD_OK".

### Test 6.5: Named Pipe Stager (Linux, select architectures)

For at least x86_64:

1. Create a FIFO (named pipe) on the filesystem.
2. Build a pipe stager blob configured with the FIFO path.
3. In parallel: write a length-prefixed payload to the FIFO.
4. Execute the blob.
5. Verify the payload executes ("PIPE_OK" on stdout).

### Test 6.6: Mmap File Stager (Linux, select architectures)

For at least x86_64 and aarch64:

1. Write a test payload to a file on disk.
2. Build an mmap stager blob configured with the file path, offset 0, and payload size.
3. Execute and verify the payload executes ("MMAP_OK" on stdout).

### Test 6.7: Windows TCP Stager (Control Flow Verification)

Using the mock TEB/PEB test runner (x86_64, per ADR-010):

1. Build a Windows TCP stager blob.
2. Execute in the mock test runner under QEMU user-static.
3. Verify the mock verification log confirms the blob:
   a. Resolved WSAStartup, WSASocketA, connect, recv, closesocket from mock ws2_32.dll (loading it via mock LoadLibraryA if needed).
   b. Resolved VirtualAlloc, ExitProcess from mock kernel32.dll.
   c. Called mock WSAStartup.
   d. Called mock WSASocketA with AF_INET/AF_INET6, SOCK_STREAM, IPPROTO_TCP.
   e. Called mock connect with the configured address and port.
   f. Called mock recv in a loop (mock returns canned length + payload data).
   g. Called mock VirtualAlloc for payload memory.
   h. Called mock recv in a loop for payload bytes.
   i. Branched to the allocated region.

### Test 6.8: Windows Named Pipe Stager (Control Flow Verification)

Using the mock TEB/PEB test runner (x86_64):

1. Build a Windows pipe stager blob configured for `\\.\pipe\test_picblobs`.
2. Execute in the mock test runner.
3. Verify the mock verification log confirms the blob resolved CreateFileA from mock kernel32.dll, called it with the pipe path, then read length + payload via mock ReadFile calls.

### Test 6.9: Windows Stagers on aarch64

Repeat Windows TCP and pipe stager control flow tests using the mock TEB/PEB test runner compiled for aarch64 (under QEMU aarch64-static).
Verify FlushInstructionCache is called before branching to the payload.

### Test 6.10: FreeBSD Stagers (Shim Verification)

For FreeBSD (all architectures), using the `raw_syscall` shim (per ADR-010):

1. Build FreeBSD TCP, FD, and pipe stager blobs linked against the shim.
2. Execute under QEMU user-static.
3. Verify the shim's verification log confirms the correct FreeBSD syscall numbers and arguments for:
   - TCP: socket(), connect(), read() with correct FreeBSD syscall numbers.
   - FD: read() with correct FreeBSD syscall number.
   - Pipe: open() + read() with correct FreeBSD syscall numbers.
4. Verify the shim confirms arguments match FreeBSD calling conventions (especially i686 stack-based args).

## Expected Results

- Linux: All channel types successfully receive and execute payloads end-to-end under QEMU user-static.
- FreeBSD: Shim verification confirms correct FreeBSD syscall numbers and calling conventions (per ADR-010).
- Windows: Mock verification confirms correct API resolution (DJB2 hashes), correct call sequences, and correct control flow (per ADR-010).
- Connection/open failures produce clean exits on all OS types.
- IPv4 and IPv6 both work for TCP (Linux: end-to-end; FreeBSD/Windows: verified via shim/mock).
- All architectures pass for their supported channels.
