# ADR-010: QEMU User-Static Testing with FreeBSD Shim and Windows Mock

## Status
Accepted

## Context

picblobs produces 96 blobs targeting Linux, FreeBSD, and Windows across 7 architectures. Testing all combinations requires executing code for non-native architectures and non-native operating systems. Real FreeBSD and Windows environments for every architecture are impractical to provision and maintain in CI.

All blobs are freestanding PIC — they interact with the OS exclusively through raw syscalls (Linux/FreeBSD) or PEB-resolved API calls (Windows). This means OS interaction is a narrow, well-defined surface that can be intercepted.

## Decision

All blob testing SHALL run under QEMU user-static on a Linux x86_64 host. Three distinct test runner types handle the three target operating systems:

1. **Linux test runners**: Execute blobs directly. Blob syscalls are serviced by QEMU's Linux syscall emulation. Tests verify actual end-to-end behavior.

2. **FreeBSD test runners**: FreeBSD blobs are built in two modes. **Test-mode** blobs have the bottom-level syscall handler replaced with a jump to a fixed shim address. A test-specific linker script places a verification stub at that address. The stub logs syscall numbers and arguments, validates they match FreeBSD conventions, and returns canned success values. This exercises all C-level logic and control flow. **Release-mode** blobs contain real FreeBSD syscall invocations and are shipped in the wheel; they are structurally verified (correct layout, no ELF headers, correct metadata) but not runtime-tested. Test-mode binaries do not ship in the wheel.

3. **Windows test runners**: Build a Linux test harness that constructs a fake TEB/PEB in memory, populates it with mock module entries (kernel32.dll, ntdll.dll, ws2_32.dll), and provides mock API implementations behind the expected DJB2 hashes. Mock implementations verify control flow — that the blob resolves the correct hashes, calls the correct functions in the correct order with plausible arguments. Mock functions return canned success values (e.g., mock VirtualAlloc returns a real mmap'd region, mock ExitProcess calls exit).

Each runner type is compiled for every relevant architecture using the same Bootlin toolchains and executed under QEMU user-static.

## Alternatives Considered

- **Real Windows VMs per architecture**: Correct but impractical — Windows aarch64 VMs are difficult to provision, and maintaining Windows CI infrastructure for a library that produces freestanding blobs is disproportionate overhead. The mock approach verifies the blob's control flow, which is the part the project owns; the Windows kernel's behavior is not under test.

- **Real FreeBSD VMs or QEMU system emulation**: Heavyweight — requires booting a full FreeBSD kernel per architecture. Since FreeBSD and Linux blobs share all code except syscall numbers and calling conventions, proving Linux works end-to-end plus proving FreeBSD syscall arguments are correct provides equivalent confidence.

- **Wine for Windows x86_64**: Partial coverage — Wine emulates Win32 but not the raw PEB/TEB structures at the level picblobs operates. The mock approach provides more precise verification of the exact PEB walk and DJB2 resolution logic.

## Rationale

The three-tier strategy exploits the project's architecture:

- **Linux blobs are the ground truth.** They run real syscalls under QEMU and verify actual behavior. If mmap + write + exit works on Linux x86_64 under QEMU, the syscall primitive and C wrapper layer are correct for that architecture.

- **FreeBSD blobs share all code except syscall numbers and calling conventions.** Test-mode blobs redirect the syscall handler to a shim at a fixed address (placed by a test-specific linker script), which proves the FreeBSD-specific code paths select the right syscall numbers and pass arguments in the right convention (e.g., i686 stack-based args, carry flag error returns). Since the underlying syscall dispatch and C logic are proven by the Linux runner, this is sufficient. Release-mode blobs with real FreeBSD syscalls are structurally verified only.

- **Windows blobs share the alloc/copy/jump logic with Linux blobs.** What differs is API resolution (PEB walk + DJB2) and API call sequences. The mock TEB/PEB verifies the resolution logic, and mock API functions verify control flow. The actual mmap/memcpy/branch mechanics are proven by Linux runners on the same architecture.

## Consequences

- All tests run on a single Linux x86_64 host with QEMU user-static installed.
- No Windows or FreeBSD infrastructure is required.
- FreeBSD and Windows tests are behavioral verification, not integration tests — they cannot catch bugs in real OS behavior (e.g., a FreeBSD kernel change or a Windows PEB layout change). This is acceptable because those are not bugs in picblobs.
- Approximately 16 test runner binaries are needed: 7 Linux + 7 FreeBSD (one per arch) + 2 Windows (x86_64, aarch64).
- The FreeBSD shim and Windows mock harness become testable artifacts themselves.

## Related Requirements
- REQ-001
- REQ-002
- REQ-003
- REQ-005
- REQ-006
- REQ-007
- REQ-008
- REQ-009
- REQ-010
- REQ-018

## Supersedes
- None
