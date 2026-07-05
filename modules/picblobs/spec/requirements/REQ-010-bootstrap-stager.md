# REQ-010: Bootstrap Stager Blob

## Status
Accepted

## Statement

picblobs SHALL provide a bootstrap stager blob type for every supported OS/architecture combination. A bootstrap stager establishes a data channel, reads a next-stage payload through that channel, allocates executable memory, and transfers execution to the received payload. Multiple channel types SHALL be supported. Each channel type is a distinct blob variant.

## Rationale

Bootstrap stagers are the standard mechanism for loading a payload over a network or IPC channel. They are deliberately small (minimizing the initial code that must be delivered to the target) and delegate all complex functionality to the next stage. By supporting multiple channel types, picblobs covers the common delivery scenarios: network connections, inherited file descriptors, named pipes, and file-based staging.

## Derives From
- VIS-001

## Detailed Requirements

### Channel Types

The following channel types SHALL be supported in v1. Each channel type produces a distinct blob variant for each OS/architecture combination.

#### TCP Connect-Back

- **Config**: remote IPv4/IPv6 address, remote port.
- **Behavior**:
  1. Create a socket (AF_INET or AF_INET6, SOCK_STREAM, IPPROTO_TCP).
  2. Connect to the configured address and port.
  3. Read the payload length (4-byte or 8-byte little-endian integer, as defined in config).
  4. Allocate RWX memory of that size.
  5. Read payload data from the socket into the allocated region, looping until all bytes are received.
  6. Close the socket.
  7. Flush instruction cache if required.
  8. Transfer execution to the payload.
- **Linux/FreeBSD**: Uses `socket`, `connect`, `read`/`recv`, `close`, `mmap` syscalls.
- **Windows**: Resolves `WSAStartup`, `WSASocketA`, `connect`, `recv`, `closesocket` from ws2_32.dll via PEB walk; uses `VirtualAlloc` for memory.

#### Read from File Descriptor (stdin/fd)

- **Config**: file descriptor number (default: 0 for stdin).
- **Behavior**:
  1. Read the payload length from the file descriptor (4-byte or 8-byte little-endian integer).
  2. Allocate RWX memory of that size.
  3. Read payload data from the file descriptor, looping until all bytes are received.
  4. Flush instruction cache if required.
  5. Transfer execution to the payload.
- **Use case**: The blob is already running in a process with a connected pipe, socket, or redirected stdin.
- **Windows**: Uses `ReadFile` (resolved via PEB walk) on the specified handle value.

#### Named Pipe (Windows and Linux/FreeBSD)

- **Config**: pipe name string.
- **Behavior (Windows)**:
  1. Resolve `CreateFileA` via PEB walk.
  2. Open the named pipe by name (e.g., `\\.\pipe\pipename`) using `CreateFileA` with `GENERIC_READ` access.
  3. Read payload length, allocate RWX, read payload, transfer execution (same as fd-read pattern).
- **Behavior (Linux/FreeBSD)**:
  1. Open the named pipe (FIFO) by path using the `open` syscall.
  2. Read payload length, allocate RWX, read payload, transfer execution.

#### Memory-Mapped File

- **Config**: file path string, offset within file, payload size.
- **Behavior (Linux/FreeBSD)**:
  1. Open the file using `open`/`openat` syscall.
  2. `mmap` the file (or a region of it) with `PROT_READ | PROT_EXEC` (or `PROT_READ`, then copy to a separate RWX region).
  3. Transfer execution to the mapped payload.
- **Behavior (Windows)**:
  1. Resolve `CreateFileA`, `CreateFileMappingA`, `MapViewOfFile` via PEB walk.
  2. Open the file, create a file mapping, map a view.
  3. Copy to RWX memory (or if the mapping is executable, transfer directly).
  4. Transfer execution.

### Common Stager Behavior

All stager variants SHALL share the following behaviors:

1. **Failure handling**: If any step fails (socket creation, connection, file open, memory allocation), the stager SHALL exit the process cleanly with a non-zero exit code. It SHALL NOT spin, retry, or block indefinitely on failure (the next stage can implement retry logic if needed).
2. **Instruction cache flush**: Mandatory on ARM, AArch64, MIPS after writing payload to executable memory. No-op on x86/x86_64.
3. **Payload entry**: The payload is entered as an indirect function call with a valid stack pointer. No specific register state is guaranteed.

### Config Struct

Each stager variant has its own config struct definition, but all share a common prefix:

1. **channel_type**: Enum identifying the channel type (for validation/introspection).
2. **Variant-specific fields**: Address/port for TCP, fd number for fd-read, pipe name length and bytes for named pipe, file path length, offset, and size for mmap.

String fields (pipe name, file path) SHALL be stored as a length-prefixed byte sequence within the config struct, not as null-terminated C strings (to avoid null bytes in the config region if the consumer cares about that, and to make the Python packing unambiguous).

## Acceptance Criteria

1. TCP connect-back stager successfully receives and executes a payload from a listening server on every supported OS/architecture.
2. FD-read stager successfully reads and executes a payload from stdin.
3. Named pipe stager successfully reads and executes a payload from a named pipe.
4. Mmap stager successfully maps and executes a payload from a file on disk.
5. All stager variants exit cleanly on failure (bad address, connection refused, file not found, allocation failure).

## Related Decisions
- ADR-013
- ADR-014
- ADR-015

## Modeled By
- SEQ-003

## Verified By
- TEST-006
