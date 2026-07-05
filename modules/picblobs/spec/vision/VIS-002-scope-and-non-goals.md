# VIS-002: Scope and Non-Goals

## Status
Accepted

## Refines
- VIS-001

## Scope

### In Scope

1. **Target operating systems**: Linux, FreeBSD, Windows.
2. **Target architectures (v1)**:
   - Linux: x86_64, i686, aarch64, armv5 (ARM mode and Thumb mode), s390x, mipsel32, mipsbe32, sparcv8, powerpc, ppc64le, riscv64.
   - FreeBSD: x86_64, i686, aarch64, armv5 (ARM mode and Thumb mode), mipsel32, mipsbe32 (s390x deferred — no upstream FreeBSD support).
   - Windows: x86_64, aarch64.
3. **Blob types (v1)**:
   - Alloc-and-jump: allocate RWX memory, copy a payload into it, transfer execution.
   - Reflective loader: parse and load a full ELF (Linux/FreeBSD) or PE (Windows) image from memory.
   - Bootstrap stager: establish a channel (TCP, stdin/fd, named pipe, mmap-from-file), read a payload, execute it.
4. **Syscall abstraction layer**: A complete C header and source system exposing every syscall on Linux and FreeBSD, implemented entirely in terms of a single per-architecture assembly primitive.
5. **Windows API resolution**: PEB/TEB walk with DJB2 hash-based GetProcAddress resolution; no libc, no IAT, no static linking to Windows libraries.
6. **Build system**: Bazel with Bootlin GCC cross-compilation toolchains, custom per-OS linker scripts, and pyelftools-based blob extraction.
7. **Python packaging**: A `picblobs` wheel built with uv, containing pre-compiled blob assets and auto-generated ctypes bindings.
8. **Python API**: Builder-pattern interface with rich metadata introspection.
9. **Testing**: QEMU user-static execution verification for all Linux/FreeBSD blobs across all architectures.

### Out of Scope

1. **macOS / Mach-O targets**: Not supported. macOS kernel enforces code signing requirements that make unsigned PIC execution impractical for general use.
2. **Encoding, encryption, or obfuscation**: Blobs are plaintext PIC. Encoding (XOR, AES, custom) is the caller's responsibility and may be layered on top.
3. **Byte-pattern avoidance**: No null-free or bad-byte filtering. Blobs contain whatever bytes the compiler emits.
4. **Payload generation**: picblobs provides the loader/stager stub, not the payload itself. The user supplies their own payload bytes.
5. **C2 infrastructure**: No command-and-control protocol, no beaconing, no exfiltration. Bootstrap stagers establish a channel and hand off to the user's payload.
6. **Runtime compilation**: Blobs are pre-compiled at wheel build time. The consumer does not need GCC, Bazel, or any compiler toolchain installed.
7. **Dynamic blob customization beyond config structs**: The blobs are fixed binaries with an appendable config region. Arbitrary compile-time customization (e.g., choosing which syscalls to include) is not exposed to the Python consumer.
8. **Kernel exploits or privilege escalation**: Blobs execute in user-space ring 3 only.
9. **Anti-analysis or evasion techniques**: No anti-debugging, anti-VM, or sandbox detection. Blobs are straightforward and auditable.
