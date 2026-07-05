# REQ-004: Per-Architecture Syscall Number Tables

## Status
Accepted

## Statement

picblobs SHALL maintain per-architecture syscall number mappings for every supported OS. These numbers SHALL be embedded inline within each syscall wrapper header (e.g., `picblobs/sys/mmap.h`) via `#ifdef` chains, rather than in separate table files. The mappings SHALL be derived from authoritative kernel sources and maintained in a canonical Python registry (`tools/registry.py`), from which C headers are generated.

## Rationale

Syscall numbers are the fundamental interface between user-space PIC and the kernel. They vary across architectures on Linux (e.g., `mmap` is 9 on x86_64, 90 on i686, 222 on aarch64, 192 on armv5 as `mmap2`, 4090 on mipsel as `mmap2`). FreeBSD's numbers are architecture-independent but differ entirely from Linux's. Maintaining authoritative, versioned tables prevents silent bugs where a blob invokes the wrong syscall.

## Derives From
- REQ-002
- REQ-003

## Detailed Requirements

### Inline Format

Each generated syscall wrapper header contains per-architecture number definitions within `#ifdef` chains:

```c
// In picblobs/sys/mmap.h (generated)
#if defined(__x86_64__)
#define __PIC_NR_mmap 9
#elif defined(__i386__)
#define __PIC_NR_mmap2 192
#elif defined(__aarch64__)
#define __PIC_NR_mmap 222
// ... etc
#endif
```

This approach co-locates the syscall number with the wrapper function that uses it, eliminating a separate layer of indirection.

### Registry Organization

The canonical syscall number data lives in `tools/registry.py` in the `SYSCALL_NUMBERS` dictionary, organized as:

```python
SYSCALL_NUMBERS = {
    "linux": {
        "__x86_64__": {"read": 0, "write": 1, "mmap": 9, ...},
        "__i386__":   {"read": 3, "write": 4, "mmap2": 192, ...},
        ...
    },
    "freebsd": {
        "_all_": {"read": 3, "write": 4, "mmap": 477, ...},
    },
}
```

Linux numbers are per-architecture (via GCC predefined macros). FreeBSD numbers are architecture-independent (`_all_` key).

### Source Authority

- **Linux**: Numbers derived from kernel `unistd.h` / syscall tables per architecture.
- **FreeBSD**: Numbers derived from `sys/kern/syscalls.master`.

### Completeness

The tables SHALL include every syscall that appears in any blob type's implementation. Architecture-specific variants (e.g., `mmap2` on 32-bit, `openat` on aarch64) are tracked as separate entries where the syscall number differs.

## Acceptance Criteria

1. Every syscall used by blob code has a correct number for every supported OS/architecture combination.
2. Numbers are generated from the registry — no hand-maintained number tables.
3. `tools/generate.py --check` verifies generated headers match the registry.
4. FreeBSD numbers are architecture-independent where the OS defines them as such.

## Verified By
- TEST-002
