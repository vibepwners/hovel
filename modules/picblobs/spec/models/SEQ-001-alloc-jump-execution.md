# SEQ-001: Alloc-and-Jump Execution Sequence

## Status
Accepted

## Description

This sequence describes the runtime execution of an alloc-and-jump blob from entry to payload execution, for both the Linux/FreeBSD and Windows variants.

## Linux/FreeBSD Sequence

```
Blob loaded at arbitrary address
         |
         v
[1] Entry function begins
         |
         v
[2] Compute address of config struct
    (PC-relative access to __config_start symbol)
         |
         v
[3] Read config.payload_size from config struct
         |
         v
[4] Call mmap(NULL, payload_size, PROT_READ|PROT_WRITE|PROT_EXEC,
              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    -> raw_syscall(__NR_mmap, ...)
         |
         +--- mmap returns MAP_FAILED (-1)?
         |         |
         |         v
         |    Call exit_group(1)
         |    -> raw_syscall(__NR_exit_group, 1)
         |    [TERMINATE]
         |
         v
[5] Copy payload bytes from config struct region
    to mmap'd address
    (inline memcpy-equivalent loop: byte-by-byte or word-by-word)
         |
         v
[6] Architecture requires icache flush?
         |
         +--- x86/x86_64: No (coherent icache)
         |
         +--- aarch64/armv5/mips: Yes
         |         |
         |         v
         |    Call cacheflush / equivalent syscall
         |    -> raw_syscall(__NR_cacheflush, start, end, flags)
         |       or use __builtin___clear_cache equivalent
         |
         v
[7] Indirect branch to mmap'd region
    (function pointer call: ((void(*)())addr)())
         |
         v
[PAYLOAD EXECUTES]
```

## Windows Sequence

```
Blob loaded at arbitrary address
         |
         v
[1] Entry function begins
         |
         v
[2] Compute address of config struct
    (PC-relative access to __config_start symbol)
         |
         v
[3] Read config.payload_size from config struct
         |
         v
[4] Resolve VirtualAlloc:
    -> Access TEB via gs:[0x30]
    -> Read PEB from TEB+0x60
    -> Walk InMemoryOrderModuleList
    -> Find kernel32.dll (DJB2 hash match)
    -> Parse kernel32 export table
    -> Find VirtualAlloc (DJB2 hash match)
    -> Cache function pointer
         |
         v
[5] Call VirtualAlloc(NULL, payload_size,
                      MEM_COMMIT|MEM_RESERVE,
                      PAGE_EXECUTE_READWRITE)
         |
         +--- VirtualAlloc returns NULL?
         |         |
         |         v
         |    Resolve ExitProcess, call ExitProcess(1)
         |    [TERMINATE]
         |
         v
[6] Copy payload bytes from config struct region
    to allocated address
         |
         v
[7] Architecture requires icache flush?
         |
         +--- x86_64: No
         +--- aarch64: Yes -> Resolve and call FlushInstructionCache
         |
         v
[8] Indirect branch to allocated region
         |
         v
[PAYLOAD EXECUTES]
```

## Derives From
- REQ-007
