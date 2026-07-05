# REQ-005: Windows PEB/TEB Walk for API Resolution

## Status
Accepted

## Statement

For Windows targets, picblobs SHALL implement a PEB (Process Environment Block) and TEB (Thread Environment Block) walk to locate loaded DLLs and resolve exported function addresses at runtime. This mechanism SHALL be the sole method by which Windows blobs obtain pointers to Windows API functions. No import tables, no static linking to Windows DLLs, and no assumptions about DLL base addresses SHALL be made.

## Rationale

PIC blobs on Windows cannot rely on the standard PE loader, import address tables, or fixed DLL base addresses. The PEB/TEB walk is the established technique for position-independent Windows shellcode to discover loaded modules and resolve function exports. By walking the PEB's InMemoryOrderModuleList, the blob can find kernel32.dll (or ntdll.dll) and then resolve any needed function by parsing the DLL's export directory.

## Derives From
- VIS-001

## Detailed Requirements

### TEB Access

The blob SHALL access the TEB via the architecture-specific mechanism:

- **x86_64**: Read the TEB pointer from the `gs` segment register. The TEB is located at `gs:[0x30]`, and the PEB pointer is at offset `0x60` within the TEB.
- **aarch64**: Read the TEB pointer from a dedicated register or memory location per Windows ARM64 convention. The PEB pointer is at the documented offset within the TEB.

This is the one additional piece of architecture-specific code required beyond the syscall stub (noted as an exception in REQ-001). It SHALL be implemented as a minimal inline accessor or a second small assembly function, documented alongside the syscall stub.

### PEB Walk

From the PEB, the blob SHALL:

1. Access the `Ldr` field (PEB_LDR_DATA pointer).
2. Traverse the `InMemoryOrderModuleList` (a doubly-linked list of LDR_DATA_TABLE_ENTRY structures).
3. For each loaded module, read the `BaseDllName` (Unicode string) and the `DllBase` (module base address).
4. Identify the target module by comparing a hash of its name against a precomputed hash value (see REQ-006).

### Export Directory Parsing

Once the target DLL is located, the blob SHALL:

1. Parse the PE headers starting from the DLL's base address.
2. Locate the export directory from the PE optional header's data directory.
3. Walk the export name table, comparing each exported function name's hash against the target hash.
4. Resolve the function's address via the export address table and ordinal table.
5. Handle forwarded exports: if the resolved address points within the export directory's address range, it is a forwarded export string. The blob SHALL follow the forward by resolving the target DLL and function recursively.

### Resolved Function Caching

The blob SHOULD cache resolved function pointers in a struct or array to avoid redundant PEB walks when the same function is called multiple times. The config struct appended to the blob (see REQ-014) MAY include a region for this purpose.

### Minimum Required Resolutions

For the v1 blob types, the following Windows API functions SHALL be resolvable (non-exhaustive — each blob type will document its specific needs):

- From **kernel32.dll**: `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `LoadLibraryA`, `GetProcAddress`, `CreateFileA`, `ReadFile`, `WriteFile`, `CloseHandle`, `CreateThread`, `ExitThread`, `ExitProcess`.
- From **ntdll.dll**: `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx` (if needed for direct syscall fallback paths).
- From **ws2_32.dll**: `WSAStartup`, `WSASocketA`, `connect`, `send`, `recv`, `closesocket` (for bootstrap stager TCP channel — note that ws2_32.dll may need to be loaded via `LoadLibraryA` if not already present).

### Error Handling

If a DLL or function cannot be found via the PEB walk, the blob SHALL fail gracefully — either by returning a null pointer to the calling blob logic (which then decides how to handle it) or by immediately exiting the process, depending on the blob type's requirements.

## Acceptance Criteria

1. On Windows x86_64 and aarch64, the PEB walk successfully locates kernel32.dll and ntdll.dll in a standard Windows process.
2. Export resolution correctly finds all functions listed in the minimum required set.
3. Forwarded exports are correctly followed.
4. The blob contains no import tables, no relocations, and no references to fixed addresses.
5. The TEB access mechanism works in both standard processes and non-standard execution contexts (e.g., thread injection, hollowed processes) where the PEB/TEB are intact.

## Related Decisions
- ADR-005

## Modeled By
- MOD-005

## Verified By
- TEST-003
