# SEQ-002: Reflective Loader Execution Sequence

## Status
Accepted

## Description

This sequence describes the runtime execution of reflective loader blobs. Two variants are documented: the ELF reflective loader (Linux/FreeBSD) and the PE reflective loader (Windows).

## ELF Reflective Loader (Linux/FreeBSD)

```
Blob loaded at arbitrary address
         |
         v
[1] Entry: access config struct via __config_start
    Read config.elf_size, config.flags
    Locate config.elf_data (variable region after fixed fields)
         |
         v
[2] Validate ELF header at config.elf_data:
    - Magic: 0x7f 'E' 'L' 'F'
    - Class matches target (ELF32 or ELF64)
    - Machine matches target arch
         |
         +--- Validation fails? -> exit_group(1)
         |
         v
[3] Parse ELF program headers
    Count PT_LOAD segments
    Calculate total memory footprint (max_vaddr - min_vaddr)
         |
         v
[4] Determine base address:
    - ET_DYN (PIE): mmap a large enough RW region, use as base
    - ET_EXEC: attempt to mmap at the ELF's specified vaddr
         |
         v
[5] For each PT_LOAD segment:
    |
    +---> [5a] Calculate segment address = base + (p_vaddr - min_vaddr)
    |
    +---> [5b] mmap(segment_addr, p_memsz, PROT_READ|PROT_WRITE,
    |           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0)
    |
    +---> [5c] Copy p_filesz bytes from ELF image to segment
    |
    +---> [5d] Zero-fill remaining bytes (p_memsz - p_filesz) [BSS]
    |
    +---> [next segment]
         |
         v
[6] Process relocations:
    Parse PT_DYNAMIC to find DT_RELA/DT_REL, DT_RELASZ/DT_RELSZ
    |
    +---> For each relocation entry:
    |     |
    |     +---> Determine relocation type
    |     +---> Apply fixup (add base delta for R_*_RELATIVE, etc.)
    |     +---> [next relocation]
         |
         v
[7] Apply final memory protections:
    For each PT_LOAD segment:
    |
    +---> mprotect(segment_addr, p_memsz, translate_pflags(p_flags))
    |     (e.g., PF_R|PF_X -> PROT_READ|PROT_EXEC)
    |
    +---> [next segment]
         |
         v
[8] Execute constructors (if config.flags & CALL_INIT):
    Parse DT_INIT_ARRAY and DT_INIT_ARRAYSZ from PT_DYNAMIC
    For each function pointer in init_array:
    |
    +---> Call function_ptr()
    |
    +---> [next constructor]
         |
         v
[9] Flush instruction cache (if required by architecture)
         |
         v
[10] Compute entry point: base + e_entry (adjusted for ET_DYN)
     Indirect branch to entry point
         |
         v
[LOADED ELF EXECUTES]
```

## PE Reflective Loader (Windows)

```
Blob loaded at arbitrary address
         |
         v
[1] Entry: access config struct via __config_start
    Read config.pe_size, config.flags, config.entry_type
    Locate config.pe_data
         |
         v
[2] Resolve required API functions via PEB walk:
    - VirtualAlloc (kernel32.dll)
    - VirtualProtect (kernel32.dll)
    - LoadLibraryA (kernel32.dll)
    - FlushInstructionCache (kernel32.dll) [aarch64 only]
    - RtlAddFunctionTable (ntdll.dll) [optional, x86_64 SEH]
    - ExitProcess (kernel32.dll)
    Cache all resolved pointers
         |
         v
[3] Validate PE headers at config.pe_data:
    - DOS magic: 'MZ'
    - PE signature: 'PE\0\0'
    - Machine type matches target
         |
         +--- Validation fails? -> ExitProcess(1)
         |
         v
[4] Read SizeOfImage from optional header
    VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
         |
         +--- Allocation fails? -> ExitProcess(1)
         |
         v
[5] Copy PE headers to allocated base
         |
         v
[6] For each section:
    |
    +---> [6a] Calculate dest = alloc_base + section.VirtualAddress
    +---> [6b] Copy section.SizeOfRawData bytes from PE image
    +---> [6c] Zero-fill remaining (VirtualSize - SizeOfRawData)
    +---> [next section]
         |
         v
[7] Process base relocations:
    Calculate delta = alloc_base - ImageBase (from optional header)
    |
    +--- delta == 0? -> Skip relocations
    |
    +---> Parse relocation directory
    +---> For each relocation block:
    |     For each relocation entry:
    |       Apply fixup based on type (DIR64, HIGHLOW, etc.)
    +---> [next block]
         |
         v
[8] Resolve imports:
    Parse import directory
    |
    +---> For each imported DLL:
    |     |
    |     +---> Check PEB: DLL already loaded?
    |     |     YES -> Use existing base
    |     |     NO  -> Call LoadLibraryA(dll_name)
    |     |
    |     +---> For each imported function:
    |           |
    |           +---> By name: parse DLL export table, string compare
    |           +---> By ordinal: index into DLL export address table
    |           +---> Write function address to IAT slot
    |     |
    |     +---> [next DLL]
         |
         v
[9] Apply section protections:
    For each section:
    |
    +---> Map section characteristics to page protection
    |     (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ -> PAGE_EXECUTE_READ)
    +---> VirtualProtect(section_addr, section_size, protection)
    +---> [next section]
         |
         v
[10] Register exception handlers (optional, x86_64):
     If config.flags & REGISTER_SEH:
       Parse exception directory (.pdata)
       Call RtlAddFunctionTable(FunctionTable, EntryCount, alloc_base)
         |
         v
[11] Execute TLS callbacks (optional):
     If config.flags & PROCESS_TLS:
       Parse TLS directory
       For each callback: Call callback(alloc_base, DLL_PROCESS_ATTACH, NULL)
         |
         v
[12] Flush instruction cache (aarch64):
     Call FlushInstructionCache(GetCurrentProcess(), alloc_base, SizeOfImage)
         |
         v
[13] Transfer to entry point:
     entry = alloc_base + AddressOfEntryPoint
     |
     +--- config.entry_type == DLL?
     |    Call entry(alloc_base, DLL_PROCESS_ATTACH, NULL)
     |
     +--- config.entry_type == EXE?
          Call entry()
         |
         v
[LOADED PE EXECUTES]
```

## Derives From
- REQ-008
- REQ-009
