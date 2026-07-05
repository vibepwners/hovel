# REQ-009: Reflective PE Loader Blob

## Status
Accepted

## Statement

picblobs SHALL provide a reflective PE loader blob for every supported Windows architecture (x86_64, aarch64). This blob SHALL parse a PE/COFF binary from memory, map its sections with correct permissions, process relocations, resolve imports via PEB walk, and transfer execution to its entry point — all without invoking the Windows PE loader (`LoadLibrary`), without writing the PE to disk, and without creating file-backed section objects.

## Rationale

Reflective PE loading is the standard technique for executing a DLL or EXE from memory on Windows. The loaded PE can be a fully-featured DLL with imports from the Windows API, because the reflective loader resolves those imports by walking the PEB and parsing export tables of already-loaded system DLLs.

## Derives From
- VIS-001
- REQ-005
- REQ-006

## Detailed Requirements

### PE Parsing

The loader SHALL:

1. Validate the DOS header magic (`MZ`).
2. Follow the `e_lfanew` pointer to the PE signature and validate it (`PE\0\0`).
3. Parse the COFF file header to determine machine type and number of sections.
4. Parse the optional header to determine:
   - Image base address
   - Section alignment
   - Entry point RVA
   - Data directory entries (import table, relocation table, TLS directory, exception directory, etc.)
5. Parse section headers for each section's virtual address, virtual size, raw data pointer, raw data size, and characteristics (permissions).

### Section Mapping

The loader SHALL:

1. Allocate a contiguous region of memory large enough to hold the entire image at section-aligned boundaries, using `VirtualAlloc` (resolved via PEB walk) with `PAGE_READWRITE` initially.
2. Copy each section's raw data from the in-memory PE image to the correct offset within the allocated region.
3. Zero-fill any remaining space in each section (virtual size minus raw data size).
4. After all sections are copied and relocations/imports are processed, apply the correct page protections to each section using `VirtualProtect` (e.g., `.text` gets `PAGE_EXECUTE_READ`, `.rdata` gets `PAGE_READONLY`, `.data` gets `PAGE_READWRITE`).

### Base Relocation Processing

If the PE cannot be loaded at its preferred image base (which is the typical case for reflectively loaded images), the loader SHALL:

1. Locate the base relocation directory from the data directories.
2. Calculate the delta between the preferred image base and the actual allocation base.
3. Process each relocation block, applying fixups for the supported relocation types:
   - `IMAGE_REL_BASED_DIR64` (x86_64)
   - `IMAGE_REL_BASED_HIGHLOW` (if supporting 32-bit PE in future)
   - `IMAGE_REL_BASED_ARM_MOV32` and `IMAGE_REL_BASED_THUMB_MOV32` (aarch64 — or the specific ARM64 relocation types used by Windows)
   - `IMAGE_REL_BASED_ABSOLUTE` (no-op, skip)

### Import Resolution

The loader SHALL:

1. Locate the import directory from the data directories.
2. For each imported DLL:
   a. Check if the DLL is already loaded by walking the PEB's InMemoryOrderModuleList.
   b. If not loaded, resolve `LoadLibraryA` (via PEB walk of kernel32.dll) and call it with the DLL name string from the import descriptor.
3. For each imported function:
   a. If imported by name: resolve the function in the target DLL's export table by parsing the DLL's export directory (same technique as REQ-005 export parsing, but using direct string comparison since the import table already provides the name).
   b. If imported by ordinal: resolve via the export ordinal table.
4. Write the resolved function pointer into the corresponding IAT (Import Address Table) slot.

### Delayed Import Resolution

The loader SHALL process delayed imports (delay-load import directory) eagerly using the same mechanism as standard imports. For each delay-load descriptor, the loader SHALL resolve the target DLL and all imported functions, writing resolved pointers into the delay-load IAT slots. This ensures that delay-loaded functions are available immediately without requiring a delay-load helper stub in the loaded PE.

### Exception Handling (x86_64)

On x86_64 Windows, the loader SHALL register the PE's exception handling data using `RtlAddFunctionTable` (resolved via PEB walk of ntdll.dll) so that structured exception handling (SEH) works correctly in the loaded image. Non-trivial PE images rely on SEH, making this essential for correct operation.

### TLS Callbacks

If the PE contains a TLS directory with TLS callbacks, the loader SHALL invoke each callback with `DLL_PROCESS_ATTACH` reason after the image is fully set up and before calling the entry point.

### Entry Point Transfer

The loader SHALL:

1. Determine the entry point RVA from the optional header and compute the absolute address within the allocated image.
2. Call the entry point with the appropriate calling convention:
   - For DLLs: `DllMain(hinstDLL, DLL_PROCESS_ATTACH, lpReserved)` where `hinstDLL` is the base address of the allocated image, `DLL_PROCESS_ATTACH` is 1, and `lpReserved` is NULL (or non-NULL if loaded implicitly — NULL for reflective loading).
   - For EXEs: call the entry point directly with no arguments (or with the standard `mainCRTStartup` expectations — the loaded EXE is responsible for its own CRT initialization).
3. Return the entry point's return value to the calling context.

### Config Struct

The reflective PE loader's config struct SHALL contain at minimum:

1. **pe_size**: Size of the in-memory PE image in bytes.
2. **pe_data**: The raw PE image bytes, appended after the fixed config fields.
3. **flags**: Optional flags (e.g., call DllMain, process TLS callbacks, register exception handlers).
4. **entry_type**: Enum indicating whether to call as DLL entry (DllMain) or EXE entry.

### .NET Assembly Support

The loader SHALL detect PE images with a CLR header (COM descriptor directory entry). The loader SHALL process the CLR header, initialize the CLR runtime (by resolving and calling `mscoree.dll!CorBindToRuntimeEx` or `CLRCreateInstance` via PEB walk), and invoke the managed entry point. This enables reflective loading of .NET assemblies.

### SxS (Side-by-Side) Manifest Resolution

The loader SHALL parse the PE's embedded manifest (if present in the resource section) and resolve SxS assembly dependencies. The loader SHALL locate the required assemblies in the WinSxS store and load them as needed.

### API Set Resolution

The loader SHALL resolve API set names (e.g., `api-ms-win-*`) to their backing DLL names using the API set schema map. The loader SHALL locate the API set schema map from the PEB and use it to translate API set contract names to host DLL names before resolving imports.

### Module List Registration

The loader SHALL insert the reflectively loaded image into the PEB's module lists (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList) so that the loaded module is visible to the standard Windows loader APIs (`GetModuleHandle`, `EnumProcessModules`, etc.) and to other modules that may walk the PEB.

## Acceptance Criteria

1. A simple PE DLL (calling `MessageBoxA` or writing to a file via `WriteFile`) can be reflectively loaded and its DllMain executed on Windows x86_64 and aarch64.
2. Base relocations are correctly applied when the image loads at a non-preferred base.
3. Imports from kernel32.dll, ntdll.dll, and user32.dll are correctly resolved.
4. Section protections are correctly applied after loading.
5. The loader blob itself contains no import tables, no relocations, and no absolute addresses.

## Related Decisions
- ADR-005
- ADR-006
- ADR-012
- ADR-013
- ADR-014

## Modeled By
- SEQ-002

## Verified By
- TEST-005
