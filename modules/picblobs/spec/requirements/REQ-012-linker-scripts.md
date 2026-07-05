# REQ-012: Custom Linker Script for Blob Binary Layout

## Status
Accepted

## Statement

picblobs SHALL use a custom GCC LD linker script to produce ELF binaries with a controlled layout suitable for PIC blob extraction. A single shared linker script SHALL define the memory layout, section ordering, and a config section whose symbol is known to the C code but whose content is not included in the extracted blob — it serves as the attachment point for the runtime config struct.

## Rationale

Standard linker scripts produce ELFs intended for OS loaders, with sections, alignment, and metadata that are unnecessary or harmful for PIC blobs. Custom linker scripts give precise control over:
- Section ordering (code first, then read-only data, then the config symbol).
- Elimination of unnecessary sections (dynamic linking metadata, symbol tables, debug info).
- Placement of a config section at a known position, so the C code can reference it via a linker-defined symbol while the Python extraction step knows to exclude it.

## Derives From
- VIS-001

## Detailed Requirements

### Linker Script

A single shared linker script (`src/linker/blob.ld`) SHALL define the layout for all target OSes. Since blobs are freestanding (`-ffreestanding -nostdlib`) and interact with the OS exclusively through raw syscalls or PEB-resolved APIs, the binary layout is OS-independent. Per-OS linker scripts MAY be introduced if future divergence requires it (e.g., a FreeBSD test-mode variant).

### Section Layout

The linker script SHALL define the following section ordering, with 16-byte alignment:

1. **`.text.pic_trampoline`**: MIPS self-relocation trampoline (see ADR-020). Empty on non-MIPS architectures. Placed first so it executes at byte 0.
2. **`.text.pic_entry`**: Blob entry point function, placed via `PIC_ENTRY` section macro.
3. **`.text.pic_code`**: Helper functions, placed via `PIC_TEXT` section macro.
4. **`.text`**: Remaining code (syscall wrappers, compiler-generated functions).
5. **`.rodata`**: Read-only data (string literals, constant tables, precomputed hashes). Includes `.rodata.pic` subsection.
6. **`.got`**: Global Offset Table. Required for MIPS PIC addressing; may be empty on other architectures.
7. **`.data`**: Mutable initialized data. Includes `.data.pic` and `.data.rel.ro` subsections.
8. **`.bss`**: Zero-initialized data. Includes `.bss.pic` subsection.
9. **`.config`**: Config section with linker symbol `__config_start`. Placed last.

Section placement is controlled by C macros defined in `section.h`: `PIC_ENTRY`, `PIC_TEXT`, `PIC_RODATA`, `PIC_DATA`, `PIC_BSS`, `PIC_CONFIG`.

### Linker Symbols

The linker script SHALL export the following symbols:

- `__blob_start`: Address of the beginning of the blob (start of `.text.pic_trampoline` or `.text.pic_entry`).
- `__blob_end`: Address of the end of the last data section before `.config` (end of `.bss`).
- `__config_start`: Address of the beginning of the `.config` section.
- `__got_start`: Start of the `.got` section (used by MIPS self-relocation, see ADR-020).
- `__got_end`: End of the `.got` section.

These symbols enable:
- The C code to reference the config struct via `__config_start`.
- The MIPS trampoline to patch GOT entries between `__got_start` and `__got_end`.
- The extraction tool to know which bytes to copy (from `__blob_start` to `__blob_end`).

### Entry Point

The linker script SHALL set `ENTRY(_start)`. On non-MIPS architectures, `_start` is the blob's main entry function placed in `.text.pic_entry` via the `PIC_ENTRY` macro. On MIPS, `_start` is in `.text.pic_trampoline` — the auto-generated trampoline that performs GOT self-relocation before calling the user's entry function.

### Dead Code Elimination

The linker script SHALL work in conjunction with `--gc-sections` to eliminate unused functions and data. Only functions reachable from the entry point SHALL be included in the final ELF.

### Alignment

Sections SHALL use 16-byte alignment to satisfy architecture requirements (aarch64 requires at least 4-byte instruction alignment; 16-byte provides a consistent default). The linker script base address SHALL be 0.

### Discarded Sections

The linker script SHALL discard (via `/DISCARD/`) all sections unnecessary for the blob:
- `.interp`, `.dynamic` (no dynamic linker).
- `.plt`, `.got.plt` (no PLT-based calls).
- `.eh_frame`, `.eh_frame_hdr` (no exception handling metadata).
- `.comment`, `.note.*`, `.debug_*` (no debug/build info).
- `.hash`, `.gnu.hash`, `.dynsym`, `.dynstr` (no dynamic symbol resolution).
- `.rela.*`, `.rel.*` (relocations discarded to enforce PIC — any remaining relocations indicate a bug).

## Acceptance Criteria

1. The linked ELF contains only the specified sections in the specified order.
2. The `__config_start` symbol is accessible from C code and points to the correct location.
3. The extraction tool can use ELF section headers or symbol table to identify the code region (`.text` through `.bss`) and the config region (`.config`) precisely.
4. No unnecessary padding exists between sections.
5. No standard ELF runtime sections (`.interp`, `.dynamic`, `.plt`, `.eh_frame`) appear in the output.
6. `--gc-sections` successfully eliminates unreachable code.

## Related Decisions
- ADR-003

## Modeled By
- MOD-003

## Verified By
- TEST-001
- TEST-009
