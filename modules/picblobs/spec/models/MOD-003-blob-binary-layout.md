# MOD-003: Blob Binary Layout

## Status
Accepted (amended Sprint 1)

## Description

This model describes the memory layout of a PIC blob at each stage of its lifecycle, from linked shared object to runtime execution.

## Stage 1: Linked Shared Object (.so)

The Bazel build produces an ELF shared object with a custom linker script controlling section placement. All sections are 16-byte aligned, base address 0.

```
Offset  Section              Content                    Macro
──────  ───────────────────  ─────────────────────────  ──────────
0x0000  .text.pic_trampoline MIPS self-reloc trampoline (auto, MIPS only)
        .text.pic_entry      Entry point (_start)       PIC_ENTRY
        .text.pic_code       Helper functions           PIC_TEXT
        .text                Remaining code
        .plt                 PLT stubs (if any)
        .rodata              Read-only data             PIC_RODATA
        .got                 Global offset table
        .data                Initialized data           PIC_DATA
        .data.rel.ro         Relocation read-only data
        .bss                 Zero-initialized data      PIC_BSS
──────  ── __blob_end ──────────────────────────────────────────────
        .config              Config struct              PIC_CONFIG
──────  ───────────────────────────────────────────────────────────

Non-loadable (metadata, not extracted):
        .symtab              Symbol table (for pyelftools)
        .strtab              String table
        .shstrtab            Section header strings
```

### Symbols

| Symbol | Location | Purpose |
|---|---|---|
| `__blob_start` | Start of `.text.pic_trampoline` | First byte of blob code |
| `__blob_end` | After `.bss` | End of blob data |
| `__config_start` | Start of `.config` | Where config struct begins |
| `__got_start` | Start of `.got` | GOT bounds for MIPS self-relocation |
| `__got_end` | End of `.got` | GOT bounds for MIPS self-relocation |

### Discarded Sections

The linker script discards: `.comment`, `.note.*`, `.eh_frame`, `.eh_frame_hdr`, `.hash`, `.gnu.hash`, `.dynsym`, `.dynstr`, `.dynamic`, `.rela.*`, `.rel.*`, `.interp`.

## Stage 2: Extracted Flat Binary

At build time, `tools/extract_release.py` reads the `.so` via pyelftools and writes `.bin` plus JSON sidecar artifacts containing:

- `code`: bytes from `__blob_start` to `__blob_end` (only SHF_ALLOC sections)
- `config_offset`: `__config_start - __blob_start`
- `sections`: dict of section names to (offset, size) tuples
- `sha256`: hash of the code bytes

The extraction reads only allocated sections (SHF_ALLOC flag), skipping `.symtab`/`.strtab` which have `sh_addr=0`. Runtime loaders consume the sidecar artifacts directly and do not parse `.so` files.

## Stage 3: Prepared Blob (for execution)

The runner (or Python API) prepares a flat binary file:

```
[extracted code bytes][config struct at config_offset]
```

The test runner mmaps this into an RWX region and jumps to offset 0.

## Position Independence

### x86_64, aarch64, ARM (armv5)

These architectures use PC-relative addressing for data references. No relocation needed at load time — the code works at any address.

### i686

Uses `@GOTOFF` relative to a PC-discovered GOT base. The GOT is in the blob, so the offset is constant. Works at any address without patching.

### MIPS32 (mipsel, mipsbe)

MIPS32 has no PC-relative data instructions. PIC code uses the GOT via `$gp`, and GOT entries contain link-time absolute addresses.

The blob solves this with a self-relocation trampoline at byte 0:

1. `.text.pic_trampoline` uses `bal` to discover runtime PC
2. Computes `$t9` = runtime address of `_start`
3. Passes runtime base in `$s0`
4. Calls `_start` — GCC's `.cpload $t9` sets `$gp` correctly
5. `PIC_SELF_RELOCATE()` patches GOT entries by adding the base delta

After relocation, GOT-relative data accesses resolve to correct runtime addresses.

## Section Placement Macros

Source files use macros from `picblobs/section.h`:

| Macro | Section | Purpose |
|---|---|---|
| `PIC_ENTRY` | `.text.pic_entry` | Entry point (one per blob) |
| `PIC_TEXT` | `.text.pic_code` | General code |
| `PIC_RODATA` | `.rodata.pic` | Read-only data (strings, tables) |
| `PIC_DATA` | `.data.pic` | Writable initialized data |
| `PIC_BSS` | `.bss.pic` | Zero-initialized data |
| `PIC_CONFIG` | `.config` | Config struct |

## Derives From
- REQ-012
- ADR-003
