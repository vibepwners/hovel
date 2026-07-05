# TEST-009: Linker Script Verification

## Status
Accepted

## Verifies
- REQ-012

## Goal

Demonstrate that the custom per-OS linker scripts produce blob binaries with correct section ordering, correct linker symbol placement, proper dead code elimination, and correct config section layout across all target architectures.

## Preconditions

- Bazel build has completed for the target architecture.
- pyelftools is available for ELF inspection.
- The linked ELF (pre-extraction) is available as a build artifact.

## Procedure

### Test 9.1: Section Ordering

For each linked ELF across all OS/arch combinations:

1. Parse the ELF section headers.
2. Verify sections appear in the canonical order: `.text` → `.rodata` → `.data` → `.bss` → `.config`.
3. Verify that no unexpected sections are present (e.g., `.eh_frame`, `.comment`, `.dynamic`, `.interp` should be discarded by the linker script).

### Test 9.2: Linker Symbol Placement

For each linked ELF:

1. Verify `__blob_start` is defined and points to the beginning of the `.text` section.
2. Verify `__blob_end` is defined and points to the end of the last data section (before `.config`).
3. Verify `__config_start` is defined and points to the beginning of the `.config` section.
4. Verify `__config_end` is defined and points to the end of the `.config` section.
5. Verify that `__config_start - __blob_start` equals the expected flat binary size.

### Test 9.3: Dead Code Elimination

For each OS/arch, build two blobs:

1. A blob that uses a subset of syscall wrappers (e.g., alloc-jump uses only mmap and exit).
2. Inspect the linked ELF and verify that unused syscall wrapper functions are NOT present in the final `.text` section.
3. Verify that `--gc-sections` is effective by comparing the `.text` size against a build without `--gc-sections` — the gc'd version SHALL be strictly smaller.

### Test 9.4: Config Section Isolation

For each linked ELF:

1. Verify that the `.config` section has no relocations referencing it from `.text` (config is accessed via PC-relative computation from `__config_start`, not via absolute relocations).
2. Verify that the `.config` section's load address is contiguous with the preceding sections (no gaps or alignment padding that would break the flat binary extraction).

### Test 9.5: Empty and Edge-Case Sections

1. Build a blob with an empty `.bss` section (no uninitialized data). Verify the linker script handles this without producing an invalid binary.
2. Build a blob with a large `.rodata` section (e.g., a reflective loader with embedded format strings). Verify section ordering and symbol placement remain correct.
3. Build a blob with no `.data` section (all data is const). Verify the linker script handles the missing section gracefully.

### Test 9.6: Cross-OS Linker Script Differences

1. Build the same blob type (e.g., alloc-jump for x86_64) with the Linux, FreeBSD, and Windows linker scripts.
2. Verify that each produces valid section ordering and symbol placement.
3. Verify that OS-specific section differences (if any) are correctly handled.

### Test 9.7: Position Independence Verification

For each linked ELF:

1. Verify the binary contains no absolute address relocations that would break position independence.
2. Disassemble the `.text` section and verify all references to `__config_start` and other linker symbols are PC-relative.

## Expected Results

- All blobs have sections in canonical order with no unexpected sections.
- All four linker symbols (`__blob_start`, `__blob_end`, `__config_start`, `__config_end`) are present and correctly placed.
- Dead code elimination removes unreferenced functions.
- Config section is contiguous and unrelocated.
- Edge cases (empty `.bss`, missing `.data`, large `.rodata`) produce valid binaries.
- All references are position-independent.
