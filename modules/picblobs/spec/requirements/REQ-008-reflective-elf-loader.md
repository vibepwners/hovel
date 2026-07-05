# REQ-008: Reflective ELF Loader Blob

## Status
Accepted

## Statement

picblobs SHALL provide a reflective ELF loader blob for every supported Linux and FreeBSD architecture. This blob SHALL parse an ELF binary from memory, map its segments with correct permissions, perform relocations, and transfer execution to its entry point — all without invoking the OS dynamic linker or any user-space library loader.

## Rationale

The reflective ELF loader enables loading a complete ELF executable or shared object from memory without writing it to disk or using `dlopen`. This is essential for scenarios where the payload is a compiled ELF binary (not raw shellcode) and the operator wants to execute it from memory.

## Derives From
- VIS-001

## Detailed Requirements

### ELF Parsing

The loader SHALL:

1. Validate the ELF magic bytes (`\x7fELF`).
2. Validate that the ELF class (32-bit or 64-bit) matches the blob's target architecture.
3. Validate that the ELF machine type matches the target architecture.
4. Parse the ELF program headers to identify loadable segments (`PT_LOAD`).
5. Parse the ELF section headers or dynamic segment to locate relocation tables, symbol tables, and string tables as needed for relocation processing.

### Segment Mapping

For each `PT_LOAD` segment, the loader SHALL:

1. Calculate the required memory region (virtual address, alignment, file size, memory size).
2. Allocate memory via `mmap` (Linux/FreeBSD) at the correct relative offsets. The loader SHALL support both ET_EXEC (fixed-address) and ET_DYN (position-independent) ELFs. For ET_DYN, the loader SHALL choose a base address and adjust all segment mappings relative to it.
3. Copy segment data from the in-memory ELF image into the mapped regions.
4. Zero-fill the BSS portion (memory size minus file size) of each segment.
5. Set the correct memory protections (read, write, execute) per segment flags using `mprotect`.

### Relocation Processing

The loader SHALL process relocations to fix up addresses:

1. Parse the `.rela.dyn` / `.rel.dyn` and `.rela.plt` / `.rel.plt` sections (or equivalent entries in the `PT_DYNAMIC` segment).
2. Support the relocation types common to the target architecture (e.g., `R_X86_64_RELATIVE`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`, `R_X86_64_64` on x86_64, and their equivalents on other architectures).
3. For relocations that reference symbols, resolve the symbol from the ELF's own symbol table. External symbol resolution (e.g., resolving libc symbols) is NOT required — the loaded ELF is expected to be statically linked or self-contained. If an unresolvable external symbol is encountered, the loader SHALL store a null or sentinel value and document this behavior.

### TLS (Thread-Local Storage)

If the loaded ELF contains a `PT_TLS` segment, the loader SHALL allocate and initialize thread-local storage for the main thread. The loader SHALL:

1. Allocate memory for the TLS block as described by the `PT_TLS` segment (file size for initialized data, memory size for total allocation including BSS).
2. Copy the TLS initialization image into the allocated block.
3. Zero-fill the remainder (memory size minus file size).
4. Set up the TLS base pointer via the architecture-appropriate mechanism (e.g., `arch_prctl` on x86_64, TPIDR_EL0 on aarch64) so that TLS-referencing instructions in the loaded ELF resolve correctly.

### Dynamic Linking

The loader SHALL support resolving external symbols from shared libraries already loaded in the process address space. The loader SHALL:

1. Parse `DT_NEEDED` entries from the ELF's dynamic segment to identify required shared libraries.
2. For each required library, locate it in the process's already-mapped memory (e.g., by walking `/proc/self/maps` or by attempting `dlopen` with `RTLD_NOLOAD` semantics via raw syscalls).
3. Parse the located library's symbol table and resolve symbols referenced by the loaded ELF.
4. If a required library is not found or a symbol cannot be resolved, the loader SHALL fail cleanly with an identifiable error code rather than branching to an invalid address.

### Signal Handler Frame Setup

The loader SHALL set up signal handler frames so that signal delivery works correctly in the loaded ELF. The loader SHALL:

1. Ensure the stack is configured to support signal delivery (proper alignment, adequate space).
2. If the loaded ELF registers signal handlers, those handlers SHALL be invocable without corruption of the ELF's execution state.

### Constructor Execution

If the ELF contains an `__init_array` section (identified via `DT_INIT_ARRAY` and `DT_INIT_ARRAYSZ` in the dynamic segment), the loader SHOULD call each constructor function pointer in order before transferring to the entry point. If no init array is present, no constructors are called.

### Entry Point Transfer

The loader SHALL:

1. Determine the ELF entry point from the ELF header (`e_entry`), adjusted by the base address for ET_DYN images.
2. Flush the instruction cache on architectures that require it.
3. Transfer execution to the entry point.
4. The entry point SHALL be called with a valid stack. The loader SHALL set up a minimal auxiliary vector (auxv) on the stack (at minimum `AT_NULL` termination, `AT_PHDR`, `AT_PHNUM`, `AT_ENTRY`, `AT_BASE`, `AT_PAGESZ`) so that ELFs relying on auxv for self-inspection can function correctly.

### Config Struct

The reflective ELF loader's config struct SHALL contain at minimum:

1. **elf_size**: Size of the in-memory ELF image in bytes.
2. **elf_data**: The raw ELF image bytes, appended after the fixed config fields.
3. **flags**: Optional flags (e.g., whether to execute constructors, whether to set up auxv).

## Acceptance Criteria

1. A statically-linked ELF "hello world" (using direct syscalls, no libc) can be loaded and executed from memory on every supported Linux/FreeBSD architecture.
2. ET_DYN (PIE) ELFs load correctly with base address relocation.
3. ET_EXEC ELFs load correctly at their specified virtual addresses (may fail if addresses conflict — this is documented).
4. BSS segments are correctly zero-filled.
5. Memory protections are correctly applied (e.g., .text is R-X, .rodata is R--, .data is RW-).
6. The loader blob itself contains no relocations, no imports, and no absolute addresses.

## Related Decisions
- ADR-006
- ADR-012
- ADR-013
- ADR-014
- ADR-015

## Modeled By
- SEQ-002

## Verified By
- TEST-005
