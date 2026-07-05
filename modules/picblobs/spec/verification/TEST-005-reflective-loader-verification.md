# TEST-005: Reflective Loader Verification

## Status
Accepted

## Verifies
- REQ-008
- REQ-009

## Goal

Demonstrate that the reflective ELF loader (Linux/FreeBSD) and reflective PE loader (Windows) correctly load and execute binaries from memory.

## Preconditions

- QEMU user-static for all architectures.
- Per ADR-010: Linux ELF loader tests verify end-to-end behavior via real syscalls. FreeBSD ELF loader tests use the `raw_syscall` shim. Windows PE loader tests use the mock TEB/PEB harness.
- A set of test ELFs: minimal statically-linked binaries compiled with Bootlin toolchains that output a known value.
- For Windows PE loader tests: mock verification of control flow (section mapping, relocation, import resolution sequence) rather than functional PE execution.

## Procedure

### Test 5.1: ELF Loader — Static PIE (ET_DYN)

For each Linux/FreeBSD architecture:

1. Compile a minimal static PIE ELF (position-independent executable) that writes "LOADED" to stdout and exits.
2. Use the Python API to build a reflective ELF loader blob with this ELF.
3. Execute under QEMU user-static.
4. Verify stdout contains "LOADED" and exit code is 0.

### Test 5.2: ELF Loader — Static Non-PIE (ET_EXEC)

For each Linux architecture (where applicable):

1. Compile a minimal static non-PIE ELF at a fixed base address.
2. Build a reflective ELF loader blob with this ELF.
3. Execute under QEMU user-static.
4. Verify correct execution (may fail if the fixed address conflicts — document this).

### Test 5.3: ELF Loader — Relocations

For each architecture:

1. Compile a static PIE ELF with global variables and function pointers that require relocation fixups (R_*_RELATIVE at minimum).
2. Load via reflective loader.
3. Verify the ELF accesses its global variables correctly (indicating relocations were applied).

### Test 5.4: ELF Loader — BSS Initialization

1. Compile a static PIE ELF with a large zero-initialized global array in BSS.
2. Load via reflective loader.
3. Have the ELF verify all BSS bytes are zero and report success.

### Test 5.5: ELF Loader — Constructor Execution

1. Compile a static PIE ELF with a constructor function (`__attribute__((constructor))`) that sets a global flag.
2. Load via reflective loader with the CALL_INIT flag set.
3. Verify the constructor ran (the ELF's main checks the global flag).

### Test 5.6: PE Loader — Basic DLL Loading (Control Flow Verification)

Using the mock TEB/PEB test runner (x86_64, per ADR-010):

1. Prepare a minimal test PE binary (DLL) with a DllMain entry point.
2. Build a reflective PE loader blob with this DLL, with the DLL flag set.
3. Execute in the mock test runner under QEMU user-static.
4. Verify the mock verification log confirms the blob:
   a. Resolved VirtualAlloc, VirtualProtect, LoadLibraryA from mock kernel32.dll.
   b. Called mock VirtualAlloc with MEM_COMMIT|MEM_RESERVE for image allocation.
   c. Copied PE headers and sections to the allocated region.
   d. Called the entry point as DllMain(base, DLL_PROCESS_ATTACH, NULL).

### Test 5.7: PE Loader — Import Resolution (Control Flow Verification)

Using the mock TEB/PEB test runner (x86_64):

1. Prepare a test PE with import table entries referencing kernel32.dll functions.
2. Load via reflective PE loader in the mock test runner.
3. Verify the mock verification log confirms the blob:
   a. Parsed the import table.
   b. For each imported DLL: checked the mock PEB module list, called mock LoadLibraryA if not found.
   c. For each imported function: parsed the mock export table to resolve the function address.
   d. Wrote the resolved addresses to the IAT.

### Test 5.8: PE Loader — Base Relocation (Control Flow Verification)

Using the mock TEB/PEB test runner (x86_64):

1. Prepare a test PE with a preferred base address and base relocation entries.
2. The mock VirtualAlloc returns a base address different from the preferred base (forcing relocation).
3. Verify the mock verification log confirms the blob processed the relocation table and applied fixups.

### Test 5.9: PE Loader — Windows aarch64

Repeat Tests 5.6 through 5.8 using the mock TEB/PEB test runner compiled for aarch64 (under QEMU aarch64-static).
Verify TEB access via x18 register and that FlushInstructionCache is called.

### Test 5.10: Invalid Input Handling

1. Feed the ELF loader a truncated/corrupt ELF file and verify clean exit (Linux runner, under QEMU user-static).
2. Feed the PE loader a truncated/corrupt PE file and verify clean exit (mock test runner).
3. Feed the ELF loader a PE file and verify clean exit (wrong magic).
4. Feed the PE loader an ELF file and verify clean exit.

## Expected Results

- PIE ELFs load and execute correctly on all Linux architectures (end-to-end under QEMU user-static).
- FreeBSD ELF loader makes correct FreeBSD syscalls (verified via shim per ADR-010).
- PE loader control flow is correct on Windows x86_64 and aarch64 (verified via mock TEB/PEB per ADR-010).
- Relocations are correctly applied (ELF: verified end-to-end on Linux; PE: verified via mock log).
- BSS is zero-initialized.
- Constructors execute when flagged.
- PE imports resolve correctly (verified via mock export table traversal).
- Invalid inputs produce clean exits, not crashes.
