# TEST-008: Python API and Wheel Verification

## Status
Accepted

## Verifies
- REQ-015
- REQ-016
- REQ-017
- REQ-018

## Goal

Demonstrate that the Python builder API, metadata introspection API, and wheel packaging are correct and complete.

## Preconditions

- The picblobs wheel has been built and installed in a clean virtual environment.

## Procedure

### Test 8.1: Import and Basic API

1. `import picblobs` succeeds without errors.
2. `picblobs.OS`, `picblobs.Arch`, `picblobs.BlobType` enums are accessible.
3. `picblobs.Blob` class is accessible.

### Test 8.2: Support Matrix Completeness

1. Call `picblobs.targets()` and verify it returns all targets from REQ-018.
2. For each target, call `picblobs.blob_types(os, arch)` and verify the correct blob types are listed.
3. Call `picblobs.is_supported(os, arch, blob_type)` for every cell in the REQ-018 matrix and verify all return True.
4. Call `picblobs.is_supported("linux", "x86_64", "reflective_pe")` and verify it returns False (Reflective PE is Windows-only).

### Test 8.3: Builder — Alloc-Jump

1. Build an alloc-jump blob:
   `picblobs.Blob("linux", "x86_64").alloc_jump().payload(b"\xcc").build()`
2. Verify the result is a `bytes` object.
3. Verify its length equals blob_size + config struct size + payload size.

### Test 8.4: Builder — Stager TCP

1. Build a TCP stager blob:
   `picblobs.Blob("linux", "aarch64").stager_tcp().address("10.0.0.1").port(4444).build()`
2. Verify the result is `bytes`.
3. Verify the config region contains the expected address and port bytes at the correct offsets.

### Test 8.5: Builder — Reflective PE

1. Build a reflective PE loader blob with a small PE file:
   `picblobs.Blob("windows", "x86_64").reflective_pe().pe(pe_bytes).call_dll_main(True).build()`
2. Verify the result is `bytes`.

### Test 8.6: Builder — Validation Errors

1. Attempt `.build()` without setting required parameters. Verify `ValidationError` is raised.
2. Attempt `.Blob("linux", "x86_64").reflective_pe()`. Verify error (PE is Windows-only).
3. Attempt `.stager_tcp().port(99999)`. Verify error (port out of range).
4. Attempt `.Blob("macos", "x86_64")`. Verify error (unsupported OS).

### Test 8.7: Builder — Immutability

1. Create a partial builder: `b = picblobs.Blob("linux", "x86_64").stager_tcp().port(4444)`
2. Build two variants: `b.address("10.0.0.1").build()` and `b.address("10.0.0.2").build()`
3. Verify the two outputs differ (different address) and that `b` is not mutated.

### Test 8.8: Builder — String and Enum Parity

1. Build blob with string args: `picblobs.Blob("linux", "x86_64")...build()`
2. Build blob with enum args: `picblobs.Blob(picblobs.OS.LINUX, picblobs.Arch.X86_64)...build()`
3. Verify both produce identical bytes.

### Test 8.9: Metadata Introspection

1. For a known blob (linux, x86_64, alloc_jump):
   - Verify `blob_size` matches the raw blob file size.
   - Verify `config_offset` is a positive integer.
   - Verify `build_hash` matches SHA256 of `picblobs.raw_blob("linux", "x86_64", "alloc_jump")`.
2. Call `picblobs.config_layout("linux", "x86_64", "alloc_jump")`.
   - Verify it lists the expected fields (version, payload_size, etc.).
   - Verify field offsets and sizes are plausible.

### Test 8.10: Raw Blob Access

1. `raw = picblobs.raw_blob("linux", "x86_64", "alloc_jump")`
2. Verify `len(raw)` matches the metadata's `blob_size`.
3. Verify `hashlib.sha256(raw).hexdigest()` matches the metadata's `build_hash`.

### Test 8.11: DJB2 Utility

1. `picblobs.djb2("VirtualAlloc")` returns expected hash value.
2. `picblobs.djb2_dll("KERNEL32.DLL")` returns same value as `picblobs.djb2("kernel32.dll")`.
3. `picblobs.djb2("")` returns 5381.

### Test 8.12: Wheel Properties

1. Inspect the installed wheel metadata.
2. Verify the wheel tag is `py3-none-any`.
3. Verify no native extensions (`.so`, `.pyd`, `.dylib`) are included.
4. Verify the `_blobs/` directory contains files for all matrix entries.
5. Verify Python version requirement is >= 3.10.
6. Verify no external runtime dependencies are declared.

## Expected Results

- All API calls succeed for supported combinations.
- Validation errors are raised for invalid inputs with descriptive messages.
- Builder immutability is maintained.
- Metadata matches actual blob properties.
- DJB2 hashes match expected values.
- Wheel is correctly tagged and structured.
