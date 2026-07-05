# TEST-007: Config Struct C/Python Parity

## Status
Accepted

## Verifies
- REQ-014

## Goal

Demonstrate that the auto-generated Python ctypes config struct bindings produce byte-identical serializations to what the C code expects, and that the codegen tool correctly handles all supported struct features.

## Preconditions

- The config codegen tool has been run, producing Python ctypes classes.
- A C test harness can be compiled that deserializes config structs and reports field values.

## Procedure

### Test 7.1: Size Parity

For each config struct definition:

1. Compute `sizeof(struct)` in C (by compiling a small program that prints it).
2. Compute `ctypes.sizeof(GeneratedStruct)` in Python.
3. Verify they are identical.

### Test 7.2: Field Offset Parity

For each config struct and each field:

1. Compute `offsetof(struct, field)` in C.
2. Compute the field offset in the Python ctypes struct (via `GeneratedStruct.field.offset`).
3. Verify they are identical.

### Test 7.3: Round-Trip Serialization — Little Endian

For each config struct:

1. In Python, create an instance with known field values and serialize to bytes using the little-endian variant.
2. In C (compiled for a little-endian architecture, e.g., x86_64), deserialize the same bytes by casting to a struct pointer.
3. Verify every field value matches.

### Test 7.4: Round-Trip Serialization — Big Endian

Same as Test 7.3 but using the big-endian variant (for mipsbe32 targets).

Compile the C test for mipsbe32, run under QEMU user-static.

### Test 7.5: Variable-Length Data

For config structs with variable-length trailing data (e.g., alloc-jump payload, stager pipe name):

1. In Python, build a config with specific variable-length data appended.
2. In C, read the length field, then read that many bytes from the trailing region.
3. Verify the data matches.

### Test 7.6: Nested Structs

For config structs with nested sub-structs:

1. Verify nested struct size and field offsets match between C and Python.
2. Serialize a struct with nested data in Python.
3. Deserialize in C and verify all nested field values.

### Test 7.7: Array of Structs

For config structs with arrays of sub-structs in the variable-length region:

1. In Python, serialize a config with an array of 3+ sub-structs.
2. In C, read the count field and iterate over the array.
3. Verify each sub-struct's fields match.

### Test 7.8: Codegen Tool Rejection

1. Feed the codegen tool a C header containing a pointer field. Verify it fails with a clear error.
2. Feed it a header with a platform-dependent type (`size_t`). Verify it fails with a clear error.
3. Feed it a header with a non-packed struct. Verify it fails (or warns) about potential padding.

### Test 7.9: Big-Endian End-to-End Blob Execution

Verify that a Python-serialized big-endian config is correctly consumed by a real big-endian blob at runtime:

1. In Python, build a complete alloc-jump blob for mipsbe32 Linux using `picblobs.Blob("linux", "mipsbe32").alloc_jump().payload(test_payload).build()`.
2. Execute the assembled blob (code + BE config) under QEMU user-static for mipsbe32.
3. Verify the blob correctly reads the config fields (payload_size, payload_data) from the big-endian serialization.
4. Verify the test payload executes and produces the expected output.
5. Repeat for at least one additional blob type (e.g., stager_fd) to ensure BE serialization works across config struct layouts.

This test is distinct from Test 7.4 (which verifies C/Python field-level parity in isolation). This test verifies the complete pipeline: Python API serializes BE config → blob binary reads it at runtime → correct execution.

### Test 7.10: Version Field

1. Build a blob and config struct in Python.
2. In the C test harness, verify the version field at offset 0 matches the expected version number.

## Expected Results

- Every struct's sizeof and field offsets are identical between C and Python.
- Round-trip serialization produces matching field values in both endianness variants.
- Variable-length data, nested structs, and arrays of structs work correctly.
- The codegen tool rejects invalid struct definitions.
