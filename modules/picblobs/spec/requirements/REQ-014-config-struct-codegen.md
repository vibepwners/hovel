# REQ-014: Config Struct Definition and Python Codegen

## Status
Accepted

## Statement

Each blob type SHALL define its runtime configuration as a packed C struct in a header file. These C headers are the single source of truth for config layout. A build-time code generation step SHALL parse the C headers and produce Python `ctypes.Structure` subclasses that mirror the C structs exactly, ensuring the Python API can serialize config data into the exact byte layout the blob expects.

## Rationale

The config struct is the interface contract between the Python API and the compiled blob. The C side consumes the struct at runtime by dereferencing the `__config_start` symbol. The Python side must produce byte-identical representations. Making the C header authoritative and auto-generating Python bindings eliminates the risk of layout drift between the two sides. Manual mirroring of packed structs across languages is a reliable source of subtle bugs (wrong field order, wrong padding, wrong size).

## Derives From
- VIS-001

## Detailed Requirements

### C Header Conventions

Config struct headers SHALL follow these conventions:

1. **One header per blob type**: e.g., `config/alloc_jump.h`, `config/stager_tcp.h`.
2. **Packed structs**: All config structs SHALL use `__attribute__((packed))` to eliminate compiler-inserted padding. The layout is defined by field order and field sizes alone.
3. **Fixed-width types**: All fields SHALL use fixed-width integer types (`uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int32_t`, etc.) from `<stdint.h>` (provided by the freestanding compiler). No `int`, `long`, `size_t`, or other platform-dependent types.
4. **Explicit endianness documentation**: Each header SHALL document whether multi-byte fields are stored in little-endian or big-endian format. For simplicity, all config structs SHOULD use little-endian regardless of target architecture (the blob code handles byte-swapping on big-endian targets if needed). Alternatively, native-endian MAY be used if the Python API handles endian selection per target — this decision SHALL be documented in ADR-009.
5. **Variable-length trailing data**: Config structs that include variable-length data (payload bytes, file paths, pipe names) SHALL define fixed fields first, followed by a flexible array member or a documented convention that variable data is appended immediately after the fixed fields. The fixed fields SHALL include a length field for each variable-length region.
6. **No pointers**: Config structs SHALL NOT contain pointer fields. All references to variable-length data SHALL be expressed as offsets or lengths relative to the struct base.
7. **Nested structs**: Config structs MAY contain nested structs (e.g., a socket address struct). Nested structs SHALL follow the same packed/fixed-width conventions.
8. **Arrays of structs**: Config structs MAY contain arrays of sub-structs (e.g., a list of DJB2 hashes for function resolution). The array SHALL be preceded by a count field. The array elements are appended in the variable-length trailing region.

### Code Generation Tool

A Python script (the "config codegen tool") SHALL:

1. Parse the C config headers using `pycparser` or an equivalent C parsing library capable of handling GCC extensions (`__attribute__((packed))`).
2. For each config struct, emit a Python class with:
   - A `struct.pack` format string mirroring the C struct's field layout (e.g., `"<HII"` for version + two uint32 fields on a little-endian target). The endianness prefix (`<` or `>`) is selected per-target at serialization time (see ADR-009).
   - Field name constants and offset values matching the C struct.
   - Correct type mappings (e.g., `uint32_t` -> `"I"`, `uint16_t` -> `"H"`, `uint8_t` -> `"B"`).
3. For nested structs, emit the nested struct's format string first and inline it in the parent.
4. Emit helper methods on each generated class:
   - `pack(endian: str, **fields) -> bytes`: Serialize the fixed fields to bytes using `struct.pack` with the given endianness prefix.
   - `unpack(endian: str, data: bytes) -> dict`: Deserialize from bytes using `struct.unpack`.
   - `fixed_size() -> int`: Return the size of the fixed-field portion of the struct.
5. For variable-length regions, emit a builder or factory method that accepts Python data (e.g., `payload: bytes`) and produces the complete config blob (fixed fields + inline trailing variable data). The fixed fields SHALL include a length field for each variable-length region, and the variable data SHALL be appended immediately after the fixed fields in declaration order.
6. Emit an `__all__` list and type annotations compatible with static type checkers (mypy, pyright).

### Integration with Bazel

The code generation tool SHALL run as a Bazel genrule:

- Input: C config header files.
- Output: Python source file(s) containing the generated `ctypes.Structure` classes.
- The generated Python files SHALL be included in the picblobs Python package.

### Versioning

Each config struct SHALL have a `version` field (uint8 or uint16) as its first field. This allows the blob to validate that the config struct it receives matches the expected version. The Python API SHALL set this field automatically based on the blob version.

### Compatibility Policy

Config struct layout changes are governed by strict semantic versioning at the package level (REQ-017). A change to any config struct's field layout, field order, or field semantics constitutes a breaking change and SHALL require a major version bump. No runtime config version negotiation is required — consumers are expected to rebuild against the matching picblobs version.

## Acceptance Criteria

1. For every config struct defined in C, a corresponding Python `ctypes.Structure` class is auto-generated.
2. Serializing a struct in Python and deserializing it in C (or vice versa) produces identical field values — verified by round-trip tests.
3. The generated Python struct's `ctypes.sizeof()` matches the C struct's `sizeof()` for every struct.
4. The codegen tool correctly handles packed structs, nested structs, arrays of structs, and fixed-width types.
5. The codegen tool fails with a clear error if it encounters a type it cannot map (e.g., a pointer, a platform-dependent type).

## Related Decisions
- ADR-004

## Modeled By
- MOD-003

## Verified By
- TEST-007
