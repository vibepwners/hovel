# ADR-004: C Headers as Single Source of Truth for Config Structs

## Status
Accepted

## Context

Config structs are the interface between compiled C blobs and the Python API. Both sides must agree exactly on the struct layout (field order, field sizes, packing, endianness). There needs to be a single source of truth to prevent drift.

## Decision

The C config header files SHALL be the single source of truth for config struct definitions. A build-time code generation tool SHALL parse the C headers (using pycparser or equivalent) and emit Python `ctypes.Structure` subclasses that mirror the C structs exactly.

## Alternatives Considered

- **Python as source of truth**: Define structs in Python, generate C headers. Rejected: expressing C-level concerns (packing, alignment, bitfields, GCC attributes) in Python is awkward. The structs exist to be consumed by C code; C is their natural home.
- **Neutral schema (protobuf, JSON Schema, Cap'n Proto)**: Define structs in a third language, generate both C and Python. Rejected: adds a third language and build dependency. Protobuf/Cap'n Proto impose their own encoding formats which don't match the raw-memory layout needed here. JSON Schema can describe fields but not binary packing.
- **Manual mirroring**: Define structs in both C and Python manually, with tests to verify parity. Rejected: manual mirroring is exactly the fragile process we want to avoid. Works initially but drifts over time.
- **Binary introspection at runtime**: Ship the ELF with DWARF debug info; Python parses DWARF to discover struct layouts. Rejected: heavyweight, fragile, and overkill.

## Consequences

- The codegen tool must handle GCC extensions (`__attribute__((packed))`) and fixed-width types.
- The codegen tool is a build-time dependency (Python + pycparser), not a runtime dependency.
- Config struct changes require only editing the C header; the Python side regenerates automatically.
- The codegen tool must be tested to ensure correctness (round-trip tests between C and Python representations).

## Related Requirements
- REQ-014
