# ADR-009: Native-Endian Config Structs with Per-Target Serialization

## Status
Accepted

## Context

Config structs contain multi-byte integer fields (uint16, uint32, uint64). These fields can be stored in little-endian or big-endian byte order. The config struct is serialized by Python on the host machine and deserialized by the blob on the target machine. The host and target may have different endianness (e.g., Python on x86_64 little-endian, target is mipsbe32 big-endian).

## Decision

Config structs SHALL be serialized in the **target's native endianness**. The Python API SHALL determine the target architecture's endianness from the builder's `arch` parameter and serialize multi-byte fields accordingly.

The C blob code reads config fields as native memory accesses (no byte-swapping needed at runtime). This is the simplest and fastest approach for the blob.

## Alternatives Considered

- **Always little-endian**: Simpler for Python (always pack as LE) but forces big-endian targets (mipsbe32) to byte-swap every config field at runtime. Adds code size and complexity to the blob. Rejected.
- **Always big-endian (network byte order)**: Convention in networking but same problem: little-endian targets (the majority) would need runtime byte-swapping. Rejected.
- **Self-describing format (length-value pairs, protobuf)**: Maximum flexibility but adds parsing complexity to the blob. The blob should just cast a pointer to a struct. Rejected.

## Serialization Mechanism

The Python API SHALL use `struct.pack` with explicit format strings for config serialization, **not** `ctypes.Structure`. The format string prefix selects endianness: `<` for little-endian targets, `>` for big-endian targets (mipsbe32). The endianness is a static property of each `Arch` enum member.

The auto-generated code from the config codegen tool (REQ-014) SHALL emit `struct.pack`/`struct.unpack` format strings alongside field definitions, rather than `ctypes.Structure` subclasses. This provides explicit control over byte order without relying on `ctypes` cross-endian behavior.

## Consequences

- The Python API must know each architecture's endianness and serialize accordingly. This is straightforward: the endianness is a static property of each `Arch` enum member.
- The codegen tool emits `struct.pack` format strings per config struct, with a per-target endianness prefix.
- Config struct round-trip tests must cover both endianness variants.

## Related Requirements
- REQ-014
- REQ-015
