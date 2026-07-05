# REQ-016: Blob Metadata and Introspection API

## Status
Accepted

## Statement

picblobs SHALL expose a Python API for querying metadata about available blobs, their properties, config struct layouts, and the full OS/architecture/blob-type support matrix. This introspection API SHALL allow consumers to programmatically discover what the library supports, inspect blob internals, and generate documentation or tooling integrations without prior knowledge of the library's contents.

## Rationale

Rich metadata enables tool integration: a framework can enumerate available targets, present them in a UI, validate user selections, and generate reports — all without hardcoded knowledge of picblobs' capabilities. It also aids debugging: a consumer can inspect a blob's size, config layout, and expected config offset to diagnose assembly issues.

## Derives From
- VIS-001

## Detailed Requirements

### Support Matrix Query

The API SHALL provide:

1. `picblobs.targets() -> list[Target]` — returns the list of all supported OS/architecture combinations.
2. `picblobs.blob_types(os, arch) -> list[BlobType]` — returns the blob types available for a given target.
3. `picblobs.is_supported(os, arch, blob_type) -> bool` — checks if a specific combination is supported.

### Blob Metadata

For each blob (identified by OS, architecture, and blob type), the API SHALL expose:

1. **blob_size**: Size of the pre-compiled blob binary in bytes (excluding the config struct).
2. **config_offset**: Byte offset where the config struct is appended.
3. **entry_offset**: Byte offset of the entry point within the blob (normally 0).
4. **config_layout**: A description of the config struct's fields, including:
   - Field name.
   - Field type (as a string, e.g., "uint32_t", "uint8_t").
   - Field offset within the struct.
   - Field size in bytes.
   - Whether the field is fixed or variable-length.
5. **build_hash**: SHA256 hash of the pre-compiled blob binary for integrity verification.
6. **sections**: List of sections within the blob (name, offset, size) — from the extraction metadata.

This metadata is derived from the metadata JSON/YAML files emitted by the extraction tool (REQ-013) and the generated config struct definitions (REQ-014). It is bundled into the wheel alongside the blob binaries.

### Config Layout Introspection

The API SHALL provide:

1. `picblobs.config_layout(os, arch, blob_type) -> ConfigLayout` — returns a structured description of the config struct for a given blob.
2. The `ConfigLayout` object SHALL support:
   - Iteration over fields.
   - Lookup by field name.
   - A `total_fixed_size` property for the fixed portion of the struct.
   - A `to_dict()` method for serialization.

### Raw Blob Access

The API SHALL provide:

1. `picblobs.raw_blob(os, arch, blob_type) -> bytes` — returns the pre-compiled blob binary WITHOUT a config struct appended. This is useful for consumers who want to handle config assembly themselves.

### DJB2 Utility

The API SHALL expose the DJB2 hash utility (from REQ-006):

1. `picblobs.djb2(name: str) -> int` — computes the DJB2 hash of a string, using the same algorithm and conventions as the C implementation.
2. `picblobs.djb2_dll(name: str) -> int` — computes the DJB2 hash of a DLL name (lowercased).

## Acceptance Criteria

1. `picblobs.targets()` returns a complete and accurate list of supported targets.
2. `picblobs.blob_types(os, arch)` returns the correct blob types for each target.
3. Metadata values (blob_size, config_offset, build_hash) match the actual blob binaries.
4. Config layout introspection correctly reflects the C struct definitions.
5. `raw_blob()` returns the exact pre-compiled binary (matching the build_hash).
6. `djb2()` produces values identical to the C implementation for all test vectors.

## Verified By
- TEST-008
