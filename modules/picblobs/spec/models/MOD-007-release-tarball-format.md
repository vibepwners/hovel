# MOD-007: Release Format Specification

## Status
Draft

## Description

This specification defines the **picblobs release structure** — a canonical directory layout of pre-extracted flat binary blobs with structured JSON metadata. This layout is the single source of truth for all release vehicles: the Python wheel (PyPI), the gzip tarball, and the zstd tarball.

All three vehicles package the same content in the same layout. The Python `picblobs` package reads the manifest and sidecar JSON at runtime instead of performing ELF extraction. This eliminates pyelftools as a runtime dependency and unifies the data format across all consumers.

## Design Principles

1. **One layout, multiple vehicles.** The release structure is defined once. The wheel, `.tar.gz`, and `.tar.zst` are identical in content — only the outer container differs.
2. **Self-contained.** The manifest and sidecar files carry all information needed to use any blob. No ELF parser, no external registry, no language-specific tooling required.
3. **Flat.** All blob artifacts live in a single `blobs/` directory. The manifest is the index; the filesystem is a content store.
4. **Manifest-driven.** Consumers always start from `manifest.json`. Filenames are human-readable but the manifest is the API contract.
5. **Sidecar metadata.** Per-blob details (config struct layout, section map, hash) live in a `.json` file adjacent to the `.bin` file, not in the top-level manifest. The manifest stays small; consumers read only the metadata they need.
6. **Stable schema.** The manifest declares a `schema_version`. Breaking changes increment this version. Additive changes do not.

## Canonical Release Structure

All release vehicles share this directory layout:

```
manifest.json                          # Catalog + architecture table
blobs/
  hello.linux.x86_64.bin               # Flat binary blob
  hello.linux.x86_64.json              # Sidecar metadata
  hello.linux.aarch64.bin
  hello.linux.aarch64.json
  hello.windows.x86_64.bin
  hello.windows.x86_64.json
  nacl_client.linux.mipsel32.bin
  nacl_client.linux.mipsel32.json
  ul_exec.linux.x86_64.bin
  ul_exec.linux.x86_64.json
  ...
```

This structure is embedded verbatim in each release vehicle as described in [Release Vehicles](#release-vehicles).

### Filename Convention

Blob files use dot-delimited naming:

```
{type}.{os}.{arch}.bin      # flat binary
{type}.{os}.{arch}.json     # sidecar metadata
```

**Invariant:** The characters `.` and `/` SHALL NOT appear in any `type`, `os`, or `arch` identifier. This ensures filenames are unambiguously parseable. The canonical identifiers are defined by the `catalog` and `architectures` sections of the manifest.

Filenames are derived from the triple `(type, os, arch)` for human convenience. However, the manifest and sidecar JSON are the authoritative source of metadata -- consumers SHOULD NOT parse filenames to extract semantics.

## Manifest Schema (`manifest.json`)

The manifest is the entry point for all consumers. It provides:

1. Schema and package version metadata
2. An architecture reference table (bits, endianness, GCC triple)
3. A catalog of blob types with platform support matrices and config struct presence

### Top-Level Structure

```json
{
  "schema_version": 1,
  "picblobs_version": "0.1.6",
  "architectures": { ... },
  "catalog": { ... }
}
```

### Field: `schema_version`

- **Type:** integer
- **Required:** yes
- **Description:** Version of this manifest schema. Consumers MUST check this field and refuse to process manifests with an unrecognized schema version. Incremented only for breaking changes (field removals, semantic changes). Additive fields (new keys in existing objects) do not increment the schema version.

### Field: `picblobs_version`

- **Type:** string (semver)
- **Required:** yes
- **Description:** Version of the picblobs release. Matches the version in `pyproject.toml` and the PyPI wheel.

### Section: `architectures`

A map of architecture identifiers to their properties. This section allows consumers to understand the target architecture without hardcoding platform knowledge.

```json
"architectures": {
  "x86_64": {
    "bits": 64,
    "endian": "little",
    "gcc_triple": "x86_64-buildroot-linux-gnu"
  },
  "i686": {
    "bits": 32,
    "endian": "little",
    "gcc_triple": "i686-buildroot-linux-gnu"
  },
  "aarch64": {
    "bits": 64,
    "endian": "little",
    "gcc_triple": "aarch64-buildroot-linux-gnu"
  },
  "armv5_arm": {
    "bits": 32,
    "endian": "little",
    "gcc_triple": "arm-buildroot-linux-gnueabi"
  },
  "armv5_thumb": {
    "bits": 32,
    "endian": "little",
    "gcc_triple": "arm-buildroot-linux-gnueabi"
  },
  "armv7_thumb": {
    "bits": 32,
    "endian": "little",
    "gcc_triple": "arm-buildroot-linux-gnueabihf"
  },
  "mipsel32": {
    "bits": 32,
    "endian": "little",
    "gcc_triple": "mipsel-buildroot-linux-gnu"
  },
  "mipsbe32": {
    "bits": 32,
    "endian": "big",
    "gcc_triple": "mips-buildroot-linux-gnu"
  },
  "s390x": {
    "bits": 64,
    "endian": "big",
    "gcc_triple": "s390x-buildroot-linux-gnu"
  }
}
```

#### Architecture Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bits` | integer | yes | Pointer width: 32 or 64. Determines the size of `uintptr` fields in config structs. |
| `endian` | string | yes | Byte order: `"little"` or `"big"`. Determines byte order for all multi-byte fields in config structs and in the blob's runtime data. |
| `gcc_triple` | string | yes | GCC target triple for the cross-compilation toolchain. Provides an unambiguous machine-readable identifier that consumers can map to their own platform conventions (Rust target triples, Go GOARCH, LLVM triples, etc.). |

**Design note:** Architecture-internal traits (`needs_got_reloc`, `uses_mmap2`, etc.) are intentionally excluded. These are implementation details of the blob's syscall layer, not properties a consumer needs to serialize configs or select blobs. Consumers that need to make loader-level decisions (e.g., whether to set up GOT relocation) should consult the picblobs documentation, not the manifest.

### Section: `catalog`

A map of blob type identifiers to their descriptions and platform support matrices.

```json
"catalog": {
  "hello": {
    "description": "Minimal hello-world syscall test",
    "has_config": false,
    "platforms": {
      "linux": ["x86_64", "i686", "aarch64", "armv5_arm", "armv5_thumb", "armv7_thumb", "mipsel32", "mipsbe32", "s390x"],
      "windows": ["x86_64", "i686", "aarch64"]
    }
  },
  "ul_exec": {
    "description": "Userland ELF reflective loader",
    "has_config": true,
    "platforms": {
      "linux": ["x86_64", "i686", "aarch64", "armv5_arm", "armv5_thumb", "armv7_thumb", "mipsel32", "mipsbe32", "s390x"]
    }
  },
  "nacl_client": {
    "description": "NaCl encrypted TCP client (raw syscalls)",
    "has_config": false,
    "platforms": {
      "linux": ["x86_64", "i686", "aarch64", "armv5_arm", "armv5_thumb", "armv7_thumb", "mipsel32", "mipsbe32", "s390x"]
    }
  }
}
```

#### Catalog Entry Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | yes | One-line human-readable description of the blob type. |
| `has_config` | boolean | yes | Whether blobs of this type expect a config struct to be written at `config_offset`. When `false`, the blob requires no runtime configuration. When `true`, the per-blob sidecar JSON contains a `config` object describing the struct layout. |
| `platforms` | object | yes | Map of OS name to list of architecture names. Each `(os, arch)` pair corresponds to exactly one `.bin` + `.json` pair in the `blobs/` directory. All architecture names MUST exist as keys in the top-level `architectures` section. |

#### Invariants

- For every `(os, arch)` pair listed under a catalog entry's `platforms`, there SHALL exist files `blobs/{type}.{os}.{arch}.bin` and `blobs/{type}.{os}.{arch}.json` in the archive.
- For every `.bin` file in `blobs/`, there SHALL exist a corresponding catalog entry and platform listing in the manifest.
- The manifest and the `blobs/` directory MUST be consistent -- no orphan files, no missing files.

## Sidecar Schema (`blobs/{type}.{os}.{arch}.json`)

Each blob has a sidecar JSON file containing its exact binary properties. This is the file a consumer reads to understand how to use the blob.

### Example: Blob Without Config

```json
{
  "type": "hello",
  "os": "linux",
  "arch": "x86_64",
  "size": 176,
  "entry_offset": 0,
  "config_offset": 176,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sections": {
    ".text": { "offset": 0, "size": 144, "perm": "rx" },
    ".rodata": { "offset": 144, "size": 16, "perm": "r" },
    ".config": { "offset": 176, "size": 0, "perm": "rw" }
  },
  "config": null
}
```

### Example: Blob With Config

```json
{
  "type": "ul_exec",
  "os": "linux",
  "arch": "x86_64",
  "size": 7960,
  "entry_offset": 0,
  "config_offset": 7944,
  "sha256": "...",
  "sections": {
    ".text": { "offset": 0, "size": 7200, "perm": "rx" },
    ".rodata": { "offset": 7200, "size": 512, "perm": "r" },
    ".data": { "offset": 7712, "size": 64, "perm": "rw" },
    ".bss": { "offset": 7776, "size": 168, "perm": "rw" },
    ".config": { "offset": 7944, "size": 16, "perm": "rw" }
  },
  "config": {
    "endian": "little",
    "fixed_size": 20,
    "fields": [
      { "name": "elf_size",   "type": "u32", "offset": 0  },
      { "name": "argc",       "type": "u32", "offset": 4  },
      { "name": "argv_size",  "type": "u32", "offset": 8  },
      { "name": "envp_count", "type": "u32", "offset": 12 },
      { "name": "envp_size",  "type": "u32", "offset": 16 }
    ],
    "trailing_data": [
      { "name": "elf_data",  "length_field": "elf_size"  },
      { "name": "argv_data", "length_field": "argv_size" },
      { "name": "envp_data", "length_field": "envp_size" }
    ]
  }
}
```

### Example: 32-bit Big-Endian Blob With Config

```json
{
  "type": "ul_exec",
  "os": "linux",
  "arch": "mipsbe32",
  "size": 67584,
  "entry_offset": 0,
  "config_offset": 67568,
  "sha256": "...",
  "sections": {
    ".text": { "offset": 0, "size": 65536, "perm": "rx" },
    ".rodata": { "offset": 65536, "size": 1024, "perm": "r" },
    ".got": { "offset": 66560, "size": 512, "perm": "rw" },
    ".data": { "offset": 67072, "size": 256, "perm": "rw" },
    ".bss": { "offset": 67328, "size": 240, "perm": "rw" },
    ".config": { "offset": 67568, "size": 16, "perm": "rw" }
  },
  "config": {
    "endian": "big",
    "fixed_size": 20,
    "fields": [
      { "name": "elf_size",   "type": "u32", "offset": 0  },
      { "name": "argc",       "type": "u32", "offset": 4  },
      { "name": "argv_size",  "type": "u32", "offset": 8  },
      { "name": "envp_count", "type": "u32", "offset": 12 },
      { "name": "envp_size",  "type": "u32", "offset": 16 }
    ],
    "trailing_data": [
      { "name": "elf_data",  "length_field": "elf_size"  },
      { "name": "argv_data", "length_field": "argv_size" },
      { "name": "envp_data", "length_field": "envp_size" }
    ]
  }
}
```

Note: The `config.endian` is `"big"` here, matching the target architecture. A consumer on a little-endian host MUST byte-swap multi-byte fields when serializing the config struct.

### Sidecar Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | Blob type identifier. Matches the catalog key. |
| `os` | string | yes | Target operating system. |
| `arch` | string | yes | Target architecture. Key into the manifest `architectures` table. |
| `size` | integer | yes | Size of the `.bin` file in bytes. This is the extracted code region from `__blob_start` to `__blob_end`. |
| `entry_offset` | integer | yes | Byte offset of the entry point within the `.bin` file. Currently always `0` for all blobs (entry is at the start). Reserved for future use. |
| `config_offset` | integer | yes | Byte offset where the config struct begins, relative to the start of the `.bin` file. Corresponds to `__config_start - __blob_start` in the ELF. For blobs without config, this equals `size` (config region is zero-length at the end). |
| `sha256` | string | yes | SHA-256 hex digest of the `.bin` file contents. For integrity verification. |
| `sections` | object | yes | Map of section names to their location and permissions within the `.bin`. See [Section Entry Fields](#section-entry-fields). |
| `config` | object or null | yes | Config struct schema. `null` if the blob does not use a config struct. See [Config Schema](#config-schema). |

### Section Entry Fields

Each entry in the `sections` object describes a contiguous region within the flat binary.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `offset` | integer | yes | Byte offset from the start of the `.bin` file. |
| `size` | integer | yes | Size in bytes. May be `0` for empty sections. |
| `perm` | string | yes | Memory permission hint. One of: `"r"` (read-only), `"rx"` (read-execute), `"rw"` (read-write). |

#### Standard Sections

| Section | Typical Permission | Content |
|---------|-------------------|---------|
| `.text` | `rx` | Executable code (entry point, functions, trampolines) |
| `.rodata` | `r` | Read-only data (strings, constant tables) |
| `.got` | `rw` | Global Offset Table (present on MIPS, some 32-bit arches) |
| `.data` | `rw` | Initialized writable data |
| `.bss` | `rw` | Zero-initialized data (filled with `0x00` in the `.bin` file) |
| `.config` | `rw` | Config struct region (written by consumer at runtime) |

Not all sections are present in every blob. A section is included in the `sections` map if and only if it has non-zero allocation in the linked ELF. The `.config` section is always present (with `size: 0` if the blob has no config).

Sections appear in memory-layout order (ascending by `offset`). They are contiguous and non-overlapping. The last section's `offset + size` equals the blob `size` (or `config_offset` for the region before `.config`).

### Config Schema

When `config` is non-null, it describes the binary layout of the configuration struct that must be written at `config_offset` before the blob is executed.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `endian` | string | yes | Byte order for multi-byte fields: `"little"` or `"big"`. Matches the target architecture's endianness. |
| `fixed_size` | integer | yes | Size in bytes of the fixed-layout header portion of the config struct. This is the minimum number of bytes that must be written at `config_offset`. |
| `fields` | array | yes | Ordered list of fields in the fixed-layout header. See [Config Field](#config-field). |
| `trailing_data` | array | no | Ordered list of variable-length data buffers that follow the fixed header. See [Trailing Data](#trailing-data). Omitted or empty array if the config is purely fixed-size. |

#### Config Field

Each entry describes one field in the config struct's fixed-size header.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Field name (from the C struct definition). |
| `type` | string | yes | Field type. See [Config Field Types](#config-field-types). |
| `offset` | integer | yes | Byte offset of this field within the config struct (relative to `config_offset`). Explicit offsets avoid ambiguity from compiler padding and alignment rules. |

#### Config Field Types

| Type | Size (bytes) | Description |
|------|-------------|-------------|
| `u8` | 1 | Unsigned 8-bit integer |
| `u16` | 2 | Unsigned 16-bit integer (endian-sensitive) |
| `u32` | 4 | Unsigned 32-bit integer (endian-sensitive) |
| `u64` | 8 | Unsigned 64-bit integer (endian-sensitive) |
| `uintptr` | 4 or 8 | Unsigned pointer-sized integer. 4 bytes when `architectures[arch].bits == 32`, 8 bytes when `bits == 64`. Endian-sensitive. |
| `bytes:N` | N | Fixed-size byte array of exactly N bytes. Not endian-sensitive. Written verbatim. Example: `"bytes:32"` for a 256-bit key. |

All multi-byte integer types use the byte order specified by `config.endian`.

#### Trailing Data

Some config structs are followed by variable-length data buffers. Each trailing data entry specifies a buffer that is appended immediately after the previous buffer (or after the fixed header for the first entry).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Buffer name (descriptive, from the C source). |
| `length_field` | string | yes | Name of the field in `fields` whose value gives the byte length of this buffer. |

Trailing data buffers are concatenated in array order, immediately following the fixed-size header. The total config payload size is: `fixed_size + sum(value of each length_field)`.

#### Config Serialization

To prepare a blob for execution, a consumer:

1. Reads the `.bin` file into a writable buffer.
2. If `config` is non-null:
   a. Serializes each field in `config.fields` at `config_offset + field.offset` using the specified type and endianness.
   b. Appends each `trailing_data` buffer sequentially starting at `config_offset + fixed_size`.
3. The prepared buffer (code + config) is ready for loading into executable memory.

## Flat Binary Production

The `.bin` files in the tarball are produced by extracting code bytes from the linked `.so` ELF files. The extraction process is implemented by `tools/extract_release.py`:

1. Parse the ELF `.so` file.
2. Read `__blob_start` and `__blob_end` symbol addresses from `.symtab`.
3. Iterate all sections with the `SHF_ALLOC` flag within the `[__blob_start, __blob_end)` range.
4. For `SHT_PROGBITS` sections: copy bytes from the ELF.
5. For `SHT_NOBITS` sections (`.bss`): emit zero bytes.
6. Write the concatenated result as the `.bin` file.

The resulting `.bin` file is a flat memory image. Loading it at any address and jumping to `entry_offset` executes the blob (assuming appropriate memory permissions and, for blobs with config, a valid config struct at `config_offset`).

This process is also equivalent to `objcopy -O binary` on the `.so` file, as the linker script ensures all allocated sections are contiguous starting at address 0.

## Scaling Characteristics

| Dimension | At 66 blobs (today) | At 10,000 blobs |
|-----------|---------------------|-----------------|
| `manifest.json` size | ~2 KB | ~50 KB (types grow slowly) |
| Files in `blobs/` | 132 (66 .bin + 66 .json) | 20,000 |
| Sidecar read per lookup | 1 small JSON file | 1 small JSON file |
| Archive size | ~1 MB | 50-200 MB (depends on blob sizes) |
| Filesystem performance | Trivial | Fine on ext4/XFS/APFS/NTFS |

The catalog in `manifest.json` grows with the number of *blob types* (tens to low hundreds), not the number of *blob instances* (types x platforms). Per-blob metadata lives in sidecars, so the manifest stays small regardless of platform matrix size.

## Consumer Workflow

### Rust `build.rs` Example

```rust
// 1. Read manifest, check schema version
let manifest: Manifest = serde_json::from_str(
    &std::fs::read_to_string("picblobs/manifest.json")?
)?;
assert_eq!(manifest.schema_version, 1);

// 2. Look up blob type in catalog
let entry = &manifest.catalog["ul_exec"];
assert!(entry.platforms["linux"].contains(&"x86_64".to_string()));

// 3. Read sidecar for target-specific details
let sidecar: BlobMeta = serde_json::from_str(
    &std::fs::read_to_string("picblobs/blobs/ul_exec.linux.x86_64.json")?
)?;

// 4. Verify integrity
let bin = std::fs::read("picblobs/blobs/ul_exec.linux.x86_64.bin")?;
assert_eq!(hex::encode(sha256(&bin)), sidecar.sha256);

// 5. Use config schema to generate struct definition or serialize at runtime
assert_eq!(sidecar.config.as_ref().unwrap().endian, "little");
```

### Go Example

```go
// 1. Read manifest
manifest := parseManifest("picblobs/manifest.json")

// 2. Find available blobs for target
for _, arch := range manifest.Catalog["hello"].Platforms["linux"] {
    fmt.Println("hello available for linux/" + arch)
}

// 3. Read sidecar + blob
meta := parseSidecar("picblobs/blobs/hello.linux.amd64.json")
blob, _ := os.ReadFile("picblobs/blobs/hello.linux.amd64.bin")

// 4. Verify
if sha256hex(blob) != meta.SHA256 {
    panic("integrity check failed")
}
```

## Release Vehicles

Three release vehicles are produced from every release. All three contain the same canonical release structure — identical `manifest.json`, identical `blobs/` directory, identical content. Only the outer container differs.

### 1. Python Wheel (`picblobs-{version}-py3-none-any.whl`)

Published to PyPI. Installed via `pip install picblobs`.

#### Wheel Layout

```
picblobs/
  __init__.py                    # Public API: get_blob, list_blobs, BlobData, etc.
  __main__.py                    # CLI entry point
  cli.py                         # CLI subcommands
  runner.py                      # QEMU execution helpers
  _extractor.py                  # BlobData construction from .bin + .json
  _qemu.py                       # QEMU binary name mapping
  _objdump.py                    # Disassembly support
  manifest.json                  # <-- Canonical release manifest
  blobs/                         # <-- Canonical release blobs
    hello.linux.x86_64.bin
    hello.linux.x86_64.json
    hello.linux.aarch64.bin
    hello.linux.aarch64.json
    ...
```

The `manifest.json` and `blobs/` directory are embedded directly inside the `picblobs` package. They are the **same files** as in the tarballs — byte-for-byte identical.

#### Python API Changes

The Python `picblobs` package reads `manifest.json` and the sidecar `.json` files at runtime to discover and load blobs. The `_extractor.py` module constructs `BlobData` objects from the `.bin` file and its sidecar JSON, rather than parsing ELF `.so` files with pyelftools.

This means:

- **pyelftools is no longer a runtime dependency.** It remains a build-time dependency (used during the release build to extract `.bin` files from `.so` ELFs and generate sidecar metadata).
- **`get_blob()`** reads `manifest.json` for discovery, then reads `blobs/{type}.{os}.{arch}.json` for metadata and `blobs/{type}.{os}.{arch}.bin` for code bytes. Results are still LRU-cached.
- **`list_blobs()`** reads `manifest.json` and enumerates the catalog's platform entries, rather than walking the `_blobs/` directory tree.
- **Runtime `.so` extraction is removed.** Development builds must run `tools/stage_blobs.py` or `tools/extract_release.py` before loading blobs through the Python API.
- **`BlobData`** is unchanged — same fields, same interface. The construction path changes from "parse ELF at runtime" to "read .bin + .json at runtime."

#### Wheel Tag

The wheel remains `py3-none-any` because the `.bin` files are cross-compiled data assets, not host-native Python extensions. The wheel is platform-independent.

#### Runners and Verifier Fixtures

Test runners (`_runners/`) and verifier-only `ul_exec` test binaries
(`_test_binaries/`) are included in the companion `picblobs-cli` wheel,
not in the `picblobs` wheel or release tarballs. They are QEMU test
harness assets and are not needed by consumers that only assemble blob
bytes.

#### Wheel-Specific Dependencies

```toml
[project]
dependencies = []  # No runtime dependencies

[project.optional-dependencies]
dev = [
    "pyelftools>=0.31",   # For tools/extract_release.py during development
    "pytest>=8.0",
    "pycparser>=2.22",
]
```

### 2. Gzip Tarball (`picblobs-{version}.tar.gz`)

Published as a GitHub release asset. The primary language-agnostic release vehicle.

#### Tarball Layout

```
picblobs-{version}/
  manifest.json
  blobs/
    hello.linux.x86_64.bin
    hello.linux.x86_64.json
    ...
```

All paths within the archive are prefixed with `picblobs-{version}/` (a single top-level directory). The contents of `manifest.json` and `blobs/` are byte-for-byte identical to those in the wheel.

Gzip is chosen as the primary compressed format for maximum portability — every platform has gzip decompression support.

#### No Runners

The tarballs do NOT include test runners. Runners are a Python/QEMU testing concern. Non-Python consumers that need to execute blobs will use their own loader.

### 3. Zstd Tarball (`picblobs-{version}.tar.zst`)

Also published as a GitHub release asset. Identical content to the `.tar.gz`, using zstd compression for better compression ratio and faster decompression.

```
picblobs-{version}/
  manifest.json
  blobs/
    ...
```

Zstd support is widespread in modern toolchains (Rust, Go, C, system `tar` on Linux/macOS). The `.tar.zst` variant is provided as a convenience for CI pipelines and build systems that prefer zstd.

### Vehicle Comparison

| Aspect | Python Wheel | `.tar.gz` | `.tar.zst` |
|--------|-------------|-----------|------------|
| Container | `.whl` (zip) | gzip tar | zstd tar |
| Published to | PyPI | GitHub Releases | GitHub Releases |
| Installed via | `pip install picblobs` | Download + extract | Download + extract |
| Contains `manifest.json` | Yes | Yes | Yes |
| Contains `blobs/` | Yes (identical) | Yes (identical) | Yes (identical) |
| Contains Python code | Yes | No | No |
| Contains test runners / verifier fixtures | No (`picblobs-cli` only) | No | No |
| Runtime dependencies | None | N/A | N/A |
| Primary consumer | Python programs | Rust, Go, C, ... | Rust, Go, C, ... |
| Wheel tag | `py3-none-any` | N/A | N/A |

### Content Identity Guarantee

The following files are **byte-for-byte identical** across all three vehicles:

- `manifest.json`
- Every `blobs/{type}.{os}.{arch}.bin`
- Every `blobs/{type}.{os}.{arch}.json`

This guarantee is enforced by the build pipeline: a single extraction step produces the canonical release structure, which is then packaged into all three vehicles. There is no separate code path for wheel vs. tarball content.

A consumer can verify this by comparing the `sha256` values in any sidecar against the corresponding `.bin` file from any vehicle — they will always match.

## Build Pipeline

The release build proceeds in three stages:

### Stage 1: Compile (Bazel)

For each platform config (`{os}:{arch}`), Bazel compiles blob sources into `.so` ELF files:

```bash
bazel build //modules/picblobs/release:full --config=linux_x86_64
bazel build //modules/picblobs/release:full --config=linux_aarch64
# ... for all platform configs
```

Output: `.so` files in `bazel-bin/src/payload/`.

### Stage 2: Extract + Generate Metadata

A release tool (Python script, run at build time) processes every `.so`:

1. **Extract flat binary.** Read ELF via pyelftools, extract bytes from `__blob_start` to `__blob_end`, write `{type}.{os}.{arch}.bin`.
2. **Generate sidecar JSON.** Compute size, config_offset, entry_offset, sha256, section map, and config struct schema. Write `{type}.{os}.{arch}.json`.
3. **Generate manifest.** Aggregate the catalog (blob types, platform matrices, has_config) and architecture table into `manifest.json`.

Config struct schemas are sourced from the registry (`tools/registry.py`), which is extended to include config struct definitions per blob type. The generator combines ELF-derived metrics (offsets, sizes) with registry-defined struct layouts to produce complete sidecar metadata.

Output: the canonical release structure (`manifest.json` + `blobs/`).

### Stage 3: Package

The canonical release structure is packaged into three vehicles:

1. **Wheel:** The `blobs/` directory and `manifest.json` are copied into the `picblobs` package tree. `hatchling` builds the wheel.
2. **`.tar.gz`:** `tar czf picblobs-{version}.tar.gz picblobs-{version}/`
3. **`.tar.zst`:** `tar --zstd -cf picblobs-{version}.tar.zst picblobs-{version}/`

All three are published as part of a single release.

### Stage Diagram

```
  Bazel (per-platform)
  ┌─────────────────┐
  │ src/payload/*.c  │
  │       ↓          │
  │  pic_blob() rule │
  │       ↓          │
  │    *.so (ELF)    │
  └────────┬─────────┘
           │
  Extract + Metadata (pyelftools, build-time only)
  ┌────────┴─────────────────────────────────┐
  │  For each .so:                           │
  │    → extract .bin (flat binary)          │
  │    → generate .json (sidecar metadata)   │
  │  Aggregate:                              │
  │    → generate manifest.json              │
  └────────┬─────────────────────────────────┘
           │
    Canonical release structure
    ┌──────┴──────┐
    │manifest.json│
    │blobs/       │
    │  *.bin      │
    │  *.json     │
    └──────┬──────┘
           │
     ┌─────┼──────────────┐
     │     │              │
     ▼     ▼              ▼
   .whl  .tar.gz      .tar.zst
  (PyPI) (GitHub)     (GitHub)
```

## Versioning

All three vehicles carry the same version (`picblobs_version`), released from the same commit and build pipeline.

`schema_version` is independent of `picblobs_version`. Schema version `1` is defined by this document. It will remain at `1` as long as changes are purely additive (new fields, new sections). A breaking change (removing fields, changing field semantics) requires schema version `2` and a new version of this specification.

## Integrity and Signing

Each sidecar contains a `sha256` field for per-blob integrity verification.

Release archives SHOULD be published with a detached checksum file:

```
picblobs-{version}.tar.gz.sha256
picblobs-{version}.tar.zst.sha256
```

The PyPI wheel has its own integrity mechanism (PyPI's built-in hash verification).

For authenticity, GitHub release attestations or detached signatures (GPG, minisign) MAY be used. The specific signing mechanism is outside the scope of this specification and depends on the release infrastructure.

## Migration from ADR-018

This specification supersedes ADR-018 ("Ship .so Files in Wheel with Runtime pyelftools Extraction"). The migration path:

1. **pyelftools moves from runtime to build-time dependency.** The wheel's `[project.dependencies]` drops pyelftools. It remains in `[project.optional-dependencies.dev]` for development use.
2. **`_blobs/` directory is replaced by `blobs/`.** The wheel ships `.bin` + `.json` pairs instead of `.so` files. The `_blobs/` directory and its `{os}/{arch}/{type}.so` layout are removed.
3. **`_extractor.py` is rewritten.** Instead of parsing ELF files, it reads `.bin` files and constructs `BlobData` from the sidecar JSON. No runtime `.so` extraction API is retained.
4. **`manifest.json` is added to the package.** `list_blobs()` reads the manifest instead of walking the directory tree.
5. **Public API changes.** `get_blob()`, `list_blobs()`, `BlobData`, and `clear_cache()` retain their signatures and semantics; the public `extract()` runtime API is removed.

## Derives From
- MOD-003 (Blob Binary Layout)
- ADR-022 (Registry-Driven Code Generation)

## Supersedes
- ADR-018 (Ship .so Files in Wheel with Runtime pyelftools Extraction)
