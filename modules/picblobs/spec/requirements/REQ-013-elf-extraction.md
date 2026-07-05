# REQ-013: Build-Time ELF-to-Blob Extraction via pyelftools

## Status
Accepted (amended — runtime extraction removed; extraction is build-time only)

## Statement

picblobs SHALL use pyelftools during the build/release pipeline to extract flat PIC blob code from `.so` shared objects into `.bin` files with JSON sidecar metadata. Runtime package code SHALL load only those sidecar artifacts and SHALL NOT parse `.so` files.

## Rationale

Keeping ELF parsing in the build pipeline makes installed packages deterministic, removes pyelftools from runtime dependencies, and gives source checkouts the same blob-loading behavior as wheels.

## Derives From
- VIS-001

## Detailed Requirements

### Extraction Process

The `tools/extract_release.py` extraction process SHALL:

1. Open the `.so` file and parse it as an ELF via `elftools.elf.elffile.ELFFile`.
2. Locate the `.symtab` section. Raise `ValueError` if absent.
3. Find symbols `__blob_start`, `__blob_end`, `__config_start`. Raise `ValueError` if any is missing.
4. Read bytes from all `SHF_ALLOC` sections whose `sh_addr` falls within `[__blob_start, __blob_end)`.
5. For `SHT_NOBITS` sections (`.bss`), emit zero bytes.
6. Skip non-allocated sections (`.symtab`, `.strtab`, `.shstrtab`).
7. Write `{blob_type}.{os}.{arch}.bin` and `{blob_type}.{os}.{arch}.json`.

### BlobData Fields

| Field | Type | Description |
|---|---|---|
| `code` | `bytes` | Flat code bytes from `__blob_start` to `__blob_end` |
| `config_offset` | `int` | `__config_start - __blob_start` |
| `entry_offset` | `int` | Entry point offset (0) |
| `blob_type` | `str` | Blob type identifier |
| `target_os` | `str` | Target operating system |
| `target_arch` | `str` | Target architecture |
| `sha256` | `str` | SHA-256 hex digest of `code` |
| `sections` | `dict` | Section name → (offset, size) for allocated sections |

### Path Convention

Build-time staged `.so` files are stored at:

```
python/picblobs/_blobs/{os}/{arch}/{blob_type}.so
```

Runtime sidecar artifacts are stored at:

```
python/picblobs/blobs/{blob_type}.{os}.{arch}.bin
python/picblobs/blobs/{blob_type}.{os}.{arch}.json
```

### Caching

`picblobs.get_blob()` caches sidecar-loaded `BlobData` results via `functools.lru_cache`. Repeated calls for the same blob return the same `BlobData` instance without re-reading the `.bin` or `.json` files.

## Acceptance Criteria

1. `tools/extract_release.py` correctly reads `.so` files produced by the Bazel build pipeline.
2. Extracted `code` bytes execute correctly when loaded at any address (verified on all 6 architectures).
3. `config_offset` matches the actual `__config_start` symbol value minus `__blob_start`.
4. Non-allocated sections are not included in the extracted bytes.
5. Missing `.symtab` or required symbols raise build-time `ValueError` messages.

## Related Decisions
- ADR-007
- MOD-007 (supersedes ADR-018 runtime extraction)

## Verified By
- TEST-001
