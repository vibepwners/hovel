# ADR-018: Ship .so Files in Wheel with Runtime pyelftools Extraction

## Status
Superseded by MOD-007 / REQ-013 sidecar-only runtime loading

## Context

ADR-007 specified build-time extraction of flat .bin files from linked ELFs using pyelftools as a Bazel build tool. This added a build pipeline stage (Stage 4 in MOD-002), required a separate metadata JSON file per blob, and split the extraction logic between a Python build tool and the Bazel action graph.

Shipping .so files directly simplifies the pipeline: the build system produces shared objects, the Python wheel ships them as-is, and pyelftools extracts code sections at runtime when a user requests a blob.

## Decision

The build system SHALL produce shared objects (.so files) via `cc_binary` with `-shared -nostdlib -nostartfiles` and the custom linker script. These .so files SHALL be shipped directly in the Python wheel under `picblobs/_blobs/{os}/{arch}/{blob_type}.so`.

At runtime, the Python package SHALL use pyelftools to read the `.symtab` from each .so file and extract the flat code bytes between `__blob_start` and `__blob_end`. Metadata (config offset, section layout, hash) is derived from the ELF on demand rather than stored in separate JSON files.

pyelftools becomes a runtime dependency of the picblobs package.

## Alternatives Considered

- **Keep build-time extraction (ADR-007)**: Ship flat .bin + .meta.json. More complex build pipeline, but smaller wheel (no ELF overhead). Rejected: the simplification outweighs the ~200-400KB size increase across 96 blobs.
- **Use objcopy at build time**: Strip to flat binary with `objcopy -O binary`. Loses section metadata and symbol information. Rejected.
- **dlopen the .so files**: Load them as shared libraries at runtime. Not viable — they are freestanding cross-compiled blobs, not host-native libraries.

## Rationale

- Fewer build stages: removes Stage 4 (extraction) from the pipeline entirely.
- No separate metadata files: ELF headers and .symtab contain all necessary information.
- Inspectable artifacts: users and developers can examine blobs with standard ELF tools (`readelf`, `objdump`).
- Simpler Bazel rules: `pic_blob` macro produces two targets instead of three.
- Extraction logic lives in Python: easier to test, debug, and maintain.

## Consequences

- pyelftools is now a runtime dependency (not just build-time).
- Wheel size increases slightly (~2-4KB ELF overhead per .so × 96 blobs ≈ 200-400KB total).
- First access to a blob incurs extraction latency (mitigated by `lru_cache`).
- The .so files are not loadable by a dynamic linker (their `.dynamic`/`.got`/`.plt` sections are discarded by the linker script). They are opaque data files parsed by pyelftools.
- The wheel tag remains `py3-none-any` because the .so files are cross-compiled data assets, not host-native Python extensions.
- `.symtab` must be preserved in the .so (no `--strip-all` during build).

## Related Requirements
- REQ-013

## Supersedes
- ADR-007
