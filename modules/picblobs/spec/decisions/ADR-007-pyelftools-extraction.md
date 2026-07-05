# ADR-007: pyelftools for ELF-to-Blob Extraction

## Status
Superseded by ADR-018

## Context

After GCC produces a linked ELF binary (via the custom linker script), the code and data sections must be extracted into a flat binary. The extraction step must also emit metadata (section offsets, config offset, blob size, hash) for the Python introspection API.

## Decision

A Python tool built on the pyelftools library SHALL perform the ELF-to-blob extraction and metadata emission.

## Alternatives Considered

- **`objcopy -O binary`**: The standard approach for ELF-to-flat-binary conversion. Simple but provides no control over which sections to include/exclude, no metadata emission, and no validation. We need to exclude the `.config` section and emit structured metadata. Rejected as the sole tool, but could be used as a cross-check.
- **Custom C tool**: Write a small C program to parse ELF and extract sections. Faster than Python but requires its own build/test infrastructure. No advantage since extraction runs at build time, not runtime. Rejected.
- **LIEF (Python library)**: More feature-rich than pyelftools, supports PE and Mach-O as well. Considered but overkill: we only need to read ELF sections and symbols, which pyelftools handles well. LIEF is also a larger dependency. Rejected for v1.
- **llvm-objcopy with response file**: Could handle section selection but still can't emit structured metadata. Rejected.

## Consequences

- pyelftools is a build-time Python dependency (not shipped in the wheel).
- The extraction tool is a Python script, which fits naturally into the Bazel genrule ecosystem (Python is available on the build host).
- The tool can be tested independently by constructing minimal ELF test fixtures.
- If pyelftools proves too slow for the 96-blob matrix, parallelization (Bazel runs extractions in parallel by default) or caching will mitigate.

## Related Requirements
- REQ-013
