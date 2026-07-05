# TEST-001: Build Pipeline Integrity

## Status
Accepted

## Verifies
- REQ-011
- REQ-012
- REQ-013
- REQ-018

## Goal

Demonstrate that the Bazel build pipeline produces correct, complete, and reproducible blob binaries for the entire target matrix.

## Preconditions

- Bazel and Bazelisk are installed on the build host (Linux x86_64).
- Network access is available for initial Bootlin toolchain download (or toolchains are cached).

## Procedure

### Test 1.1: Complete Build

1. Run `bazel build //blobs:all` from a clean state.
2. Verify that 96 blob binary files are produced (per REQ-018 matrix).
3. Verify that 96 metadata JSON files are produced alongside the blobs.
4. Verify that no build errors or warnings occur.

### Test 1.2: Blob Binary Properties

For each produced blob binary:

1. Verify the file is non-empty.
2. Verify the file contains no ELF header (magic bytes `\x7fELF` do not appear at offset 0).
3. Verify the file size matches the `blob_size` field in its metadata JSON.
4. Verify the `build_hash` in the metadata matches the SHA256 of the binary.

### Test 1.3: Linker Script Compliance

For each intermediate linked ELF (before extraction):

1. Verify the ELF contains the expected sections: `.text`, `.config` (at minimum).
2. Verify the ELF does NOT contain unwanted sections: `.interp`, `.dynamic`, `.plt`, `.eh_frame`.
3. Verify the symbols `__blob_start`, `__blob_end`, `__config_start` exist.
4. Verify `__config_start` is positioned after `__blob_end` (or at `__blob_end`).

### Test 1.4: Dead Code Elimination

1. Build a minimal blob (alloc-jump) and a complex blob (reflective ELF loader) for the same architecture.
2. Verify the alloc-jump blob is significantly smaller than the reflective loader.
3. Verify the alloc-jump blob does NOT contain symbols or code from the reflective loader's logic (confirming `--gc-sections` works).

### Test 1.5: Reproducibility

1. Build all blobs twice from the same commit (clean build each time).
2. Compare the SHA256 hashes of all produced binaries between the two builds.
3. All hashes SHALL match (bit-for-bit reproducibility).

### Test 1.6: Metadata Accuracy

For each blob/metadata pair:

1. Verify `target_os`, `target_arch`, and `blob_type` in metadata match the blob's position in the directory structure.
2. Verify `config_offset` is a plausible value (>= some minimum code size, <= blob_size).
3. Verify `entry_offset` is 0 (or the documented value for that blob type).

## Expected Results

- All 96 blobs build successfully.
- All binaries are flat PIC (no ELF headers, no relocations).
- Builds are bit-for-bit reproducible.
- Metadata accurately describes each blob.
