# ADR-021: Embedded Cross-Compiled Test Runners

## Status
Accepted

## Context

The test runner is a freestanding C program that mmaps a blob into RWX memory and jumps to byte zero. To run a blob for aarch64 on an x86_64 host, both the runner and the blob must be aarch64 binaries — QEMU user-static emulates the entire process, not just the blob.

Previously, runners were compiled only for the host architecture and lived in `bazel-bin/`. This meant `picblobs run hello linux:armv5_arm` failed with "Invalid ELF image for this architecture" because it tried to run an x86_64 runner under qemu-arm-static.

## Decision

Test runners SHALL be cross-compiled for every target architecture using the same Bootlin toolchains as the blobs, and SHALL be staged into the Python package tree alongside the blobs.

Layout:
```
picblobs/_blobs/{os}/{arch}/{blob_type}.so
picblobs/_runners/{os}/{arch}/runner
```

The `picblobs build` CLI command (backed by `tools/stage_blobs.py`) SHALL build both blobs and runners for all platform configs in a single invocation, iterating over each `--config` and running `bazel build` for both the blob and runner targets.

The `picblobs.runner.find_runner()` function SHALL search for runners in this order:
1. Embedded in package: `picblobs/_runners/{runner_type}/{arch}/runner`
2. Fallback to Bazel build tree: `bazel-bin/tests/runners/{runner_type}/runner.bin`

The runner binary is compiled as a static freestanding executable via genrule (not `cc_binary`, which injects `-Wl,-S` and strips sections on some architectures). It includes per-architecture `_start` entry stubs in top-level `__asm__` blocks for x86_64, i686, aarch64, ARM, and MIPS.

## Alternatives Considered

- **Host-only runner + extract-and-patch**: Run the blob natively via ctypes/mmap. Works for host arch but doesn't test the real execution model (mmap → jump) and doesn't support cross-arch.
- **Separate runner per OS type only**: One runner binary, run under QEMU for the right arch. This is what we do, but the runner itself must be compiled for the target arch.

## Consequences

- `picblobs build` produces 12 artifacts per blob type (6 `.so` + 6 runners for Linux).
- The wheel contains runner binaries as data files (they're cross-compiled, not host-native).
- `picblobs run hello linux:armv5_arm` works out of the box after `picblobs build`.
- Adding a new architecture requires: Bootlin toolchain registration, `_start` stub in runner.c, platform config in `stage_blobs.py`.

## Related Requirements
- ADR-010 (QEMU testing strategy)
- ADR-019 (runner/debug facility)

## Supersedes
- None
