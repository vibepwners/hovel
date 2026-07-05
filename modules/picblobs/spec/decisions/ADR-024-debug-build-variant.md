# ADR-024: Debug Build Variant and Developer Tooling Strategy

## Status
Accepted

## Context

Developing freestanding PIC blobs is a black-box experience: the blobs run without libc, cannot call `printf`, and the release build strips debug symbols and optimizes aggressively (`-Os`). When a blob misbehaves, the developer's only recourse is to manually add raw `write(2)` syscalls, rebuild, re-test under QEMU, and manually run architecture-specific `objdump` against the `.so`. This workflow is slow and error-prone, especially for cross-architecture targets.

We need:
1. A way to add temporary logging to blob C code that compiles to nothing in release.
2. Debug-symbol-bearing `.so` files for source-level disassembly.
3. A CLI tool that automates `objdump` invocations with the correct cross-toolchain binary.

## Decision

### Two build variants: release and debug

Every platform config in `.bazelrc` gets a `_debug` counterpart (e.g., `linux_x86_64_debug`). Debug configs differ from release in three ways:

| Aspect | Release | Debug |
|---|---|---|
| Optimization | `-Os` | `-Os` |
| Debug info | (none) | `-g` (DWARF) |
| Logging macro | `PIC_LOG_ENABLE` undefined | `-DPIC_LOG_ENABLE` |

Optimization is identical in both variants. This ensures the disassembly of a debug blob reflects the same code generation as the release blob — the only differences are DWARF metadata and logging call sites. All other freestanding flags (`-ffreestanding`, `-nostdlib`, `-fPIC`, etc.) remain identical.

### Debug artifacts are local-only

Debug `.so` files are staged to a separate directory (`debug/{os}/{arch}/`) and are never copied into `python/picblobs/_blobs/` or included in the wheel. This keeps the published package small and free of debug strings.

### PIC logging via `write(2)`

A `PIC_LOG()` macro in `src/include/picblobs/log.h` uses the existing `sys_write()` syscall wrapper to write to fd 2 (stderr). In release builds, the macro expands to nothing — no strings, no code, no data. The formatter supports `%s`, `%d`, and `%x` specifiers — sufficient for debugging addresses, sizes, and status strings. The formatting implementation is compiled only under `#ifdef PIC_LOG_ENABLE` so it is fully dead-code-eliminated in release.

### Separate debug CLI, not shipped

A `picblobs-debug` CLI lives in the source tree (e.g., `tools/debug_cli.py`) and is not registered as a wheel console script. It extends the main CLI with `disasm` (per-function disassembly) and `listing` (full disassembly) commands that shell out to the cross-toolchain's `objdump`.

The `listing` command is also available in the shipped `picblobs` CLI for release `.so` files (without source interleaving), since that doesn't require debug symbols.

### Depend on toolchain `objdump`, not capstone

We shell out to architecture-specific `objdump` (e.g., `aarch64-linux-gnu-objdump`) rather than using a Python disassembler library like capstone. Rationale:
- `objdump -S` can interleave C source lines with assembly when DWARF info is present — no Python library can do this.
- The Bootlin toolchains provisioned by Bazel already include `objdump`.
- The debug CLI is a developer tool, not a user-facing feature — requiring the cross-toolchain installed is acceptable.

## Alternatives Considered

### capstone for disassembly
Pure Python, pip-installable, no toolchain dependency. However, capstone cannot interleave source lines (it doesn't read DWARF), which is the primary value of the debug disassembly feature. Rejected.

### Ship debug blobs in wheel
Would roughly double wheel size and include OPSEC-sensitive debug strings. Debug blobs are developer tools, not deployment artifacts. Rejected.

### Single CLI with `--debug-so-dir` flag
Instead of a separate `picblobs-debug` CLI, add flags to the main CLI to point at debug `.so` files. This works but clutters the shipped CLI with options that only make sense in a development environment. A separate CLI is cleaner.

## Consequences

- Every `.bazelrc` platform config needs a `_debug` twin — maintenance cost scales linearly with architectures.
- Developers must have the Bootlin cross-toolchain `objdump` available (either via Bazel or system packages) to use disassembly features.
- The `log.h` header becomes part of the blob C API — blob authors can use `PIC_LOG()` freely knowing it vanishes in release.

## Related
- REQ-019
- REQ-011 (Bazel cross-compilation)
- ADR-019 (CLI runner and debug facility — this extends it)
