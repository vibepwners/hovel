# ADR-019: CLI Runner and Debug Facility

## Status
Accepted

## Context

Developers working on picblobs need fast feedback when writing or modifying blob source code. The development cycle is: edit C source, build/stage blobs, run the blob, check output. The "run the blob" step requires orchestrating several pieces: loading sidecar blob bytes, writing a flat binary with an optional config struct, selecting the right C test runner, selecting the right QEMU user-static binary for the target architecture, invoking the runner, and capturing output.

Without a unified facility, developers must manually assemble these steps or write ad-hoc scripts. This slows iteration and creates friction, especially when working across multiple architectures.

## Decision

The `picblobs` CLI SHALL provide a `run` subcommand that orchestrates the full execution pipeline: sidecar blob loading, flat binary preparation, QEMU invocation of the C test runner, and output capture.

### Target Syntax

Targets use `os:arch` format with a default of `linux:x86_64`:

```
picblobs run <blob_type> [os:arch]
```

Examples:
```
picblobs run hello                           # linux:x86_64
picblobs run hello linux:aarch64             # cross-arch via QEMU
picblobs run alloc_jump freebsd:mipsel32     # FreeBSD shim runner
```

### Direct File Mode

For development with an already assembled blob file:

```
picblobs-cli run --file out.bin linux:x86_64
```

The CLI does not extract `.so` files at runtime. Developers must run
`tools/stage_blobs.py` or `tools/extract_release.py` before registry-mode
execution.

### Configuration

Config structs are passed via:
- `--config-hex DEADBEEF` — hex-encoded bytes appended at `__config_start`
- `--payload file.bin` — raw bytes read from a file

### Debug Mode

`--debug` enables verbose diagnostics printed to stderr:
- Resolved runner binary path
- Resolved QEMU binary path
- Prepared blob file path (temp file is preserved, not cleaned up)
- Full command line
- Exit code and execution duration

### Dry Run

`--dry-run` prints the command that would be executed without running it. Useful for scripting or manual debugging.

### Execution Pipeline

1. Load pre-extracted blob code and sidecar metadata via `picblobs.get_blob()`
2. Write flat binary (code + config at `config_offset`) to a temp file
3. Locate the C test runner for the target OS in `bazel-bin/tests/runners/{os}/runner`
4. Locate the QEMU user-static binary for the target architecture
5. Invoke: `qemu-{arch}-static ./runner ./blob.bin`
6. Capture stdout, stderr, exit code
7. Clean up temp files (unless `--debug`)

For native x86_64 execution, QEMU is skipped — the runner is invoked directly.

### Runner Discovery

The C test runner is located by searching `bazel-bin/tests/runners/{runner_type}/runner`. This path can be overridden with `--runner-path`.

### QEMU Binary Map

| Architecture | QEMU Binary |
|---|---|
| x86_64 | (native, no QEMU) |
| i686 | qemu-i386-static |
| aarch64 | qemu-aarch64-static |
| armv5_arm | qemu-arm-static |
| armv5_thumb | qemu-arm-static |
| mipsel32 | qemu-mipsel-static |
| mipsbe32 | qemu-mips-static |

## Alternatives Considered

- **ctypes/mmap direct execution**: Shown to work for native x86_64 (the "Hello, world!" demo), but bypasses the C test runner entirely — no config struct handling, no FreeBSD shim, no Windows mock, and no cross-architecture support. Useful for quick demos but not suitable as the test facility.
- **Shell scripts per blob**: No discoverability, no structured output, manual QEMU management. Rejected.
- **Bazel test rules only (qemu_test.bzl)**: Already exists but operates at the Bazel level — not ergonomic for interactive development. The Python CLI complements it by providing a faster feedback loop without a full Bazel rebuild cycle.

## Consequences

- Developers can run any blob with a single command.
- Cross-architecture testing requires only QEMU user-static installed on the host.
- The C test runners must be built before `picblobs run` works: `bazel build //modules/picblobs/tests/runners/...`.
- Debug mode preserves temp files in `/tmp/picblobs_*/` — developers should clean these up manually.
- The CLI depends on the `runner.py` module, which depends on `_extractor.py`, creating a clean dependency chain: CLI → runner → extractor → pyelftools → .so files.

## Related Requirements
- REQ-011 (build system)
- ADR-010 (QEMU testing strategy)
- ADR-018 (.so shipping)

## Supersedes
- None
