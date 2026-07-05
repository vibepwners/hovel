# REQ-019: Debug Build Variant and Developer Tooling

## Status
Accepted

## Statement

picblobs SHALL support two build variants — **release** and **debug**. The release variant is the current production build shipped in the Python wheel. The debug variant adds compiler debug symbols (`-g`), a C-level PIC logging facility that emits messages via `write(2)` to stderr, and is stored only as local build artifacts (never packaged in the wheel). A separate **debug CLI** (`picblobs-debug`) SHALL be provided as a development-only tool (not shipped in the wheel) that offers disassembly and inspection features using the architecture-appropriate cross-toolchain `objdump`. The existing shipped CLI (`picblobs`) SHALL also be usable with the debug CLI's features that do not require debug symbols.

## Rationale

Developing and debugging freestanding PIC blobs is exceptionally difficult without visibility into what the code is doing at runtime or the ability to inspect the generated machine code. A structured debug build variant with logging and a dedicated developer CLI eliminates the need for ad-hoc `printf`-debugging via raw syscalls and manual `objdump` invocations, while keeping the release artifacts clean, small, and free of debug strings.

## Derives From
- VIS-001
- REQ-011

## Detailed Requirements

### Build Variants

The Bazel build SHALL support two variants, selectable via `--config`:

| Variant | Config Flag | Debug Symbols | PIC Logging | Shipped in Wheel |
|---|---|---|---|---|
| Release | `--config=linux_x86_64` (existing) | No | No (`PIC_LOG_ENABLE` undefined) | Yes |
| Debug | `--config=linux_x86_64_debug` | Yes (`-g`) | Yes (`-DPIC_LOG_ENABLE`) | No |

Debug configs SHALL be defined for every platform in `.bazelrc` following the pattern `{os}_{arch}_debug`. Debug builds SHALL use `-g` (DWARF debug info) and `-DPIC_LOG_ENABLE` in addition to the existing freestanding flags. The optimization level SHALL remain `-Os` in both variants — debug and release produce identical optimization, differing only in debug symbols and logging.

### Debug .so Storage

Debug `.so` files SHALL be staged to a separate directory tree:

```
bazel-out/  (or a dedicated debug staging directory)
  debug/
    {os}/{arch}/{blob_type}.so
```

They SHALL NOT be copied into `python/picblobs/_blobs/` or included in the wheel.

### PIC Logging Facility (C-side)

A logging macro system SHALL be provided in `src/include/picblobs/log.h`:

1. **`PIC_LOG(fmt, ...)`** — When `PIC_LOG_ENABLE` is defined (debug builds), expands to a format-and-write sequence that outputs the formatted message to stderr (file descriptor 2) via `sys_write()`. When `PIC_LOG_ENABLE` is not defined (release builds), expands to nothing (zero code generation).
2. The logging facility SHALL use the existing per-architecture `sys_write()` syscall wrapper — no libc dependency.
3. Format string support SHALL include `%s` (string), `%d` (signed decimal integer), and `%x` (unsigned hexadecimal integer). A minimal `printf`-style formatter SHALL be implemented in `log.h` (or a companion `log.c`) that is compiled only when `PIC_LOG_ENABLE` is defined.
4. All log format strings, formatting code, and logging infrastructure SHALL be completely eliminated by the preprocessor in release builds — no string literals, no function bodies, no data sections.

### Debug CLI (`picblobs-debug`)

A separate CLI entry point SHALL be provided as `tools/debug_cli.py` (or equivalent), invocable as `python -m picblobs.debug` during development. This CLI SHALL NOT be registered as a console script in the wheel and SHALL NOT be shipped in the published package.

The debug CLI SHALL support all commands from the main `picblobs` CLI (list, info, extract, run, verify) plus the following debug-specific commands:

#### `disasm` — Disassemble a Function

```
picblobs-debug disasm <blob_type> <os:arch> --function <name> [--so <path>]
```

1. Locates the debug `.so` for the given blob type and target.
2. Resolves the architecture-appropriate cross-toolchain `objdump` (e.g., `aarch64-linux-gnu-objdump`).
3. Invokes `objdump -d -S --disassemble=<function_name>` to produce disassembly with interleaved source for the named function.
4. Outputs the disassembly to stdout.
5. If no `--function` is given, lists all available function symbols from the `.symtab`.
6. This command requires debug `.so` files with `-g` symbols. If only release `.so` files are available, it SHALL print an error instructing the user to build with the debug config.

#### `listing` — Full Disassembly Listing

```
picblobs-debug listing <blob_type> <os:arch> [--so <path>]
```

1. Produces a complete disassembly of the entire `.so` file using `objdump -d -S`.
2. With debug `.so` files: includes interleaved C source lines.
3. With release `.so` files: produces disassembly without source interleaving (still functional, just less informative).

### Main CLI Compatibility

The `listing` command (full disassembly without `--function`) SHALL also be available in the shipped `picblobs` CLI, operating on release `.so` files from the wheel. It will produce disassembly without source interleaving since release `.so` files lack debug symbols. This requires the cross-toolchain `objdump` to be installed on the host.

### Toolchain `objdump` Resolution

The debug CLI SHALL resolve the correct `objdump` binary for each architecture:

| Architecture | objdump Binary |
|---|---|
| x86_64 | `x86_64-linux-gnu-objdump` or `objdump` |
| i686 | `i686-linux-gnu-objdump` |
| aarch64 | `aarch64-linux-gnu-objdump` |
| armv5_arm / armv5_thumb | `arm-linux-gnueabi-objdump` |
| mipsel32 | `mipsel-linux-gnu-objdump` |
| mipsbe32 | `mips-linux-gnu-objdump` |
| s390x | `s390x-linux-gnu-objdump` |

The CLI SHALL first check for the Bazel-provisioned Bootlin toolchain's `objdump` in the Bazel output tree, falling back to system-installed cross-toolchain binaries.

### Build Integration

The `picblobs build` command (or equivalent `tools/stage_blobs.py`) SHALL be extended with a `--debug` flag:

```
picblobs build --debug
```

This builds all blobs with the debug config and stages them to the debug output directory. A plain `picblobs build` continues to produce release blobs only.

## Acceptance Criteria

1. `picblobs build` produces release `.so` files identical to the current build output.
2. `picblobs build --debug` produces debug `.so` files with DWARF debug info and `PIC_LOG_ENABLE` active.
3. Debug `.so` files are not included in the wheel produced by `uv build`.
4. PIC logging macros produce `write(2)` calls in debug builds and zero code in release builds.
5. `picblobs-debug disasm hello linux:x86_64 --function blob_main` outputs the disassembly of `blob_main` with interleaved C source.
6. `picblobs-debug disasm hello linux:x86_64` (no `--function`) lists all function symbols.
7. `picblobs-debug listing hello linux:aarch64` produces a full disassembly of the debug `.so`.
8. `picblobs listing hello linux:x86_64` (main CLI) produces a full disassembly of the release `.so` without source interleaving.
9. All existing `picblobs` CLI commands (list, info, extract, run, verify) work identically in `picblobs-debug`.
10. The debug CLI is not registered as a console script in `pyproject.toml` and is not included in the published wheel.

## Related Decisions
- ADR-024

## Verified By
- TEST-010
