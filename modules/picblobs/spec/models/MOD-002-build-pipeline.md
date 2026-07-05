# MOD-002: Build Pipeline

## Status
Accepted (amended Sprint 1)

## Description

This model describes the complete build pipeline from C source to staged Python package. The pipeline produces cross-compiled `.so` shared objects for all target platforms, cross-compiled test runners, and stages both into the Python package tree.

## Pipeline Stages

### Stage 1: Toolchain Provisioning

- **Trigger**: First Bazel build or cache miss.
- **Action**: Bazel fetches Bootlin cross-compiler archives from toolchains.bootlin.com via the `bootlin` module extension.
- **Output**: Extracted toolchain directories in Bazel's external repository cache, with generated `cc_toolchain_config` and `BUILD.bazel` per toolchain.
- **Artifacts**: GCC 13.3.0 binaries, binutils, headers for each architecture.

### Stage 2: C Compilation

- **Input**: C source files (syscall wrappers, blob logic), inline assembly headers, C headers.
- **Action**: For each target platform (OS/arch combination), the corresponding Bootlin GCC cross-compiler compiles C source.
- **Flags**: `-ffreestanding -nostdlib -nostartfiles -fno-builtin -fno-stack-protector -fPIC -ffunction-sections -fdata-sections -Os -Wall -Werror` plus architecture-specific flags.
- **Output**: Object files (`.o`) archived into `.a` per platform.

### Stage 3: Linking

- **Input**: Archive (`.a`) from Stage 2, custom linker script (`blob.ld`).
- **Action**: GCC links via genrule (not `cc_binary`, which injects `-Wl,-S`) with `-shared -nostdlib -nostartfiles -Wl,--whole-archive`.
- **Output**: A shared object (`.so`) with controlled section layout.
- **Sections**: `.text.pic_trampoline` (MIPS self-relocation), `.text.pic_entry` (entry point), `.text.pic_code` (helpers), `.text` (remaining), `.rodata`, `.got`, `.data`, `.bss`, `.config`.
- **Symbols**: `__blob_start`, `__blob_end`, `__config_start`, `__got_start`, `__got_end`.
- **Key**: `.symtab` is preserved for build-time extraction.

### Stage 4: Release Extraction

- **Input**: Staged `.so` blobs from Stage 3.
- **Action**: `tools/extract_release.py` reads linker symbols and allocated sections with pyelftools.
- **Output**: Runtime `.bin` files, JSON sidecars, and `manifest.json`.

### Stage 5: Runner Compilation

- **Input**: Test runner C source (`tests/runners/linux/runner.c`), per-architecture `_start` entry stubs.
- **Action**: Cross-compile the test runner for each target architecture using the same Bootlin toolchains. Linked as static freestanding binary via genrule.
- **Output**: One runner binary per OS/architecture combination.

### Stage 6: Staging

- **Input**: All `.so` blobs and runner binaries from Stages 3 and 5.
- **Action**: `tools/stage_blobs.py` iterates over all platform configs,
  runs `bazel build --config={config}` for each, copies outputs into the
  Python package tree, builds `ul_exec` verifier ELFs from the same
  Bootlin toolchains, then regenerates release sidecar artifacts.
- **Output directory structure**:
  ```
  python/picblobs/
    _blobs/{os}/{arch}/{blob_type}.so
    blobs/{blob_type}.{os}.{arch}.bin
    blobs/{blob_type}.{os}.{arch}.json
    manifest.json
  python_cli/picblobs_cli/
    _runners/{os}/{arch}/runner
    _test_binaries/ul_exec/linux/{arch}/hello_et_exec
  ```

### Stage 7: Config Codegen (future)

- **Input**: C config header files (`config/*.h`).
- **Action**: pycparser-based codegen tool parses headers and emits Python `ctypes.Structure` subclasses.
- **Output**: `picblobs/_generated/configs.py`.

### Stage 8: Wheel Build

- **Input**: Complete Python packages with sidecar blob artifacts, runners, and generated code.
- **Action**: `uv build` produces a wheel.
- **Output**: `picblobs-X.Y.Z-py3-none-any.whl`.

## Parallelism

Stages 2-3 are per-platform and executed sequentially per platform config
by `stage_blobs.py` (Bazel parallelizes within each config). Stage 5 runs
alongside Stage 3 in the same Bazel invocation. The `ul_exec` verifier
fixtures are built immediately after the corresponding Linux `ul_exec`
blob while the Bootlin toolchain is available. Stage 7 is independent.

## Build Matrix Size

- 8 Linux platforms (x86_64, i686, aarch64, armv5_arm, armv5_thumb, s390x, mipsel32, mipsbe32)
- 7 FreeBSD platforms (all except s390x, deferred per ADR-023) + 2 Windows = 17 total
- 6 blob types per platform = 102 total blobs at full build-out
- 1 runner per platform = 17 runners at full build-out
- Total artifacts per full build: blobs + runners + 1 wheel

## Code Generation

The build pipeline relies on generated artifacts produced by `tools/generate.py` from the canonical registry `tools/registry.py` (see ADR-022). Generated artifacts include:

- **C headers**: `src/include/picblobs/arch.h`, `syscall.h`, `picblobs.h`, and all `sys/*.h` wrappers.
- **Bazel config**: `platforms/BUILD.bazel`, `toolchains/BUILD.bazel`, `.bazelrc` platform configs.
- **Test runners**: `tests/runners/{os}/runner.c`.

All generated files are committed to git. CI enforces freshness via `tools/generate.py --check`.

## Derives From
- REQ-011
- REQ-012
- REQ-013
- REQ-017
