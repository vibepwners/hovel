# SPRINT-001: Build System Foundation + First End-to-End Blob

## Period
2026-03-21 to 2026-03-22

## Goal
Stand up the complete Bazel build infrastructure, implement the full blob pipeline from C source to Python-driven execution, and verify "Hello, world!" runs on all 6 target architectures via QEMU.

## Work Completed

### Build System (Bazel 9 / bzlmod)

- Initialized Bazel 9 project with bzlmod (`MODULE.bazel`), pinning rules_cc 0.2.17, rules_python 1.7.0, platforms 1.0.0 (ADR-016)
- Created 16 platform definitions matching REQ-018 (7 Linux + 7 FreeBSD + 2 Windows), with custom constraint values for MIPS32 (`mipsel32`, `mipsbe32`) and ARM instruction mode
- Implemented Bootlin toolchain module extension (`toolchains/bootlin.bzl`): downloads archives from toolchains.bootlin.com, generates `cc_toolchain_config` and `BUILD.bazel` inside each external repo (bypasses bzlmod path issues)
- Registered 6 Bootlin GCC 13.3.0 toolchains (x86_64, i686, aarch64, armv5, mipsel32, mipsbe32) with version 2024.05-1
- Toolchain config: `-ffreestanding -nostdlib -nostartfiles -fno-builtin -fno-stack-protector -fPIC -ffunction-sections -fdata-sections -Os -Wall -Werror`
- C lint integration: clang-tidy aspect (`--config=picblobs_lint`) + cppcheck test rule (ADR-017)
- uv wheel build rule (`bazel/uv.bzl`)
- QEMU test rule (`bazel/qemu_test.bzl`)

### Blob Pipeline

- `pic_blob()` macro in `bazel/blob.bzl`: compiles via `cc_library`, links via `genrule` with `-shared -Wl,--whole-archive` (avoids `cc_binary`'s `-Wl,-S` which strips sections)
- Custom linker script (`src/linker/blob.ld`): section ordering with 16-byte alignment, base 0, `ENTRY(_start)`, `KEEP()` directives, `__blob_start`/`__blob_end`/`__config_start`/`__got_start`/`__got_end` symbols
- Discards `.hash`, `.gnu.hash`, `.dynsym`, `.dynstr`, `.dynamic`, `.rela.*`, `.rel.*`, `.interp` — preserves `.symtab` for pyelftools
- Section placement macros (`src/include/picblobs/section.h`): `PIC_ENTRY`, `PIC_TEXT`, `PIC_RODATA`, `PIC_DATA`, `PIC_BSS`, `PIC_CONFIG`

### Syscall Infrastructure

- Raw inline syscall primitives for all 5 ISAs: x86_64, i386, aarch64, ARM, MIPS (`src/include/picblobs/syscall.h`)
- MIPS o32 6-argument syscall: allocates 32-byte stack frame for args 5-6 to avoid clobbering caller locals
- Per-OS syscall number headers: `sys/linux/nr.h` (all 6 arches), `sys/freebsd/nr.h`
- MIPS-specific: `MAP_ANONYMOUS = 0x0800` (not 0x20), `mmap2` syscall 4210 (not mmap 4090), `mmap` offset in pages not bytes
- aarch64-specific: `openat` via `AT_FDCWD` (no legacy `open` syscall)
- Wrapper functions with libc-style prototypes: `pic_read`, `pic_write`, `pic_open`, `pic_close`, `pic_lseek`, `pic_mmap`, `pic_mprotect`, `pic_munmap`, `pic_exit`, `pic_exit_group`
- Each wrapper is `static inline` in its own header — only included wrappers are compiled

### MIPS Self-Relocation (ADR-020)

- MIPS GOT entries contain link-time absolute addresses; PIC code uses GOT via `$gp`
- Trampoline at byte 0 (`.text.pic_trampoline`): uses `bal` for PC discovery, `.cpload $ra` for `$gp`, computes runtime `_start` address, passes runtime base via `$s0`, calls `_start` via `jalr $t9`
- `PIC_SELF_RELOCATE()` macro in `_start`: loads GOT bounds via `%got($gp)`, patches every entry by adding delta
- Result: `PIC_RODATA` works on all architectures — no caller register assumptions

### Test Runners

- Linux test runner (`tests/runners/linux/runner.c`): freestanding static binary, mmaps blob into RWX, jumps to byte 0
- Per-architecture `_start` entry stubs via top-level `__asm__` (x86_64, i386, aarch64, ARM, MIPS)
- MIPS `_start`: `bal`/`.cpload $ra` for `$gp`, o32 frame setup, `jalr $t9`
- Cross-compiled via genrule (not `cc_binary`) for all 6 architectures (ADR-021)
- Runners embedded in Python package at `picblobs/_runners/{os}/{arch}/runner`

### Python Package

- `picblobs._extractor`: runtime ELF section extraction via pyelftools, `BlobData` dataclass, `SHF_ALLOC`-only filtering
- `picblobs.runner`: QEMU orchestration — `find_qemu()`, `find_runner()` (searches embedded `_runners/` first), `prepare_blob()`, `run_blob()` with `--debug`/`--dry-run`
- `picblobs.cli`: subcommands `list`, `info`, `extract`, `run` (os:arch syntax, default linux:x86_64), `build`, `test`
- `picblobs.__main__`: `python -m picblobs` support
- `pyproject.toml`: pyelftools runtime dep, `[project.scripts]` entry, force-include for `_blobs/`, `_runners/`, `_generated/`
- pytest test suite: 29 tests across `test_extractor.py`, `test_runner.py`, `test_cli.py` with conftest fixtures and skip markers
- Bazel `py_test` targets with pip-managed dependencies (pytest, pyelftools)

### Build Staging

- `tools/stage_blobs.py`: iterates over all platform configs, runs `bazel build --config={config}` for blobs + runners, copies outputs into `python/picblobs/_blobs/` and `_runners/`
- `picblobs build hello`: builds and stages all 6 arches in one command
- `picblobs list`: discovers all staged blobs from the package tree

### Hello World Payload

- `src/payload/hello.c`: uses `PIC_ENTRY`, `PIC_RODATA`, `PIC_SELF_RELOCATE()`, `pic_write()`, `pic_exit_group()`
- Verified: `picblobs run hello` prints "Hello, world!" on all 6 architectures (x86_64 native, 5 others via QEMU user-static)

## Work Not Completed

- Bootlin toolchain SHA256 pins (ADR-011)
- FreeBSD and Windows platform blobs and runners
- Per-architecture `.S` assembly stubs (using inline asm for now)
- Actual blob types (alloc-jump, reflective loader, stagers)
- Config struct codegen (pycparser)
- Python builder-pattern API (REQ-015)
- CI pipeline
- armv5_thumb variant

## ADR Updates

### New Decisions

- **ADR-016**: Bazel 9 with bzlmod and Module Extensions for Project Structure
- **ADR-017**: clang-tidy and cppcheck for C Linting and Static Analysis
- **ADR-018**: Ship .so Files in Wheel with Runtime pyelftools Extraction (supersedes ADR-007)
- **ADR-019**: CLI Runner and Debug Facility
- **ADR-020**: MIPS GOT Self-Relocation via Trampoline
- **ADR-021**: Embedded Cross-Compiled Test Runners

### Amended Decisions

- **ADR-007**: Status changed to Superseded by ADR-018

### Superseded Decisions

- **ADR-007**: Build-time pyelftools extraction → replaced by runtime extraction (ADR-018)

## Other Spec Changes

- **MOD-002**: Amended — pipeline changed from 7 stages to build→link→stage→wheel; removed build-time extraction stage; added runner compilation and staging stages
- **MOD-003**: Amended — added .so section layout, MIPS trampoline, section placement macros, per-arch PIC analysis
- **REQ-013**: Amended — changed from build-time to runtime extraction; added BlobData fields, SHF_ALLOC filtering, caching

## Implementation Discoveries

- **Bazel 9 `-Wl,-S`**: `cc_binary` injects `-Wl,-S` which strips `.text`/`.rodata` sections on some architectures. Solved by using `genrule` for both blob and runner linking.
- **Bazel 9 `--whole-archive`**: Linking from `.a` archives with `-shared` requires `--whole-archive` because no entry point pulls symbols from the archive automatically.
- **MIPS `MAP_ANONYMOUS`**: MIPS Linux uses `0x0800`, not `0x20`. Caused `EBADF` from `mmap2` that was misdiagnosed as a stack argument issue.
- **MIPS `mmap` vs `mmap2`**: Syscall 4090 (`mmap`) takes a struct pointer on MIPS, not 6 register args. Must use `mmap2` (4210) with page-unit offset.
- **MIPS o32 stack clobber**: The inline syscall `sw arg5, 16($sp)` overwrites the caller's local variables at `sp+16`. Fixed by allocating a 32-byte sub-frame before storing stack args.
- **MIPS GOT relocation**: GOT entries are absolute link-time values. x86_64/aarch64 use PC-relative, i686 uses `@GOTOFF`, but MIPS has no equivalent. Solved with self-relocating trampoline using `bal` for PC discovery.
- **MIPS `$t9` convention**: `.cpload $t9` requires `$t9` to contain the function's runtime address. Blob entry has no caller to set this. Solved by `bal`-based trampoline that computes and sets `$t9`.
- **`naked` attribute**: Not supported on aarch64 and MIPS GCC. Switched to top-level `__asm__` blocks for `_start` entry stubs.
- **aarch64 `open` syscall**: aarch64 Linux has no legacy `open` (syscall 2); only `openat` (56). Fixed `pic_open()` to use `openat` with `AT_FDCWD`.
- **`@platforms//cpu:mips32`**: Does not exist in the platforms repo. Created custom `mipsel32` and `mipsbe32` constraint values.
- **`fno-stack-protector`**: Required for i686 and other 32-bit arches — GCC inserts `__stack_chk_fail_local` references that don't exist in freestanding code.

## Notes

Sprint 1 delivered a complete vertical slice: C source → Bazel cross-compilation → .so blob → Python extraction → QEMU test runner → "Hello, world!" on 6 architectures. The infrastructure is ready for implementing real blob types (alloc-jump, stagers, reflective loaders) in Sprint 2.
