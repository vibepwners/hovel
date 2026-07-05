# TEST-010: Debug Build and Developer Tooling Verification

## Status
Planned

## Verifies
- REQ-019

## Test Categories

### T10.1: Build Variant Separation

1. **Release build unchanged**: `picblobs build` produces `.so` files bit-for-bit identical to pre-REQ-019 builds (no debug symbols, no log strings).
2. **Debug build produces DWARF**: `picblobs build --debug` produces `.so` files containing DWARF debug info sections (`.debug_info`, `.debug_line`, `.debug_abbrev`).
3. **Debug build enables PIC_LOG**: Debug `.so` files contain string literals from `PIC_LOG()` calls. Release `.so` files do not.
4. **Debug .so not in wheel**: `uv build` produces a wheel that contains no debug `.so` files and no files under a `debug/` directory.

### T10.2: PIC Logging Facility

1. **Log output on stderr**: Running a debug blob under QEMU produces log output on stderr (fd 2).
2. **No log in release**: Running the same blob built as release produces no log output.
3. **Zero code generation**: `objdump -d` of a release `.so` contains no references to `sys_write` calls that correspond to `PIC_LOG` macro expansion sites. (The blob may still use `sys_write` for its actual payload logic — this test checks that *logging-specific* writes are absent.)

### T10.3: Debug CLI — `disasm` Command

1. **Single function disassembly**: `picblobs-debug disasm hello linux:x86_64 --function blob_main` outputs disassembly containing the function name and assembly instructions.
2. **Source interleaving**: Output includes interleaved C source lines (lines starting with `/` or containing `.c:`).
3. **Function listing**: `picblobs-debug disasm hello linux:x86_64` (no `--function`) lists function symbols from `.symtab`.
4. **Error on release .so**: `picblobs-debug disasm` with a release `.so` (no debug info) prints an error message mentioning the debug build config.
5. **Cross-architecture**: `picblobs-debug disasm hello linux:aarch64 --function blob_main` uses `aarch64-linux-gnu-objdump` and produces AArch64 assembly.

### T10.4: Debug CLI — `listing` Command

1. **Full debug listing**: `picblobs-debug listing hello linux:x86_64` produces a complete disassembly with source interleaving.
2. **Full release listing**: `picblobs listing hello linux:x86_64` (main CLI) produces disassembly without source lines.
3. **All architectures**: `listing` works for at least x86_64, aarch64, and mipsel32 (covering different `objdump` binaries).

### T10.5: Debug CLI — Main CLI Parity

1. **All base commands work**: `picblobs-debug list`, `info`, `extract`, `run`, `verify` produce identical output to the main `picblobs` CLI.
2. **Debug run with logging**: after extracting/staging debug sidecar artifacts, `picblobs-debug run hello linux:x86_64` executes the debug blob and log output appears on stderr.

### T10.6: Toolchain Resolution

1. **Bazel toolchain preferred**: When Bazel output tree contains the Bootlin `objdump`, it is used over system `objdump`.
2. **System fallback**: When Bazel toolchain is unavailable, system-installed cross `objdump` is found.
3. **Missing toolchain error**: When neither is available, a clear error message names the expected binary.

## Test Infrastructure

- Tests in `python/tests/test_debug.py`.
- Debug build tests require `picblobs build --debug` to have been run first (or are skipped with `pytest.mark.skipif`).
- Toolchain resolution tests may mock `shutil.which` for portability.
