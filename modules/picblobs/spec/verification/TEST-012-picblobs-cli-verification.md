# TEST-012: `picblobs-cli` Package Verification

## Status
Accepted

## Verifies
- REQ-020
- ADR-026

## Goal

Demonstrate that the `picblobs-cli` companion package is correctly
packaged, that every command in its click tree works, and that the
separation from `picblobs` is clean (the data library no longer ships
runner binaries or verifier fixtures and remains usable on its own).

## Preconditions

- A source checkout with `tools/stage_blobs.py` already executed so
  blobs live under `python/picblobs/_blobs/` and runners under
  `python_cli/picblobs_cli/_runners/`; `ul_exec` verifier ELFs live
  under `python_cli/picblobs_cli/_test_binaries/`.
- QEMU user-static binaries on `PATH` (for execution tests).

## Procedure

### Test 12.1: Package imports

1. `import picblobs_cli` succeeds in a clean subinterpreter.
2. `picblobs_cli.__version__` matches `picblobs.__version__`.
3. `picblobs_cli.cli.main` is a click command object.

### Test 12.2: Console script entry point

1. Running `picblobs-cli --help` via `subprocess` returns exit 0.
2. `--help` output lists `run`, `verify`, `build`, `list-runners`, `info`.

### Test 12.3: `list-runners`

1. `picblobs-cli list-runners` prints at least one runner for each
   `(runner_type, arch)` pair declared in REQ-018.
2. Filtering with `--os linux` limits output to linux runners only.

### Test 12.4: `build` command — alloc_jump

1. `picblobs-cli build alloc_jump linux:x86_64 --payload <file> -o out.bin`
2. Bytes of `out.bin` SHALL equal the output of
   `picblobs.Blob("linux","x86_64").alloc_jump().payload(...).build()`
   for the same payload.

### Test 12.5: `build` command — stager_tcp

1. Same bytes parity as test 12.4 but for `stager_tcp --address 10.0.0.1 --port 4444`.

### Test 12.6: `build` command — rejects irrelevant options

1. `picblobs-cli build hello linux:x86_64 --address 1.2.3.4 -o /tmp/x`
   SHALL exit non-zero with a click validation error.

### Test 12.7: `run` command (registry mode)

1. `picblobs-cli run hello linux:x86_64` exits 0 and prints
   `Hello, world!`.
2. `picblobs-cli run hello linux:aarch64` exits 0 and prints
   `Hello, world!` (cross-arch path via QEMU).
3. `picblobs-cli run nonexistent linux:x86_64` exits non-zero with a
   descriptive error.

### Test 12.7a: `run` command (file mode)

1. Build a blob: `picblobs-cli build alloc_jump linux:x86_64 --payload
   <inner> -o aj.bin`.
2. `picblobs-cli run --file aj.bin linux:x86_64` exits 0 and produces
   the inner payload's stdout (e.g. `PASS`).
3. Cross-arch: `picblobs-cli build stager_tcp linux:aarch64
   --address 127.0.0.1 --port 1 -o stg.bin` and then
   `picblobs-cli run --file stg.bin linux:aarch64 --timeout 3` exits
   non-zero (connect refused) — proves the file is dispatched under
   qemu-aarch64-static even though the host is x86_64.
4. `picblobs-cli run hello --file aj.bin linux:x86_64` SHALL exit
   non-zero: positional blob_type and --file are mutually exclusive.
5. `picblobs-cli run --file aj.bin linux:x86_64 --config-hex 00` SHALL
   exit non-zero: --config-hex is meaningless when the file is already
   complete.

### Test 12.8: `verify` command

1. `picblobs-cli verify` exits 0 when every staged blob runs
   successfully (mirrors legacy `python -m picblobs verify`).
2. Filter flags (`--os`, `--type`, `--arch`) produce a subset of the
   full run.
3. `ul_exec` verification uses staged `picblobs-cli` test ELFs and does
   not require cross-compilers in the verification environment.

### Test 12.9: Runner discovery fallback

1. With `picblobs_cli` importable: `picblobs.runner.find_runner("windows", "x86_64")`
   returns a path inside the `picblobs_cli._runners` tree.
2. `picblobs.runner.find_runner("linux", "x86_64")` SHALL raise
   `FileNotFoundError`; Linux blobs run through `picblobs.wrap_elf()`
   rather than a bundled C runner.
3. After removing `picblobs_cli` from `sys.modules` and hiding it on
   `sys.path`, non-Linux runner discovery SHOULD fall back to
   `bazel-bin/tests/runners/`.
4. If both non-Linux locations are missing, the raised `FileNotFoundError` text
   SHALL mention `picblobs-cli`.

### Test 12.10: `picblobs` wheel purity

1. The `picblobs` wheel (as currently staged) SHALL NOT contain any
   files under a `_runners` directory.
2. The `picblobs` wheel SHALL NOT contain any files under a
   `_test_binaries` directory.
3. The `picblobs` package SHALL still satisfy every TEST-008 scenario.

### Test 12.11: `info`

1. `picblobs-cli info` prints the package versions, runner bundle path,
   and a summary of available targets.
2. Output SHALL include "picblobs-cli" and "picblobs" version lines.

## Expected Results

- Every subcommand exits 0 on valid input and non-zero on invalid input.
- `build` output is byte-identical to the equivalent builder API call.
- Runner discovery prefers the installed `picblobs_cli` bundle over
  the development tree and emits a clear error when neither is available.
- The `picblobs` wheel carries no runner binaries after the split.
