# REQ-020: `picblobs-cli` Companion Package

## Status
Accepted

## Statement

The project SHALL publish a companion Python package named
`picblobs-cli` that bundles the cross-compiled test runners and provides
a `click`-based command-line interface for assembling, running, and
verifying PIC blobs under QEMU. `picblobs-cli` SHALL declare `picblobs`
and `click` as runtime dependencies; it SHALL NOT duplicate blob data.

## Rationale

`picblobs` is a pure-data library (blobs + builder API + introspection).
Consumers that embed picblobs as a data dependency must not be forced
to install architecture-specific runner binaries or QEMU plumbing they
never use. `picblobs-cli` exists to give operators a batteries-included
tool — install one package, get a command that can build, run, and
verify blobs across every supported architecture without any further
setup.

## Derives From
- ADR-026
- REQ-015
- REQ-016

## Detailed Requirements

### Package Layout

The source tree SHALL contain `python_cli/` parallel to `python/`. Inside:

```
python_cli/
├── pyproject.toml
└── picblobs_cli/
    ├── __init__.py
    ├── __main__.py                  # enables `python -m picblobs_cli`
    ├── cli.py                       # click command tree
    ├── _test_binaries/              # verifier-only ELF fixtures
    └── _runners/
        └── {runner_type}/{arch}/runner
```

`_runners/` and `_test_binaries/` SHALL be populated by
`tools/stage_blobs.py` during the build pipeline. Both trees are package
data for `picblobs-cli`, not for `picblobs`.

### Runtime Dependencies

`pyproject.toml` SHALL declare:

```toml
[project]
name = "picblobs-cli"
dependencies = [
  "picblobs>=0.1.6",
  "click>=8.0",
]

[project.scripts]
picblobs-cli = "picblobs_cli.cli:main"
```

### CLI Surface

The `picblobs-cli` console script SHALL expose the following
subcommands. All subcommands SHALL accept `--help` and SHALL exit with
a non-zero status on any form of validation or execution failure.

#### `picblobs-cli run <blob_type> <target> [options]`
#### `picblobs-cli run --file FILE <target> [options]`

Run a single blob under the appropriate runner and QEMU. Two modes:

**Registry mode** — look a blob up by its type and append a config:

- `<blob_type>`: Blob type name (e.g. `hello`, `alloc_jump`, `ul_exec`).
- `<target>`: `os:arch` string (e.g. `linux:aarch64`).
- `--config-hex HEX`: Optional hex-encoded config bytes.
- `--payload FILE`: Optional path to a file whose contents replace the
  config region.

**File mode** — execute an already-assembled blob straight from disk:

- `-f / --file FILE`: Path to a fully-assembled blob file. The file is
  passed to the runner as-is; no config is appended and no extraction
  is performed. Typically paired with the output of
  ``picblobs-cli build ... -o FILE``.
- `<target>`: `os:arch`, selects which runner and QEMU binary to use.
- `--config-hex` / `--payload` SHALL be rejected in file mode since the
  blob is already fully assembled.
- Attempting to combine `--file` with a `<blob_type>` positional SHALL
  be rejected with a descriptive error.

Shared options:

- `--timeout SECONDS`: Execution timeout (default 30).
- `--debug`: Print the assembled command, paths, and exit diagnostics.
- `--stdin FILE`: Feed file contents to the blob's stdin.

Stdout and stderr SHALL be passed through from the blob process.

#### `picblobs-cli verify [--os OS] [--arch ARCH] [--type TYPE] [options]`

Exercise every staged blob end-to-end. SHALL include the fixtures
needed for stager-type blobs (TCP server, FIFO, temp file, stdin
pipe) and the inner-payload packing for `alloc_jump`. Filter options
repeat the current `python -m picblobs verify` behaviour.

#### `picblobs-cli build <blob_type> <target> [options] -o OUTPUT`

Use the builder API from `picblobs` to assemble a ready-to-run blob and
write it to `OUTPUT` as raw bytes.

- `--payload FILE` for `alloc_jump`.
- `--address IP --port N` for `stager_tcp`.
- `--pe FILE` for `reflective_pe`.
- `--elf FILE [--argv X ...] [--envp K=V ...]` for `ul_exec`.
- `--fd N` for `stager_fd`.
- `--path PATH` for `stager_pipe` and `stager_mmap`.
- `--offset N --size N` for `stager_mmap`.

Options that are not relevant to the chosen blob type SHALL be rejected
with a descriptive error.

#### `picblobs-cli list-runners [--os OS] [--arch ARCH]`

List the bundled runner binaries (by runner_type and arch). Useful to
verify installation and sanity-check platform coverage.

#### `picblobs-cli info`

Print version of both `picblobs` and `picblobs-cli`, the runner
bundle directory, QEMU binaries detected on `PATH`, and a one-line
summary per supported target.

### Runner Discovery

`picblobs.runner.find_runner()` SHALL be extended (but not signature-
changed) to locate bundled runners by probing:

1. The `picblobs_cli` package via `importlib.resources.files("picblobs_cli") / "_runners"`.
2. The development tree at `bazel-bin/tests/runners/{runner_type}/runner{.bin,}`.
3. The caller-provided `search_paths` list (as today).

If none of these yield a runner, the raised `FileNotFoundError` SHALL
include the guidance `"install picblobs-cli or run tools/stage_blobs.py"`.

### Packaging Properties

- `picblobs-cli` wheels SHALL be produced as `py3-none-any` because the
  runner binaries, while architecture-specific, are never executed on
  the host — they are consumed by QEMU, and QEMU determines the
  execution architecture.
- The wheel SHALL contain `_runners/` for every
  (runner_type, arch) combination in REQ-018.
- The wheel SHALL contain `_test_binaries/ul_exec/linux/{arch}/hello_et_exec`
  for Linux `ul_exec` verification. These ELFs are verifier fixtures and
  SHALL NOT be included in the `picblobs` wheel.
- The wheel SHALL NOT contain `.so` blob files — those come through the
  `picblobs` dependency.

### Compatibility With Existing `picblobs` CLI

The `python -m picblobs` CLI SHALL remain operational for pure-data
subcommands (`list`, `info`, `extract`, `listing`). The runner-
dependent subcommands (`run`, `verify`, `test`) SHALL continue to work
when `picblobs_cli` is importable and SHALL print a descriptive error
naming `picblobs-cli` when it is not.

## Acceptance Criteria

1. `pip install picblobs-cli` installs both packages and produces a
   working `picblobs-cli` command on `PATH`.
2. `picblobs-cli run hello linux:x86_64` prints `Hello, world!` and
   exits 0.
3. `picblobs-cli build stager_tcp linux:x86_64 --address 10.0.0.1 --port 4444 -o out.bin`
   writes a file whose bytes match the equivalent builder API invocation.
4. After `picblobs-cli build alloc_jump linux:x86_64 --payload inner -o aj.bin`,
   `picblobs-cli run --file aj.bin linux:x86_64` executes the assembled
   blob and produces the same stdout/exit-code as the registry path
   would for the equivalent config.
4. `picblobs-cli verify` passes for the same set of blobs as
   `python -m picblobs verify` (legacy).
5. `picblobs-cli list-runners` prints at least one runner per target.
6. With `picblobs-cli` uninstalled, `picblobs.runner.find_runner()`
   raises `FileNotFoundError` with text mentioning `picblobs-cli`.
7. The `picblobs` wheel size SHALL decrease after the split (no runner
   binaries).

## Verified By
- TEST-012
