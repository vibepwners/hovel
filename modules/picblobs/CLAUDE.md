# picblobs

Position-independent code blobs for multiple OS/arch targets. Bazel 9 + bzlmod
build system with Bootlin cross-compilation toolchains.

**Version**: 0.1.7 | **License**: Apache-2.0 | **Python**: 3.10+

This file is operating guidance for working in this repo: the non-obvious
conventions, the real (hook/CI-enforced) commands, and where things live.
It is deliberately not an API dump — for API details read the docstrings or
`docs/guide/*.html`.

`AGENTS.md` is a symlink to this file, so Codex and other agent tools read the
same guidance. Edit `CLAUDE.md`; never edit them out of sync.

## Repo layout

Two Python packages live side by side. Keep them straight — this is the most
common source of confusion:

| Path | Package | What it is |
|---|---|---|
| `python/picblobs/` | `picblobs` | Pure-data **library**: blob data, builder API, introspection, ELF wrap, runner orchestration. No runtime deps. |
| `python_cli/picblobs_cli/` | `picblobs-cli` | **click-based CLI**. Depends on `picblobs` + `click`. Bundles non-Linux runners + verifier fixtures as package data. |

- The `picblobs` **and** `picblobs-cli` console scripts both resolve to
  `picblobs_cli.cli:main` (see `python_cli/pyproject.toml`). There is **no**
  `picblobs/cli.py` — the CLI is entirely in `python_cli/`.
- Library modules (`python/picblobs/`): `_builder.py` (builder API, REQ-015),
  `_introspect.py` (REQ-016), `_elf.py` (`wrap_elf`), `_extractor.py` (sidecar
  loading), `_enums.py` (OS/Arch/BlobType), `_cross_compile.py`, `_objdump.py`,
  `_qemu.py`, `runner.py` (QEMU execution).
- Other top-level dirs: `src/` (freestanding C blobs + linker scripts),
  `tests/runners/` (C test runners), `tools/` (codegen + build + lint scripts,
  see below), `platforms/` + `toolchains/` (generated Bazel), `release/`
  (`//modules/picblobs/release:full` aggregate), `kernel/`, `mbed/`, `context/` (raw reference
  dumps), `docs/` (generated HTML guide), `spec/` + `SGM.md` + `sprints/`
  (specification-graph docs — reference material, not always current).

## Task runner — the single entry point

Every repo workflow runs through [Task](https://taskfile.dev) (`Taskfile.yml`).
There is **one** canonical command per workflow; prefer `task <name>` over
calling the underlying scripts directly. Prerequisites: `task` and `uv` on PATH.

```bash
task            # or `task --list` — show every task with a description
```

The tasks wrap the real implementations (`tools/*.py` and Bazel targets). Pass
extra args after `--`, e.g.
`task test -- --test_arg=-k --test_arg=extract`.

## Dev setup

```bash
source sourceme     # runs `task setup`
```

`task setup` verifies the generated Bazel metadata needed by the source tree.
Tooling is provided by Task/Bazel targets rather than a checked-out venv.

## Building

Target = what to build. Config = how to build it.

```bash
task build                       # //modules/picblobs/release:full for linux_x86_64
task build PLATFORM=linux_aarch64
task build PLATFORM=linux_x86_64 MODE=debug
task stage                       # build every platform + stage into the package tree
task stage -- --targets hello    # pass-through flags to the staging materializer
```

## Testing

```bash
task test                                # Bazel-integrated suite
task test -- --test_arg=-k --test_arg=test_extract
task test:unit / task test:payload       # subsets
task verify                              # end-to-end: run every staged blob
```

The Python and CLI pytest suites run as Bazel `py_test` targets.

## Code generation

`tools/registry.py` is the **single source of truth** for platforms,
architectures, traits, and syscall numbers. Most boilerplate (C headers,
`.bazelrc` platform blocks, `platforms/` + `toolchains/` BUILD files, C test
runners) is generated from it.

```bash
task generate          # regenerate all derived files
task generate:check    # fail if anything is stale
```

CI enforces freshness via the Bazel target `//modules/picblobs/tools:generate_check`
(`task bazel:generate-check`).

## Formatting and linting

```bash
task fmt           # clang-format (C) + ruff format (Python) + buildifier (Bazel)
task fmt:check     # check-only (fails if unformatted)
task lint          # ruff + lizard + buildifier
task lint:c        # clang-tidy via the Bazel lint aspect
task check         # all non-mutating gates: generate:check + fmt:check + lint:check + lint:c
```

The same Task-backed checks are run automatically by the lefthook git hooks
(pre-commit / pre-push) and by CI. The `:check` tasks set
`PICBLOBS_REQUIRE_LINT_TOOLS=1`, making a missing declared formatter/linter a
hard error instead of a skip.

## Releasing

```bash
task version -- 0.2.0      # set the version across both pyprojects + __init__
task dist                  # build + validate wheels/sdists for both packages
task clean                 # remove build/dist artifacts + `bazel clean`
```

## Key conventions

- Blobs are freestanding C (`-ffreestanding -nostdlib -fPIC -Os`). No libc.
- Platform configs are generated — do not hand-edit the block between
  `BEGIN/END GENERATED PLATFORM CONFIGS` in `.bazelrc`, or the generated files
  under `platforms/` and `toolchains/`. Edit `tools/registry.py` and regenerate.
- Debug/release are orthogonal `--config=debug` / `--config=release` flags, not
  separate targets.
- Toolchain SHA256 hashes in `tools/registry.py` must be pinned. Never leave
  empty; `task generate` materializes them into `toolchains/repositories.bzl`.
- `hello_windows` only builds for `windows:*` platform configs (TEB support is
  arch-gated).
- The Windows test runner (`tests/runners/windows/runner.c`) is hand-written
  (not generated) — it's a **Linux** binary that mocks TEB/PEB. Build it with a
  Linux config: `task -t ../../Taskfile.yml bazel:build -- --config=linux_x86_64 //modules/picblobs/tests/runners/windows:runner`.
- The FreeBSD test runner is a hand-written translating loader (like the Windows
  runner) — it patches FreeBSD syscall numbers to Linux equivalents at load time
  so FreeBSD-targeted blobs run under QEMU-on-Linux. Included in `//modules/picblobs/release:full`.

## CLI

`picblobs-cli` (click). Commands: `list`, `info`, `list-runners`, `build`,
`extract`, `run`, `debug`, `disasm`, `listing`, `test`, `verify`. Run
`picblobs-cli <cmd> --help` for the authoritative flags — do not rely on this
file for option lists.

Common ones:

```bash
picblobs-cli list                          # all staged blobs
picblobs-cli info hello linux:x86_64       # blob metadata
picblobs-cli run hello linux:aarch64       # run a staged blob under runner + QEMU
picblobs-cli run hello linux:x86_64 --debug    # verbose, keep temp files
picblobs-cli debug hello linux:aarch64     # launch under gdb, stopped at entry
picblobs-cli debug ul_exec linux:x86_64 --elf inner.elf   # debug needs build-style config
picblobs-cli run --file /tmp/hello.bin linux:x86_64   # run a prebuilt blob image
picblobs-cli run --file bash.bin linux:x86_64 -i      # -i/--interactive: attach the tty (e.g. a shell loaded by ul_exec)
picblobs-cli verify                        # run every staged blob end-to-end
picblobs-cli extract hello linux:x86_64 -o /tmp/hello.bin --config-hex 01020304
picblobs-cli listing --so path/to/hello.so linux:aarch64   # --so: disasm/listing only
```

## Library API

Public surface (see `python/picblobs/__init__.py` `__all__` for the full list,
and the module docstrings for signatures):

- **Data access**: `get_blob`, `list_blobs`, `raw_blob`, `blob_types`,
  `targets`, `is_supported`, `blob_size`, `clear_cache`, `BlobData`.
- **Builders**: `HelloBuilder`, `HelloWindowsBuilder`, `AllocJumpBuilder`,
  `StagerTcpBuilder`, `StagerFdBuilder`, `StagerMmapBuilder`,
  `StagerPipeBuilder`, `ReflectivePeBuilder`, `UlExecBuilder`, plus `Blob`,
  `Target`, `OS`, `Arch`, `BlobType`, `ConfigField`, `ConfigLayout`.
- **Helpers**: `wrap_elf`, `config_layout`, `build_hash`, `djb2`, `djb2_dll`,
  `ValidationError`.
- **Execution**: `picblobs.runner` — `run_blob`, `run_so`, `exec_command`,
  `find_qemu`, `qemu_launcher`, `can_run`, `find_runner`, `RunResult`.

```python
from picblobs import get_blob
from picblobs.runner import run_blob

blob = get_blob("hello", "linux", "aarch64")
result = run_blob(blob, config=b"\x01\x02\x03\x04", timeout=10.0)
print(result.stdout.decode(), result.exit_code)
```

## Architecture reference

Symbol conventions (from the linker scripts):

- `__blob_start` / `__blob_end` — code/data region boundaries (config follows).
- `__config_start` — start of the optional config struct region.
- `__got_start` / `__got_end` — GOT boundaries (MIPS).

Section layout: `.text → .rodata → .data → .bss → .config`.

Config struct: optional, at a link-time-fixed `config_offset` within the blob;
read via `BlobData.config_offset`, injected via `--config-hex` / `--payload`.

## Supported platforms

Authoritative source is `tools/registry.py`. Summary:

| OS | Architectures | Runner |
|---|---|---|
| linux | x86_64, i686, aarch64, armv5_arm, armv5_thumb, s390x, mipsel32, mipsbe32 | linux |
| freebsd | x86_64, i686, aarch64, armv5_arm, armv5_thumb, mipsel32, mipsbe32 | freebsd |
| windows | x86_64, i686, aarch64 | windows |

Per-arch traits (`uses_mmap2`, `uses_old_mmap`, `openat_only`,
`needs_got_reloc`, `needs_trampoline`, `is_32bit`) and syscall numbers live in
the registry.

## Troubleshooting

- **"No blob for X/Y/Z"**: `picblobs-cli list` to see what's staged; build with
  `task stage`.
- **Can't execute a cross-arch blob**: resolution order is direct exec
  (host-native, or routed by a binfmt_misc handler) → `qemu-*-static` / `qemu-*`
  on PATH → fail. See `qemu_launcher()` / `exec_command()` in `runner.py`.
  Install `qemu-user-binfmt` (Ubuntu 26.04+, preferred) or `qemu-user-static`
  (older) / `brew install qemu` (macOS). Check what this host can run with the
  "runnable" line in `picblobs-cli info`.
- **Runner binary not found**: build/stage runners with `task stage` (do not
  pass `--no-runners`); check `python/picblobs/_runners/linux/x86_64/runner`.
- **Objdump not found (disassembly)**: install a cross-toolchain
  (`apt install binutils-{arm,aarch64,mips}-linux-gnu`) or let Bazel fetch the
  Bootlin toolchains.
- **Rosetta 2 QEMU crashes (Apple Silicon)**: MIPS blobs may fail under Rosetta
  due to GOT self-relocation; `runner.is_arch_skip_rosetta()` detects and skips.

## Further docs

- `docs/guide/*.html` — full prose guide (getting started, writing blobs, adding
  an arch/syscall, testing, CLI).
- `spec/` + `SGM.md` + `sprints/` — specification-graph artifacts (vision, REQs,
  ADRs, models, verification specs). Reference material describing intent; treat
  as historical context, verify against code before relying on it.
