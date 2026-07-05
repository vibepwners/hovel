# ADR-026: Runner Binaries and QEMU CLI Split into `picblobs-cli`

## Status
Accepted

## Context

Until now, the `picblobs` wheel has bundled two very different classes of
artifact:

1. **Position-independent blob binaries** — pure data. No executable code
   runs on the host; the wheel is architecture-neutral (`py3-none-any`).
2. **Cross-compiled test runners** — executables for aarch64, ARM, MIPS,
   s390x, etc. They are not run on the host directly; they are handed to
   `qemu-*-static` along with a blob. But they are platform-specific
   binaries that fatten the wheel, and they pull the library's concerns
   into "testing / orchestration" rather than "distribute blobs".

Bundling runners has real costs:

- The wheel is ~10× larger than necessary for consumers who only want the
  blobs (e.g., an embedded pentest framework that ships picblobs as a
  data dependency).
- "Install picblobs, get a bunch of binaries I didn't ask for" surprises
  auditors and supply-chain reviewers.
- QEMU orchestration, `click`, temp-file fixtures, stdin piping, TCP
  listeners for `stager_tcp` — all of this belongs to a *testing tool*,
  not a *data library*.

ADR-021 originally chose to embed runners inside the main wheel because
there was only one package. With REQ-015 / REQ-016 stabilising the
Python library API, the picblobs wheel has earned its separation.

## Decision

The project SHALL ship two distinct packages from one source tree:

| Package       | Purpose                                   | Installs binaries? | Ships runner/test assets? |
|---------------|-------------------------------------------|--------------------|---------------------------|
| `picblobs`    | Blob data, builder API, introspection     | No (py3-none-any)  | No                        |
| `picblobs-cli`| `click`-based CLI for running/testing     | Yes                | Yes                       |

- `picblobs-cli` depends on `picblobs` for blob data and the builder API.
- `picblobs-cli` carries a `_runners/{runner_type}/{arch}/runner` tree
  identical in structure to what lived inside `picblobs` before.
- `picblobs-cli` also carries verifier-only `_test_binaries/` assets,
  including the Linux `ul_exec` input ELFs used by `picblobs-cli verify`.
- `picblobs.runner.find_runner()` continues to exist as the one-and-only
  runner lookup routine, but it now locates the binary by asking the
  `picblobs_cli` package for its bundled `_runners/` directory via
  `importlib.resources`; if `picblobs_cli` is not importable, it falls
  back to the Bazel `bazel-bin/tests/runners/` tree for development, and
  finally raises `FileNotFoundError` with guidance ("install
  picblobs-cli").

The existing `python -m picblobs` CLI (list / info / extract / listing)
stays in `picblobs` — those commands inspect blob data and do not need
runners or QEMU. The runner-dependent commands (`run`, `verify`, `test`)
move into the new `picblobs-cli` console script.

## Rationale

- **Separation of concerns.** The data library is pure, auditable, and
  tiny. The testing tool can freely add heavyweight deps (click, pytest
  fixtures, QEMU probes) without infecting downstream consumers.
- **No API break.** `picblobs.runner.find_runner()` and `run_blob()` keep
  their signatures. The only observable change is where the binary is
  physically discovered — and the fallback to the source tree keeps
  development ergonomics identical.
- **Optional tooling.** A deployment that only bundles blobs into a
  larger product has no reason to ship runners. Consumers that do want
  to run blobs install `picblobs-cli` and pick up the runners plus the
  `click` CLI as a single unit.

## Alternatives Considered

### A. Keep everything in `picblobs`

Rejected. Continues to ship native binaries inside an ostensibly
`py3-none-any` wheel. The wheel tag is already a lie under ADR-021 — the
runners make it platform-neutral only because they are never executed on
the host, but that's brittle and bad signal for supply-chain tooling.

### B. Split into three packages (`picblobs-data`, `picblobs-tools`, `picblobs`)

Rejected as over-engineering. Two packages cover the two genuine audiences
(consumers of data vs. consumers of tooling); a meta-package adds
indirection without a clear user.

### C. Ship runners as an "extras" install (`pip install picblobs[runners]`)

Rejected. Extras can add pure-Python dependencies, not architecture-
specific binary payloads. The runners need their own wheel to be
installable; at that point the wheel is already separate, so a distinct
package name is just naming it honestly.

## Consequences

- Two `pyproject.toml` files live in the source tree (`python/` and
  `python_cli/`), each producing one wheel.
- `tools/stage_blobs.py` stages blobs under `python/picblobs/_blobs/`,
  runners under `python_cli/picblobs_cli/_runners/`, and verifier ELFs
  under `python_cli/picblobs_cli/_test_binaries/`. The runner layout
  inside `picblobs_cli` mirrors what used to live inside `picblobs` so
  no Python code that already uses `find_runner()` needs signature
  changes.
- Existing pytest suites for the runner-dependent paths continue to
  work because they import `picblobs.runner.run_blob()` and let it
  locate the binary via the same helper.
- ADR-021 is updated to reference this ADR: embedded cross-compiled
  runners are still the strategy, but they now live in `picblobs-cli`.

## Verified By

- REQ-020 (picblobs-cli package)
- TEST-012 (picblobs-cli verification)
