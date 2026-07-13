# Contributing to Hovel

Thanks for your interest in improving Hovel. This document covers how to build,
test, and structure changes.

## Development environment

Install:

- [Task](https://taskfile.dev/) — the single entry point for every build command
- [bazelisk](https://github.com/bazelbuild/bazelisk) (honors `core/.bazelversion`)

Python, Go, Rust, Node, formatting, linting, documentation, and cross-compilation
tools are declared build inputs; do not install parallel host copies for
repository workflows. Install [Lefthook](https://lefthook.dev/) only if you want
the optional Git-hook integration exposed by `task hooks:install`. Host services
such as Docker, QEMU, Wine, or ffmpeg are needed only by tasks that cross those
specific system boundaries.

**Drive the build only through Task** (`task <name>`); do not invoke `bazel`,
`gofmt`, `uv`, or `lefthook` directly. `Taskfile.yml` is the single source of
truth, and CI runs the same tasks. If you need an operation that has no task,
add one to `Taskfile.yml` rather than running the tool by hand. `task --list`
shows everything.

Then:

```sh
task hooks:install   # optional: run checks on commit
task checkout:status # show which checkout slices are present
task check           # run checks available in this checkout
task ci              # full-checkout gate for wired slices
```

## Repository layout

Hovel is split into sparse-checkout friendly slices:

| Path | Purpose |
| --- | --- |
| `core/` | Self-contained Go/Bazel workspace for the Hovel framework binary, daemon, CLI/TUI/MCP front ends, schemas, core tests, and core build tooling. |
| `sdk/` | Python, Go, and Rust module SDKs. SDKs are outside `core/` so SDK work can be checked out independently from framework internals. |
| `modules/` | In-repo example modules, Squatter payload/provider code, module packaging tools, and lab helpers. |
| `docs/` | GitHub Pages source, book content, demos, and documentation tooling. |
| `repo-tools/` | Small repository-level helpers used by the root Task dispatcher. |

## Before you open a PR

For partial checkouts, run the available-slice gate while iterating:

```sh
task check
```

Before opening a PR, run the same full-checkout suite CI runs:

```sh
task ci
```

`task ci` first verifies that the full source tree is checked out. It then runs
repository policy and quality checks, the core lint/build/test/race/fuzz/coverage
gate, all three SDK build/lint/test gates, module and Picblobs build/test gates,
and the hermetic Astro documentation build and validators. The slices remain
separate so `task check` can validate a sparse checkout without pulling
unrelated code, while `task ci` proves the complete integration graph.

If you add, move, or remove Go files or imports, regenerate formatting and
`BUILD.bazel` metadata:

```sh
task fmt
```

When you add a new core test target, also add it to the `test_suite` in
`core/BUILD.bazel` so it is part of the core CI suite.

## Architecture rules

Hovel uses a hexagonal layering. Respect the dependency direction:

```
adapters -> app -> domain
infra    -> app -> domain
```

- `internal/domain` must not import CLI, TUI, REST, MCP, storage, RPC, or
  concrete module/service code. Keep it pure, with validated value objects.
- Front ends should call application services, not reach into adapters.
- Construct domain value objects through their `New...` constructors so
  validation runs.

## Code style

- Go code is formatted with `gofmt` and checked with golangci-lint; `task fmt`
  formats wired core and Go SDK sources in place.
- Match the surrounding code's naming, error-wrapping, and defensive-copy
  conventions (maps/slices are cloned at boundaries).
- Python SDK code must pass `ruff`, `mypy --strict`, and `pydoclint`.
- Rust SDK and example code must pass `rustfmt --check` and Clippy.

## Tests

- New behavior needs tests. Coverage ratchets and long-term goals are documented
  in `docs/site/src/content/spec/testing-roadmap.html`; run `task coverage` for the current
  core floors.
- Production commands should exercise the daemon boundary.
- Mock modules exist for tests and examples only and are not part of the
  shipped catalog.

## Safety-sensitive changes

Changes that touch the throw planning, confirmation, guardrail, installed
payload inventory, or audit-event path deserve extra scrutiny. Preserve these
invariants:

- A throw cannot start without a persisted plan and a recorded confirmation.
- `--now` bypasses the typed prompt but still records an auditable confirmation
  noting the bypass.
- Installed payload records are created or updated only from explicit provider
  or module descriptors, and every state change is auditable.
- Do not silently redact or drop operator-controlled configuration values.

See [SECURITY.md](SECURITY.md) for the broader model and how to report
vulnerabilities.

## Commit and PR hygiene

- Keep PRs focused; describe the change and how you tested it.
- Delete merged branches.
