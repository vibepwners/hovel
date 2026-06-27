# Contributing to Hovel

Thanks for your interest in improving Hovel. This document covers how to build,
test, and structure changes.

## Development environment

Install:

- [Task](https://taskfile.dev/) — the single entry point for every build command
- [bazelisk](https://github.com/bazelbuild/bazelisk) (honors `.bazelversion`)
- [uv](https://docs.astral.sh/uv/) (Python SDK checks)
- [Lefthook](https://lefthook.dev/) (optional git hooks)

**Drive the build only through Task** (`task <name>`); do not invoke `bazel`,
`gofmt`, `uv`, or `lefthook` directly. `Taskfile.yml` is the single source of
truth, and CI runs the same tasks. If you need an operation that has no task,
add one to `Taskfile.yml` rather than running the tool by hand. `task --list`
shows everything.

Then:

```sh
task hooks:install   # optional: run checks on commit
task ci              # full local gate: lint, docs, build, tests, race, fuzz, coverage
```

## Before you open a PR

Run the same suite CI runs:

```sh
task ci
```

That is `task lint` (gofmt, Gazelle up-to-date, Python ruff/mypy/pydoclint,
and Squatter C static checks), then `task docs`, `task build`, `task test`,
`task test:race`, `task fuzz:smoke`, and `task coverage`. CI
(`.github/workflows/ci.yml`) runs the same checks on every pull request.

If you add, move, or remove Go files or imports, regenerate formatting and
`BUILD.bazel` metadata:

```sh
task fmt
```

When you add a new test target, also add it to the `test_suite` in the root
`BUILD.bazel` so it is part of `//:test`.

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

- Go code is formatted with `gofmt`; `task fmt` formats Go and Squatter C in place.
- Match the surrounding code's naming, error-wrapping, and defensive-copy
  conventions (maps/slices are cloned at boundaries).
- Python SDK code must pass `ruff`, `mypy --strict`, and `pydoclint`.

## Tests

- New behavior needs tests. Coverage ratchets and long-term goals are documented
  in `spec/testing-roadmap.html`; run `task coverage` for the current floors.
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
