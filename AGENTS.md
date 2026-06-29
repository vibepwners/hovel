# Agent instructions for Hovel

These instructions apply to any AI agent or automation working in this
repository. (`CLAUDE.md` is a symlink to this file.)

## The one rule for the build system

**Always invoke the build system through [Task](https://taskfile.dev/)
(`task <name>`). Never call `bazel`, `gofmt`, `uv`, or `lefthook` directly.**

`Taskfile.yml` is the single source of truth for how the project is built,
tested, linted, formatted, and run. CI, the git hooks, the docs, and you all go
through it. If something cannot be done with an existing task, add or fix a task
rather than running the underlying tool ad hoc — then use the task.

Run `task --list` to see everything available.

## Shell in the build graph

Do not add shell scripts to the build, lint, test, docs, or demo pipeline by
default. Hovel uses Bazel/Starlark for declared build actions and Python for
non-trivial repository tooling. Shell is acceptable only when the shell itself
is the thing being demonstrated or operated, such as VHS terminal recordings,
Docker entrypoints, or one-off lab operator scripts.

When a check can be cached, model it as a Bazel target with explicit inputs and
outputs instead of discovering files from shell at execution time. When a task
must materialize generated artifacts back into the working tree (`_site/`,
`demo/out/`, `examples/bin/`), prefer a `bazel run` Python materializer with
declared data dependencies. Do not call `bazel` from helper scripts.

Build, test, lint, docs, and demo tools should be Bazel-managed execution
inputs whenever practical: pinned archives, pip wheels, Go/Rust toolchains, or
custom toolchains/rules. Do not add new `PATH` lookups, `go install`, `uv tool
install`, Homebrew, or apt-installed CLIs for tools that can reasonably be
declared in Bazel. Host tools are acceptable only for real host services or
system boundaries that Bazel should not own, such as Docker, Wine, tmux, ttyd,
or ffmpeg until they have a pinned execution toolchain.

## Common tasks

| Task | What it does |
| --- | --- |
| `task` / `task --list` | List all tasks. |
| `task build` | Build everything (`//...`). |
| `task build -- //cmd/hovel` | Build a specific target (args after `--`). |
| `task test` | Run all tests. |
| `task test -- //internal/domain/...` | Run specific tests. |
| `task run -- //cmd/hovel -- daemon status` | Run an arbitrary target. |
| `task lint` | Go formatting + golangci-lint + Gazelle + Rust + Python + Squatter C checks (read-only). |
| `task fmt` | Auto-format: rewrite Go source, regenerate BUILD files, and format Rust and Squatter C. |
| `task coverage` | Run domain, application, and Python SDK coverage ratchets. |
| `task check` (`task ci`) | Lint, docs, build, test, race, fuzz smoke, and coverage — the full gate. |
| `task start` (`cli`) / `task daemon` | Launch the interactive CLI / the daemon. |
| `task status` / `task init` / `task reset` | Dev workspace: status, init, wipe-and-relaunch. |
| `task modules:build` | Build the Go/Rust example modules and stage binaries to `examples/bin/`. |
| `task docs` | Build the static spec site. |
| `task hooks:install` | Install the Lefthook git hooks. |

## Definition of done

Before considering a code change complete, run **`task ci`** and make sure it
passes. This is the full local gate: lint, docs, build, test, race, fuzz smoke,
and coverage. CI
(`.github/workflows/ci.yml`) runs the same suite; the git hooks split the same
Task-backed checks across pre-commit (`task precommit`) and pre-push
(`task prepush`).

If you added, moved, or removed Go files or imports, run **`task fmt`** so
`gofmt` and Gazelle-generated `BUILD.bazel` files are up to date; otherwise
`task lint` will fail on the Gazelle diff check. `task fmt` also formats
Rust and Squatter C sources. When you add a new test target, also add it to the
`test_suite` in the root `BUILD.bazel`.

## Architecture guardrails

Hovel uses a hexagonal layering with dependencies pointing inward:

```
adapters -> app -> domain
infra    -> app -> domain
```

- `internal/domain` must not import CLI, TUI, REST, MCP, storage, RPC, or
  concrete module/service code. Keep it pure; construct value objects through
  their `New...` constructors so validation runs.
- Front ends call application services (`internal/app`); they do not reach into
  adapters directly.
- Match the surrounding code: error wrapping, and defensive copying of
  maps/slices at boundaries.

## Safety-sensitive code

Hovel is an authorized red-team emulation and defensive validation tool for
scoped, auditable assessments. Changes to the throw planning, confirmation,
guardrail, or audit-event path need extra care. Preserve:

- A throw cannot start without a persisted plan and a recorded confirmation.
- `--now` skips the typed prompt but still records an auditable confirmation
  noting the bypass.
- Modules tagged `dangerous` require `--allow-dangerous` before they can throw.
- Never silently redact or drop operator-controlled configuration values.

See `SECURITY.md` and `CONTRIBUTING.md` for the fuller picture.
