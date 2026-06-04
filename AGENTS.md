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

## Common tasks

| Task | What it does |
| --- | --- |
| `task` / `task --list` | List all tasks. |
| `task build` | Build everything (`//...`). |
| `task build -- //cmd/hovel` | Build a specific target (args after `--`). |
| `task test` | Run all tests. |
| `task test -- //internal/domain/...` | Run specific tests. |
| `task run -- //cmd/hovel -- daemon status` | Run an arbitrary target. |
| `task lint` | Go formatting + Gazelle + Python checks (read-only). |
| `task fmt` | Auto-format: rewrite Go source and regenerate BUILD files. |
| `task check` (`task ci`) | Lint, build, and test — the full gate. |
| `task start` (`cli`) / `task daemon` | Launch the interactive CLI / the daemon. |
| `task status` / `task init` / `task reset` | Dev workspace: status, init, wipe-and-relaunch. |
| `task modules:build` | Build the Go/Rust example modules and stage binaries to `examples/bin/`. |
| `task docs` | Build the static spec site. |
| `task hooks:install` | Install the Lefthook git hooks. |

## Definition of done

Before considering a code change complete, run **`task ci`** and make sure it
passes. This is exactly what CI (`.github/workflows/ci.yml`) and the pre-commit
hook run, so a green `task ci` locally means a green build.

If you added, moved, or removed Go files or imports, run **`task fmt`** so
`gofmt` and Gazelle-generated `BUILD.bazel` files are up to date; otherwise
`task lint` will fail on the Gazelle diff check. When you add a new test target,
also add it to the `test_suite` in the root `BUILD.bazel`.

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

Hovel is an authorized-security-testing tool. Changes to the throw planning,
confirmation, guardrail, or audit-event path need extra care. Preserve:

- A throw cannot start without a persisted plan and a recorded confirmation.
- `--now` skips the typed prompt but still records an auditable confirmation
  noting the bypass.
- Modules tagged `dangerous` require `--allow-dangerous` to throw.
- Never silently redact or drop operator-controlled configuration values.

See `SECURITY.md` and `CONTRIBUTING.md` for the fuller picture.
