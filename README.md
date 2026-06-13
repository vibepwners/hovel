# Hovel

![Hovel](assets/hovel.png)

Hovel is a Go-hosted framework for authorized red-team emulation, controlled
lab exercises, defensive validation, and operator workflow automation. It is
designed for scoped, auditable assessments rather than general-purpose
dual-use automation. A local engine (`hoveld`) owns the workspace database,
module process lifecycle, a plan -> confirm -> throw safety pipeline, an
artifact store, and a structured event/log rail. Operators drive it through an
interactive CLI; the same application services are intended to back additional
front ends (one-shot chain files, TUI, REST, MCP).

> **Authorized red-team emulation only.** Use Hovel only in environments you
> own or are explicitly authorized to assess, with written scope and approvals.
> See [SECURITY.md](SECURITY.md).

## Documentation

The full specification is a static website rooted at
[`index.html`](index.html).

## → [vibe-pwners.github.io/hovel](https://vibe-pwners.github.io/hovel/index.html) ←

## Layout

| Path | What it is |
| --- | --- |
| `cmd/hovel` | The `hovel` mono-binary entry point. |
| `internal/domain` | Pure domain model (no outward imports). |
| `internal/app` | Application services, command registry, operator session. |
| `internal/adapters` | CLI, daemon RPC, SQLite/filesystem storage, descriptors. |
| `internal/infra` | Daemon manager and runtime. |
| `internal/modules` | In-tree module runners (Python RPC host, mock modules). |
| `sdk/python` | Python module SDK (`hovel_sdk`). |
| `examples/python` | Example modules exercised by tests. |
| `schemas` | JSON schemas for descriptors, chains, events, throw plans. |
| `spec` | The specification website source. |

The architecture follows a hexagonal layering: `adapters → app → domain` and
`infra → app → domain`. The `domain` package must not import CLI, storage, RPC,
or concrete module/service code.

## Prerequisites

- [Task](https://taskfile.dev/) — the single entry point for every build command
- [Bazel](https://bazel.build/) (via [bazelisk](https://github.com/bazelbuild/bazelisk); pinned by `.bazelversion`)
- [uv](https://docs.astral.sh/uv/) for Python SDK lint/type/doc checks
- [Lefthook](https://lefthook.dev/) (optional) for git hooks

## Quick start

`Taskfile.yml` is the one correct way to drive the build — don't call `bazel`,
`gofmt`, `uv`, or `lefthook` directly. Run `task --list` to see everything.

```sh
# Build and launch the interactive CLI (auto-starts a managed daemon)
task start

# Is the dev daemon up?
task status

# Wipe local state and relaunch from a clean slate
task reset

# Run the full check suite (lint + build + test) — what CI runs
task ci
```

The dev workspace defaults to `./.hovel` (gitignored); override it by setting
`HOVEL_WORKSPACE`.

Run the app:

| Target | Description |
| --- | --- |
| `task start` (`dev`, `up`, `cli`) | Build and launch the interactive CLI. |
| `task daemon` | Run `hoveld` in the foreground on the default socket. |
| `task status` (`st`) | Show daemon status for the dev workspace. |
| `task init` | Initialize the dev workspace (`./.hovel`). |
| `task throw -- <chain.yaml>` | One-shot throw of a saved chain file. |
| `task clean` | Remove local dev state (`./.hovel`, `.task`). |
| `task reset` (`fresh`) | Wipe local state, then launch a fresh CLI. |

Build & checks:

| Target | Description |
| --- | --- |
| `task build` (`b`) | Build all targets (`task build -- //cmd/hovel` for one). |
| `task test` (`t`) | Run all tests (`task test -- //internal/...` for some). |
| `task lint` (`l`) | gofmt + Gazelle + Python checks (read-only). |
| `task fmt` | Auto-format Go source and regenerate `BUILD` metadata. |
| `task check` (`ci`) | Lint, build, and test. |
| `task hooks:install` | Install git hooks via Lefthook. |

## Front-end roles

```
hovel cli ...              # interactive operator shell (implemented)
hovel daemon serve ...     # run the engine explicitly
hovel throw <chain-file>   # one-shot saved-chain execution
hovel tui ...              # not implemented yet
```

`cli` auto-starts or attaches to a local daemon for the workspace. A daemon
started by an interactive session is owned by it and shuts down on exit; a
pre-existing daemon is left running.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes must pass `task ci`, which
is also enforced in CI.

## License

See [LICENSE](LICENSE).
