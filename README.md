# Hovel

![Hovel](assets/hovel.png)

Hovel is a Go-hosted framework for authorized red-team emulation, controlled
lab exercises, defensive validation, and operator workflow automation. It is
designed for scoped, auditable assessments rather than general-purpose
dual-use automation. The local daemon role (`hovel daemon serve`, often called
`hoveld` in internal docs and logs) owns the workspace database,
module process lifecycle, a plan -> confirm -> throw safety pipeline, installed
payload inventory, an artifact store, and a structured event/log rail. Operators
drive it through an interactive CLI and one-shot saved chain files; the same
application services are intended to back additional front ends (TUI, REST,
MCP).

> **Authorized red-team emulation only.** Use Hovel only in environments you
> own or are explicitly authorized to assess, with written scope and approvals.
> See [SECURITY.md](SECURITY.md).

## Documentation

The full specification is a static website rooted at
[`index.html`](index.html).

## → [vibe-pwners.github.io/hovel](https://vibe-pwners.github.io/hovel/index.html) ←

Module authors should start with the
[Module Development](spec/module-development.html) guide, then use the
language-specific guides for [Python](spec/module-python.html),
[Go](spec/module-go.html), or [Rust](spec/module-rust.html). Those pages cover
the stdio JSON-RPC contract, registration, safety tags, sessions, artifacts,
installed payload records, and provider boundaries.

`task docs` stages the full documentation site in `_site/`, including generated
SDK API reference pages under `_site/api/sdk/` and an internal link check. GitHub
Pages and GitLab Pages both run that task before publishing.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/hovel` | The `hovel` mono-binary entry point. |
| `internal/domain` | Pure domain model (no outward imports). |
| `internal/app` | Application services, command registry, operator session. |
| `internal/adapters` | CLI, daemon RPC, SQLite/filesystem storage, descriptors. |
| `internal/infra` | Daemon manager and runtime. |
| `internal/modules` | In-tree module runners (Python RPC host, mock modules). |
| [`sdk`](sdk/README.md) | SDK overview for module authors. |
| [`sdk/python`](sdk/python/README.md) | Python module SDK (`hovel_sdk`). |
| [`sdk/go`](sdk/go/README.md) | Go module SDK (`github.com/Vibe-Pwners/hovel/sdk/go/hovel`). |
| [`sdk/rust`](sdk/rust/README.md) | Rust module SDK crate. |
| `examples/python` | Example modules exercised by tests. |
| `examples/go` | Go module examples: survey, exploit, and session. |
| `examples/rust` | Rust module examples: survey, exploit, and session. |
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

# Run the full check suite (lint + docs + build + test) — what CI runs
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
| `task lint` (`l`) | Go formatting, Gazelle, Python, and Squatter C checks (read-only). |
| `task fmt` | Auto-format Go source, regenerate `BUILD` metadata, and format Squatter C. |
| `task check` (`ci`) | Lint, docs, build, and test. |
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

Root help also exposes compatibility and developer entrypoints such as `shell`,
`command`, `run`, direct registry roots (`module`, `chain`, `op`, ...), `init`,
and `status`. Prefer the role commands above in user-facing docs and examples.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes must pass `task ci`, which
is also enforced in CI.

## License

See [LICENSE](LICENSE).
