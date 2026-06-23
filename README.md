# Hovel

![Hovel](assets/hovel.png)

Hovel is a Go-hosted framework for authorized red-team emulation, controlled
lab exercises, defensive validation, and operator workflow automation. It is
designed for scoped, auditable assessments rather than general-purpose
dual-use automation. The local daemon role (`hovel daemon serve`, often called
`hoveld` in internal docs and logs) owns the workspace database,
module process lifecycle, a plan -> confirm -> throw safety pipeline, installed
payload inventory, an artifact store, and a structured event/log rail. Operators
drive it through an interactive CLI, one-shot saved chain files, and the MCP
agent front end; the same application services are intended to back the full
front-end set, including TUI, REST, and richer MCP resources.

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
the stdio JSON-RPC contract, module packages, safety tags, sessions, artifacts,
installed payload records, and provider boundaries.

## Install

The operator install is the `hovel` PyPI package, which contains the
platform-specific Go binary and does not download the binary at install time:

```sh
pipx install hovel
hovel status
```

The Python module SDK ships separately:

```sh
python -m pip install hovel-sdk
```

The `hovel` package includes no modules by default. Install trusted module
packages explicitly:

```sh
hovel module install ./squatter-0.1.0.tgz
hovel module install --link /absolute/path/to/module-package-root
hovel module install squatter@0.1.0 --index ./dist/modules/module-index.yaml
hovel module uninstall squatter@0.1.0
```

Use `--global` on module commands to install/list/uninstall from the user module
scope instead of the active workspace. Downloaded module packages are cached and
can be discovered offline.

`task docs` renders the terminal demos, stages the full documentation site in
`_site/`, embeds the generated GIFs under `_site/assets/demos/`, generates SDK
API reference pages under `_site/api/sdk/`, and runs an internal link check.
GitHub Pages runs that task before uploading and deploying the site.

`task modules:package` builds the example module `.tgz` packages, a module
index, and `SHA256SUMS` under `dist/modules/` for GitHub Release publishing.

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
- [VHS](https://github.com/charmbracelet/vhs) plus `ttyd` and `ffmpeg` for demo and docs generation
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

# Run the full check suite (lint + demo-backed docs + build + test) — what CI runs
task ci
```

The dev workspace defaults to `./.hovel` (gitignored); override it by setting
`HOVEL_WORKSPACE`.

Run the app:

| Target | Description |
| --- | --- |
| `task start` (`dev`, `up`, `cli`) | Build and launch the interactive CLI. |
| `task daemon` | Run `hoveld` in the foreground on the default socket. |
| `task mcp` | Launch the MCP agent front end for the dev workspace; `hovel mcp --transport http` serves streamable HTTP. |
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
| `task check` (`ci`) | Lint, demo-backed docs, build, and test. |
| `task upver -- 0.2.0` | Update the shared Hovel and hovel-sdk release version. |
| `task demos` | Generate VHS terminal demos into `demo/out/`. |
| `task demo:squatter-wine` | Generate the Docker/Wine Squatter MCP demo GIF. |
| `task hooks:install` | Install git hooks via Lefthook. |

## Terminal demos

Scripted terminal demos live under [`demo/tapes`](demo/tapes). Hovel uses
[Charmbracelet VHS](https://github.com/charmbracelet/vhs) to render them into
GIF artifacts under `demo/out/`; generated outputs are ignored by git.

Install VHS locally with your package manager, for example:

```sh
brew install vhs
```

The CI job currently pins VHS `v0.11.0`; install that version directly with
`go install github.com/charmbracelet/vhs@v0.11.0` if you want the same renderer
locally. VHS requires `ttyd` and `ffmpeg` on `PATH`; install those too if your
package manager does not include them with VHS.

Generate the demos locally through Task:

```sh
task demos
```

`task docs` runs the demo generators before staging the site, then copies the
generated GIFs into `_site/assets/demos/` so the static HTML can embed
them. The homepage and spec chapters embed the generated mock survey/exploit
and MCP steps inline.

The current demos cover both saved-chain execution and from-scratch chain
construction against the Go mock survey and mock session-exploit modules. The
saved-chain demos use the checked-in
[`demo/chains/mock-survey-exploit.chain.yaml`](demo/chains/mock-survey-exploit.chain.yaml).
The direct saved-chain series runs a non-JSON throw so the live log stream is
visible, lists the resulting mock shell session, reads the prompt, sends
`whoami`, reads the response, attaches with `session connect` for several typed
commands, detaches, and then reconnects to the same session. The CLI session
series starts from a hidden completed throw and shows the same read/send and
attach/detach/reconnect operations inside `hovel cli`. The
command-construction demos create the operation chain with `chain create`,
`chain add`, `target add`, `target config set`, and `chain config set`, then
save the configured chain. They also list required chain and target config
before setting values, then list the resolved config afterward. The generator
first runs silent JSON throws and session interactions for both saved and
constructed chains as e2e checks. It also runs the mock Codex-style MCP agent
harness against a real `hovel mcp` subprocess and verifies that it throws the
mock exploit through MCP before rendering. The Docker/Wine Squatter MCP demo is
generated by `task demo:squatter-wine` and included by `task docs`. Visible VHS
tapes are rendered afterward without showing test harness output in the
recordings. Demos that interact with
sessions start an explicit daemon in hidden setup, because live module sessions
belong to the daemon process; a CLI-owned managed daemon shuts down when that
CLI exits. Each rendered GIF is capped at 15 seconds by the generator.

CI runs the `demos` job after the `build-test` job passes. That job installs
`ffmpeg`, `ttyd`, and pinned VHS directly, runs `task demos`, and uploads the
generated files as the `hovel-demos` workflow artifact. The CI docs job
downloads that artifact and stages `_site` with `task docs:stage`; the GitHub
Pages workflow runs after the CI workflow succeeds, regenerates the demos with
`task docs`, uploads `_site`, and deploys it. The source GIF paths are:

| Series | Step | Output |
| --- | --- | --- |
| CLI construction | Create operation chain | `demo/out/mock-survey-exploit-cli-commands-01-create.gif` |
| CLI construction | List required config | `demo/out/mock-survey-exploit-cli-commands-02-config-before.gif` |
| CLI construction | Apply and verify config | `demo/out/mock-survey-exploit-cli-commands-03-config-apply.gif` |
| CLI construction | Validate and save | `demo/out/mock-survey-exploit-cli-commands-04-save.gif` |
| Direct construction | Create operation chain | `demo/out/mock-survey-exploit-commands-01-create.gif` |
| Direct construction | List required config | `demo/out/mock-survey-exploit-commands-02-config-before.gif` |
| Direct construction | Apply and verify config | `demo/out/mock-survey-exploit-commands-03-config-apply.gif` |
| Direct construction | Validate and save | `demo/out/mock-survey-exploit-commands-04-save.gif` |
| Direct saved chain | Inspect modules | `demo/out/mock-survey-exploit-01-inspect.gif` |
| Direct saved chain | Throw with live logs | `demo/out/mock-survey-exploit-02-throw.gif` |
| Direct saved chain | Read and send session data | `demo/out/mock-survey-exploit-03-session-io.gif` |
| Direct saved chain | Attach, detach, reconnect | `demo/out/mock-survey-exploit-04-session-connect.gif` |
| CLI saved chain | Read and send session data | `demo/out/mock-survey-exploit-cli-02-session-io.gif` |
| CLI saved chain | Attach, detach, reconnect | `demo/out/mock-survey-exploit-cli-03-session-connect.gif` |
| Module packages | Link, list, and inspect lock state | `demo/out/module-package-install-01-link.gif` |
| MCP agent | Throw mock exploit through MCP | `demo/out/mcp-agent-01-throw.gif` |
| MCP agent | Operate Squatter payload through MCP | `demo/out/mcp-agent-02-squatter-wine.gif` |

To add a demo, add a `.tape` file under `demo/tapes/`, put reusable demo fixtures
such as configured chain files under `demo/`, and point the tape's GIF `Output`
directive at `demo/out/`. Split long flows into steps when it improves
readability. Put setup and validation commands in hidden tape sections,
`scripts/demo-step-setup.sh`, or `scripts/generate-demos.sh` so the GIF shows
only the operator-facing flow.

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

`hovel mcp` exposes typed catalog, workspace, chain-apply, throw, installed
payload, and payload-command tools. Agents should start with
`hovel_catalog_snapshot` and `hovel_workspace_snapshot`, use
`hovel_chain_apply` to create or update chain state, call `hovel_throw_start`,
then use `hovel_installed_payload_list` and `hovel_payload_cmd` for commands
such as `systeminfo`. `hovel_command_run` remains an escape hatch for command
registry verbs without typed MCP tools.

Root help also exposes compatibility and developer entrypoints such as `shell`,
`command`, `run`, direct registry roots (`module`, `chain`, `op`, ...), `init`,
and `status`. Prefer the role commands above in user-facing docs and examples.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes must pass `task ci`, which
is also enforced in CI.

## License

See [LICENSE](LICENSE).
