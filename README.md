# Hovel

![Hovel](docs/site/public/assets/hovel.png)

Hovel is a Go-hosted framework for authorized red-team emulation, controlled
lab exercises, defensive validation, and operator workflow automation. It is
designed for scoped, auditable assessments rather than general-purpose dual-use
automation.

The daemon role (`hovel daemon serve`, often called `hoveld` in docs and logs)
owns the workspace database, module process lifecycle, persisted throw
plans, confirmation records, installed payload inventory, artifacts, sessions,
Mesh listener/task/stream bookkeeping, encrypted workspace PKI custody, and
structured events. Operators use the same application services through the
interactive CLI, one-shot saved-chain execution, and the MCP agent front end.
Managed local use defaults to an owner-only Unix socket; explicit daemon and
client configuration also supports TCP between containers on a protected
network.

> **Authorized red-team emulation only.** Use Hovel only in environments you own
> or are explicitly authorized to assess, with written scope and approvals. See
> [SECURITY.md](SECURITY.md).

## Documentation

The canonical documentation is the GitHub Pages book:

## [vibepwners.github.io/hovel](https://vibepwners.github.io/hovel/index.html)

Start with the [User Guide](docs/site/src/content/spec/user-guide.html) to run Hovel locally. Module
authors should use [Module Development](docs/site/src/content/spec/module-development.html), then the
language guides for [Python](docs/site/src/content/spec/module-python.html), [Go](docs/site/src/content/spec/module-go.html),
or [Rust](docs/site/src/content/spec/module-rust.html). For the trust system, read
[TLS and Workspace PKI](docs/site/src/content/spec/tls-pki.html) and the
[TLS Operations runbook](docs/site/src/content/spec/tls-operations.html). Mesh and
provider authors should continue with [Mesh Development](docs/site/src/content/spec/mesh-development.html)
and [Credential Provider Development](docs/site/src/content/spec/credential-provider-development.html).
Contributors should read the
[Development Guide](docs/site/src/content/spec/development-guide.html) for Task, CI, and
partial-checkout behavior. The source for the book lives under
[`docs/site/src/content/`](docs/site/src/content/).

For split-container deployments, see
[Connect Across Containers](docs/site/src/content/spec/user-guide.html#connect-across-containers)
for a working server/client recipe and the
[Daemon RPC transport reference](docs/site/src/content/spec/daemon-rpc.html#transport)
for listener precedence, access modes, environment variables, and the plaintext
TCP security model.

The official [Agent Integrations](docs/site/src/content/spec/agent-integrations.html)
package Hovel skills and MCP configuration for Claude Code, Codex, and OpenCode:

```sh
hovel agent install claude
hovel agent install codex
hovel agent install opencode
```

## Install

The operator install is the `hovel` PyPI package. It contains the
platform-specific Go binary and does not download the binary at install time.

```sh
pipx install hovel
hovel status
```

The Python module SDK ships separately:

```sh
python -m pip install hovel-sdk
```

The `hovel` package includes no modules by default. Install only modules you
trust:

```sh
hovel module install ./path/to/module.tgz
hovel module install --link /absolute/path/to/module-package-root
hovel module install name          # newest local package, then configured indexes
hovel module install name@version  # exact local package, then configured indexes
hovel module available   # locally installable packages and caches
hovel module installed   # modules whose install process completed
```

## Develop

Aspect CLI is the single entry point for building, testing, linting,
formatting, release artifacts, and local runs. Do not call Bazel, gofmt, uv, or
Lefthook directly.

```sh
aspect help
python3 repo-tools/tasks/checkout.py status
aspect hovel cli
aspect test
aspect hovel-check
aspect hovel-check
```

Useful commands:

| Command | Description |
| --- | --- |
| `aspect hovel cli` | Build and launch the interactive CLI with the dev workspace. |
| `aspect hovel mcp` | Launch the MCP agent front end for the dev workspace. |
| `python3 repo-tools/tasks/checkout.py status` | Show which repository slices are present. |
| `aspect hovel-check` | Run checks for the slices present in this checkout. |
| `cd core && aspect build` | Build the core Hovel binary workspace. |
| `cd core && aspect test` | Run the core Hovel binary workspace tests. |
| `aspect hovel-check core` | Run core Go formatting, golangci-lint, and Gazelle checks. |
| `aspect hovel-format` | Format wired slices: core Go/Gazelle plus Go SDK sources. |
| `aspect test --coverage` | Run core domain and application coverage ratchets. |
| `aspect hovel-check` | Require a full checkout, then run the core, SDK, modules, and docs gates. |
| `aspect hovel-check docs` | Build and validate the hermetic Astro documentation site. |
| `aspect hovel-check agent` | Validate the portable skill suite and host packages. |
| `aspect hovel-release agent` | Build versioned Claude, Codex, and OpenCode integration archives. |
| `aspect run //docs/tools/docs:stage_site` | Materialize the documentation site under `_site/`. |

## Repository layout

The repository is organized for Sapling sparse profiles:

| Path | Purpose |
| --- | --- |
| `core/` | Self-contained Hovel framework workspace: `hoveld`, CLI/TUI/MCP front ends, schemas, core tests, and core build tooling. |
| `sdk/` | Python, Go, and Rust module SDKs. These are intentionally outside core so SDK work can be checked out independently. |
| `modules/` | In-repo example modules, Squatter payload/provider code, module packaging tools, and lab helpers. |
| `docs/` | Pages source, book content, demos, and documentation tooling. |
| `agent/` | Canonical Hovel Agent Skills and deterministic host-package tooling. |
| `repo-tools/` | Repository-level helpers that must remain available in sparse checkouts. |

## Cool projects using hovel

- [Burrow](https://github.com/Bochner/burrow) — [Documentation](https://bochner.github.io/burrow/index.html).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). During sparse work, use `aspect hovel-check` to
run the checks available in the checkout. Changes should pass the relevant
slice checks before landing; `aspect hovel-check` is the full-checkout gate for core, SDKs,
modules, docs, demos, and release-package smoke checks.

## License

See [LICENSE](LICENSE).
