# Hovel

![Hovel](docs/site/assets/hovel.png)

Hovel is a Go-hosted framework for authorized red-team emulation, controlled
lab exercises, defensive validation, and operator workflow automation. It is
designed for scoped, auditable assessments rather than general-purpose dual-use
automation.

The local daemon role (`hovel daemon serve`, often called `hoveld` in docs and
logs) owns the workspace database, module process lifecycle, persisted throw
plans, confirmation records, installed payload inventory, artifacts, sessions,
and structured events. Operators use the same application services through the
interactive CLI, one-shot saved-chain execution, and the MCP agent front end.

> **Authorized red-team emulation only.** Use Hovel only in environments you own
> or are explicitly authorized to assess, with written scope and approvals. See
> [SECURITY.md](SECURITY.md).

## Documentation

The canonical documentation is the GitHub Pages book:

## [vibepwners.github.io/hovel](https://vibepwners.github.io/hovel/index.html)

Start with the [User Guide](docs/site/spec/user-guide.html) to run Hovel locally. Module
authors should use [Module Development](docs/site/spec/module-development.html), then the
language guides for [Python](docs/site/spec/module-python.html), [Go](docs/site/spec/module-go.html),
or [Rust](docs/site/spec/module-rust.html). Contributors should read the
[Development Guide](docs/site/spec/development-guide.html) for Task, CI, and
partial-checkout behavior. The source for the book lives under
[`docs/site/spec/`](docs/site/spec/).

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

`Taskfile.yml` is the single entry point for building, testing, linting,
formatting, release artifacts, and local runs. Do not call Bazel, gofmt, uv, or
Lefthook directly.

```sh
task --list
task checkout:status
task start
task test
task check
task ci
```

Useful tasks:

| Task | Description |
| --- | --- |
| `task start` | Build and launch the interactive CLI with the dev workspace. |
| `task mcp` | Launch the MCP agent front end for the dev workspace. |
| `task checkout:status` | Show which repository slices are present in this checkout. |
| `task check` | Run checks for the slices present in this checkout. |
| `task build` | Build the core Hovel binary workspace. |
| `task test` | Run the core Hovel binary workspace tests. |
| `task lint` | Run core Go formatting, golangci-lint, and Gazelle checks. |
| `task fmt` | Format wired slices: core Go/Gazelle plus Go SDK sources. |
| `task coverage` | Run core domain and application coverage ratchets. |
| `task ci` | Require a full checkout, then run the core, SDK, modules, and docs gates. |

## Repository layout

The repository is organized for Sapling sparse profiles:

| Path | Purpose |
| --- | --- |
| `core/` | Self-contained Hovel framework workspace: `hoveld`, CLI/TUI/MCP front ends, schemas, core tests, and core build tooling. |
| `sdk/` | Python, Go, and Rust module SDKs. These are intentionally outside core so SDK work can be checked out independently. |
| `modules/` | In-repo example modules, Squatter payload/provider code, module packaging tools, and lab helpers. |
| `docs/` | Pages source, book content, demos, and documentation tooling. |
| `repo-tools/` | Repository-level helpers that must remain available in sparse checkouts. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). During sparse work, use `task check` to
run the checks available in the checkout. Changes should pass the relevant
slice checks before landing; `task ci` is the full-checkout gate for core, SDKs,
modules, docs, demos, and release-package smoke checks.

## License

See [LICENSE](LICENSE).
