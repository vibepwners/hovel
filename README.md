# Hovel

![Hovel](assets/hovel.png)

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

## [vibe-pwners.github.io/hovel](https://vibe-pwners.github.io/hovel/index.html)

Start with the [User Guide](spec/user-guide.html) to run Hovel locally. Module
authors should use [Module Development](spec/module-development.html), then the
language guides for [Python](spec/module-python.html), [Go](spec/module-go.html),
or [Rust](spec/module-rust.html). The source for the book lives under
[`spec/`](spec/).

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
formatting, docs, release artifacts, and local runs. Do not call Bazel, gofmt,
uv, or Lefthook directly.

```sh
task --list
task start
task test
task ci
```

Useful tasks:

| Task | Description |
| --- | --- |
| `task start` | Build and launch the interactive CLI with the dev workspace. |
| `task mcp` | Launch the MCP agent front end for the dev workspace. |
| `task build` | Build all targets. |
| `task test` | Run all Bazel tests. |
| `task lint` | Run Go formatting, golangci-lint, Gazelle, Rust, Python, and Squatter C checks. |
| `task docs` | Build cached demos, stage the Pages site, generate SDK API docs, and check internal links. |
| `task coverage` | Run domain, application, and Python SDK coverage ratchets. |
| `task ci` | Run the local gate: lint, version-update tests, docs, build, tests, race, fuzz smoke, and coverage. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes should pass `task ci`; CI uses
the same Task-backed build, docs, lint, test, race, fuzz smoke, and coverage
entry points.

## License

See [LICENSE](LICENSE).
