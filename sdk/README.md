# Hovel SDKs

Use this directory when you are writing a module process, not when you are
changing the daemon. A Hovel module is launched as a separate process and driven
over stdin/stdout with Content-Length framed JSON-RPC 2.0.

The practical contract is simple:

- stdout belongs to the RPC transport. Do not print banners, prompts, progress,
  debug logs, or child-process output there.
- logs and diagnostics go through the SDK logger or stderr.
- `handshake` and `schema` must be cheap and side-effect free.
- `handshake` is the authoritative source for module identity, type, summary,
  tags, and context. `name`, `version`, and `moduleType` are required there.
- `hovel-module.yaml` is for package installation and launch instructions. It
  may include light `metadata.name`/`metadata.version` hints for offline tools,
  but runtime catalog/install identity is resolved from the RPC handshake.
- target interaction belongs in `execute`, `step.execute`, or explicit provider
  methods after the operator has a persisted plan and confirmation.
- return artifacts, sessions, findings, outputs, and installed payload records
  explicitly; do not hide important operator-controlled values.
- agent context is optional. Modules can ignore it; modules that opt in may read
  the SDK agent field and return `agentHints` with provenance.

## Choose a SDK

| SDK | Use it when | Current surface |
| --- | --- | --- |
| [Python](python/README.md) | You want the fastest exploit or post-exploitation iteration loop. | Core modules, async/sync `run`, line shell sessions, step hooks, installed-payload records, optional agent context and hints, framed RPC tests. |
| [Go](go/README.md) | You want typed provider/step contracts or close alignment with the daemon. | Core modules, PTY sessions, payload-provider RPC methods, step-provider RPC methods, optional agent context and hints, `hoveltest` helpers. |
| [Rust](rust/README.md) | You want a small dependency-light module binary. | Core modules, line shell sessions, installed-payload records, raw optional agent context and hints. No step/provider dispatch yet. |

The canonical module-author guide is the static spec page at
[`../docs/site/spec/module-development.html`](../docs/site/spec/module-development.html). The
language-specific pages are
[`../docs/site/spec/module-python.html`](../docs/site/spec/module-python.html),
[`../docs/site/spec/module-go.html`](../docs/site/spec/module-go.html), and
[`../docs/site/spec/module-rust.html`](../docs/site/spec/module-rust.html).

## Fast Feedback

The SDK slice has been split out of the core Bazel workspace. The root task
dispatcher can format the Go SDK today, and it reports the SDK slice during
partial-checkout checks. Language-specific SDK test/package tasks still need
their own slice-local workspace before they can be restored.

```sh
task sdk:fmt
task check
```

Example modules now live under `modules/examples/`. Module packaging and
example-binary staging are part of the modules slice and are not wired into the
root dispatcher yet.

Install or link a module package before running it:

```sh
hovel module install ./my-module-0.1.0.tgz
hovel module install --link /absolute/path/to/module-package-root
```

Python modules can use Hovel-managed python-build-standalone, an operator
interpreter, or a bundled interpreter declared in `hovel-module.yaml`; Go and
Rust modules usually package compiled binaries as launch entries.
