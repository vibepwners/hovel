# Hovel SDKs

Use this directory when you are writing a module process, not when you are
changing the daemon. A Hovel module is launched as a separate process and driven
over stdin/stdout with Content-Length framed JSON-RPC 2.0.

The practical contract is simple:

- stdout belongs to the RPC transport. Do not print banners, prompts, progress,
  debug logs, or child-process output there.
- logs and diagnostics go through the SDK logger or stderr.
- `handshake` and `schema` must be cheap and side-effect free.
- target interaction belongs in `execute`, `step.execute`, or explicit provider
  methods after the operator has a persisted plan and confirmation.
- return artifacts, sessions, findings, outputs, and installed payload records
  explicitly; do not hide important operator-controlled values.

## Choose a SDK

| SDK | Use it when | Current surface |
| --- | --- | --- |
| [Python](python/README.md) | You want the fastest exploit or post-exploitation iteration loop. | Core modules, async/sync `run`, line shell sessions, step hooks, installed-payload records, framed RPC tests. |
| [Go](go/README.md) | You want typed provider/step contracts or close alignment with the daemon. | Core modules, PTY sessions, payload-provider RPC methods, step-provider RPC methods, `hoveltest` helpers. |
| [Rust](rust/README.md) | You want a small dependency-light module binary. | Core modules, line shell sessions, installed-payload records. No step/provider dispatch yet. |

The canonical module-author guide is the static spec page at
[`../spec/module-development.html`](../spec/module-development.html). The
language-specific pages are
[`../spec/module-python.html`](../spec/module-python.html),
[`../spec/module-go.html`](../spec/module-go.html), and
[`../spec/module-rust.html`](../spec/module-rust.html).

## Fast Feedback

Run focused checks while developing a module, then run the full gate before
calling the work done.

```sh
task test -- //sdk/python:hovel_sdk_test
task test -- //sdk/go/hovel:hovel_test
task test -- //sdk/go/hoveltest:hoveltest_test
task test -- //sdk/rust/hovel:hovel_test

task test -- //examples/python/...
task test -- //examples/go/...
task test -- //examples/rust/...

task ci
```

Build and stage the in-tree Go and Rust example binaries with:

```sh
task modules:build
```

The staged binaries are referenced by [`../examples/hovel-modules.json`](../examples/hovel-modules.json).
Python examples are loaded from their `project_dir` and `module` fields instead
of staged native binaries.
