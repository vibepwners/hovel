# Configuration and Distribution

Configuration should be explicit, schema-validated, and easy to inspect.

## Global Config

```yaml
theme: acid
workspace: .hovel
modules:
  searchPaths:
    - ./modules
    - ~/.hovel/modules
services:
  searchPaths:
    - ./services
    - ~/.hovel/services
runtime:
  python:
    interpreter: python3
    preferPex: true
logging:
  level: info
  captureStdout: sdk
  captureStderr: true
```

## Workspace Config

```yaml
name: lab
artifactRetentionDays: 30
allowDangerousModules: false
requireAuthorizationBanner: true
defaultConcurrency: 8
services:
  autoStart: []
  allowRunScoped: true
policy:
  requirePlanApproval: true
  requireConfirmationFor:
    - external_bind
    - dangerous_module
    - credential_use
  mcp:
    parity: true
    requirePlanReview: true
```

Module and service configs should be schema-validated.

## Build Strategy

Hovel should start as a monorepo because built-in modules, services, SDKs, schemas, CLI, TUI, API, and MCP adapters need to evolve together.

Bazel is the authoritative build, test, docs, and release interface from day one. Ordinary Go and Python tooling may remain useful for local authoring, but CI and project workflows should go through Bazel.

Initial Bazel responsibilities:

1. Build and test all Go packages and binaries.
2. Build and test the Python SDK.
3. Build the mdBook spec from pinned prebuilt tools.
4. Run Gazelle for Go BUILD file generation.
5. Own generated schemas and contract-test outputs.
6. Produce release archives when binaries exist.

The minimum repository contract is:

```bash
bazel build //...
bazel test //...
bazel run //:gazelle
```

Non-Bazel scripts should be convenience wrappers over Bazel targets, not alternate build systems.

## Distribution

Primary distribution should be native Go binaries:

```text
hovel-linux-amd64
hovel-linux-arm64
hovel-darwin-arm64
hovel-windows-amd64.exe
hoveld-linux-amd64
hoveld-linux-arm64
hoveld-darwin-arm64
hoveld-windows-amd64.exe
```

The `hovel` binary is the production mono-binary. It includes `command`, `cli`, `daemon`, and `tui` roles. A separate `hoveld` binary may exist only as a development shim if it materially improves local testing; it is not the product contract.

Hovel may also publish a PyPI wrapper for Python-centric users:

```bash
uvx hovel command throw --chain ssh-memory --target 10.41.32.2
```

The PyPI package may download or include the Go binary, similar to other compiled tools distributed through Python package indexes.

Module and service sources:

1. Built-in modules and services in the monorepo.
2. Local module and service directories.
3. Git repositories.
4. PEX packages.
5. Native binaries.
6. Future registry.

## Terminal Libraries And Theming

The interactive `cli` shell should use go-prompt for prompt input, history, suggestions, and completions. The `cli` shell and TUI should share a small theme system without making theme work part of the critical MVP path. Lip Gloss is the styling engine for terminal presentation, with shared tokens for colors, borders, severity, focus, muted text, success, warning, danger, and active run state.

Initial theme names:

```text
31337
acid
bloodmoon
ghost
crt
paperhovel
midnight
amberterm
```

The visual target is a readable 1337 operator console with high contrast, tight navigation, and clear live status. The look should feel distinctive, but output must remain usable in low-color terminals, over SSH, in logs, and with `--no-color`. Animation should clarify state changes, not compete with the work.
