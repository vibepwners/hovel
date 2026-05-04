# Introduction

Status: Draft 0.3

Audience: Hovel maintainers, module authors, service authors, and operator-tooling engineers.

Hovel is a Go-hosted framework for authorized security research, adversary emulation, lab exploitation, defensive validation, and operator workflow automation.

Hovel is a platform for wrapping and operating third-party proofs of concept, not a catalog of first-party exploits. The project should provide the engine, SDKs, descriptors, providers, guardrails, examples, and operator experience that make third-party modules acceptable to run and inspect.

The main product goal is straightforward:

> Make modules easy to write, keep long-lived capabilities managed by the engine, and give operators a clear view of every throw.

The central runtime is a local engine, `hoveld`, which owns operations, chains, throws, module processes, managed services, provider state, structured events, artifacts, and workspace storage. Interactive `cli` mode, one-shot chain-file execution, TUI, REST/OpenAPI, and MCP are clients or adapters over the same application services.

## Core Decisions

1. The host is written in Go.
2. Python is the first-class module authoring language.
3. `hoveld` is mandatory; invoking `hovel` starts or attaches to a daemon.
4. Modules run as bounded processes through normal module runtime contracts.
5. Long-lived capabilities are managed as services.
6. Providers expose typed resources such as payloads, artifacts, facts, credentials, listeners, and sessions.
7. Payload providers return tagged bytes with minimal framework validation.
8. Throws emit structured events onto a shared logging rail consumed by every front end and persistence sink.
9. The first implementation is local-first and alpha-friendly.

## Product Shape

Hovel exposes one engine through multiple front ends:

```text
 +--------------+ +--------------+ +--------------+
 |  one-shot    | |     cli      | |     TUI      |
 +------+-------+ +------+-------+ +------+-------+
        |                |                |
+-------v------+ +-------v------+ +-------v------+
|     MCP      |>|   hoveld     |<| REST/OpenAPI |
+--------------+ | Application  | +--------------+
                 |   Services   |
                 +------+-------+
                        |
                 +------v-------+
                 | Domain Core  |
                 +------+-------+
                        |
         +--------------+-----------------+
         |              |                 |
 +-------v------+ +-----v-------+ +-------v------+
 | Module Host  | | Service Mgr | | Provider Reg |
 +-------+------+ +-----+-------+ +-------+------+
         |              |                 |
 +-------v------+ +-----v-------+ +-------v------+
 | module       | | payloads,   | | artifacts,   |
 | processes    | | listeners,  | | facts,       |
 |              | | sessions    | | credentials  |
 +--------------+ +-------------+ +--------------+
```

All front ends must call the same application services. The TUI must not contain business logic. The MCP adapter must not bypass validation. One-shot execution and `cli` mode must not implement their own chain runners. The REST API must not become a second framework.

## MVP Boundaries

The MVP should avoid pretending to be the final platform. Defer:

1. Distributed team-server architecture.
2. Persistent multi-user RBAC.
3. Public module marketplace semantics.
4. Automatic stealth guarantees.
5. Browser UI.
6. Mandatory container isolation.
7. First-party exploit or payload corpus.

The first MVP slice should prove the narrowest useful loop:

1. Initialize a local workspace.
2. Start or attach to `hoveld` from `hovel`.
3. Load and validate one module descriptor.
4. Launch one Python module through the SDK path.
5. Complete handshake, execution, logging, and shutdown.
6. Emit structured events through the shared logging rail.
7. Persist the throw plan, confirmation record, event records, artifacts, and replayable throw record.
8. Inspect the throw from the CLI.
9. Save and load targetless chain templates and configured chain YAML files for reuse and one-shot execution.

The alpha can then add managed services, provider-backed payload resolution, richer chains, MCP execution parity, and the TUI. Those features should attach to the proven loop rather than expanding the platform surface before the core path works.

## Alpha Deferrals

The following decisions should remain open until the core loop has contract tests and at least one replayable throw:

1. Whether chains are only declarative YAML or also authorable in Python or Go.
2. Whether REST ships in the first alpha or follows the CLI and TUI.
3. Whether service processes and module processes share one protocol.
4. How much provider state is persisted versus run-scoped.
5. Which isolation mechanisms are required beyond process supervision and Python dependency isolation.
