# Safety and Scope

Hovel is intended for authorized security testing, adversary emulation, internal lab research, CTF-style training, defensive validation, and controlled red-team development.

The framework may orchestrate dangerous primitives because realistic security tooling often requires them. Public documentation and examples should emphasize authorization, lab use, auditability, reproducibility, and operator accountability.

Public examples should prefer benign transports, local lab devices, toy payloads, and non-destructive demonstrations. The first demonstration may use authenticated SSH because it is easy to reason about, easy to log, and does not require publishing exploit code.

## Caller Trust Model

Hovel does not treat human operators, AI agents, CLI clients, TUI clients, REST clients, or MCP clients as inherently trusted. Every caller uses the same application services, validation model, scope guardrails, and audit trail.

MCP should eventually be able to do everything an operator can do. Safety should come from shared guardrails, explicit confirmations, descriptor metadata, module-level validation, throw planning, and auditability, not from giving MCP a weaker private API.

MCP execution parity should be phased. Inspection and planning tools may ship first. Execution tools should require the same plan review, explicit confirmation records, and audit events as CLI and REST before they are enabled.

Third-party modules and services are explicitly supported. Hovel cannot prove arbitrary third-party code is safe; it provides descriptors, process supervision, scope guardrails, logs, artifacts, and replayable records so operators can make informed decisions.

## Safety Requirements

1. Every throw must start from a persisted throw plan.
2. Starting a throw must require an explicit recorded confirmation that the plan was reviewed. In interactive flows this means the operator saw the final configuration and typed `yes`, or deliberately used `throw --now`.
3. Throws must record operator intent, inputs, target IDs, timestamps, module versions, service versions, payload hashes, artifacts, evidence, and errors.
4. Public modules should avoid destructive behavior by default.
5. Workspace config should support an explicit `allowDangerousModules` gate.
6. Listeners binding beyond localhost should require explicit configuration.
7. MCP execution tools should require the same validation and audit trail as CLI and REST execution.
8. Artifacts should be content-addressed or hash-tracked.
9. Chain cleanup steps should be visible and evented.
10. Throw plans should surface risk labels, external binds, file writes, credential use, network reachability, and cleanup behavior before execution.
11. Modules should have maximum practical optionality to perform validation, survey, compatibility checks, and target-specific safety checks before performing work.

`throw --now` is an explicit bypass of the typed confirmation prompt, not a bypass of planning, persistence, guardrails, logging, artifact handling, or audit records. The confirmation record for a `--now` throw must preserve that the bypass flag was used.

Hovel should not impose corporate secret-management behavior on chain configuration. Passwords, tokens, keys, and other sensitive values are ordinary operator-controlled configuration values. Operators are responsible for securing their machines, workspaces, and data sources. Hovel may support config value types and validation, but it must not silently redact, omit, or special-case saved configuration values in a way that degrades offensive workflow ergonomics.

## Code Trust Model

MVP assumes local single-user or trusted small-team infrastructure, but not trusted intent. The operator chooses modules and services to throw, while Hovel records decisions and enforces configured scope guardrails. Hovel should isolate where practical, but should not imply that arbitrary third-party code is safe.

Initial isolation levels:

```text
none        local process, full user privileges
process     separate supervised process
venv        Python virtual environment isolation
pex         packaged Python dependency isolation
binary      native binary process isolation
container   future optional container isolation
remote      future remote service isolation
```
