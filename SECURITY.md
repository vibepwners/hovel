# Security Policy

## Authorized use

Hovel is a framework for **authorized** security testing, adversary emulation,
internal lab research, CTF-style training, defensive validation, and controlled
red-team development. It can orchestrate dangerous primitives because realistic
security tooling often requires them.

Only use Hovel against systems you own or for which you have explicit, written
authorization to test. You are responsible for staying within the scope of that
authorization and for complying with all applicable laws and agreements.

The maintainers provide Hovel for legitimate research and defensive use and do
not condone unauthorized access to systems or data.

## Safety model

Hovel does not treat any caller — human operator, AI agent, CLI, TUI, REST, or
MCP client — as inherently trusted. Safety is intended to come from shared
guardrails, explicit confirmations, descriptor metadata, module-level
validation, throw planning, and an auditable record, not from giving any
front end a weaker private API.

Key safety properties (see `spec/safety.html` for the full model):

- Every throw starts from a persisted throw plan.
- Starting a throw requires a recorded confirmation that the plan was reviewed
  (typed `yes`, or a deliberate `throw --now`, which still records that the
  bypass flag was used).
- Throws record operator intent, reviewed configuration, target IDs, timestamps,
  module references, installed payload descriptors, materialized artifact
  hashes, structured events, and errors. Planned audit fields such as resolved
  service versions and richer risk labels should be added only when the source
  path emits them.
- Public modules should avoid destructive behavior by default.
- Artifacts are hash-tracked.

## Reporting a vulnerability

If you discover a security vulnerability in Hovel itself, please report it
privately rather than opening a public issue.

- Preferred: open a [GitHub security advisory](https://github.com/Vibe-Pwners/hovel/security/advisories/new)
  for the repository.
- Please include a description, affected versions/commits, reproduction steps,
  and any suggested remediation.

Please do not include details of vulnerabilities in third-party targets you
discovered *using* Hovel — report those to the affected vendor through their own
disclosure process.

We aim to acknowledge reports within a reasonable time and will coordinate a
fix and disclosure timeline with you.

## Supported versions

Hovel is pre-1.0 (alpha). Security fixes target the `main` branch. Pin to a
specific commit if you need stability.
