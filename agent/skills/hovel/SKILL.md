---
name: hovel
description: Operate Hovel through its typed MCP interface. Use for Hovel workspaces, operations, chains, targets, modules, throws, payloads, sessions, or artifacts.
license: Apache-2.0
compatibility: Requires Hovel 0.4.x and a configured Hovel MCP server.
metadata:
  hovel-min-version: "0.4.0"
  hovel-max-version: "0.5.0"
---

# Hovel

Use Hovel as an auditable operator platform, not as a generic command shell.

The stable mental model is:

```text
workspace
  operation
    targets
    chains
      modules
      configuration
      validation
      throw
  installed payloads
  sessions
  artifacts
```

Start with `hovel_operator_identity` and `hovel_workspace_snapshot`. Use
`hovel_catalog_snapshot` before choosing capabilities. Reuse suitable existing
state instead of creating duplicates.

Prefer typed Hovel MCP tools. Use `hovel_command_run` only when no typed tool
represents the capability. Never treat validation as authorization to execute.

Load the specialized Hovel skill matching the task:

- discovery and state orientation: `hovel-discovery`
- operations, targets, chains, modules, and validation: `hovel-chain-building`
- planning, confirming, and starting a throw: `hovel-throw`
- installed payload operations: `hovel-payloads`
- established session interaction: `hovel-sessions`
- result and artifact inspection: `hovel-artifacts`
- failures, stale state, and recovery: `hovel-troubleshooting`

Do not conflate a target with an installed payload, a payload with a session,
an artifact with a payload, a chain with a throw, or a valid plan with approval.
Read `references/workflow.md` and `references/safety-model.md` when the task
crosses more than one lifecycle boundary. Read `references/capability-map.md`
when choosing between retained-session operations and new execution or artifact
collection, and `references/error-recovery.md` when discovery or a session fails.
