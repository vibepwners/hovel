---
name: hovel-sessions
description: Discover, inspect, read from, and deliberately interact with established Hovel sessions without launching new throws.
license: Apache-2.0
compatibility: Requires Hovel 0.4.x and a configured Hovel MCP server.
metadata:
  hovel-min-version: "0.4.0"
  hovel-max-version: "0.5.0"
---

# Hovel sessions

List existing sessions through the typed session capability, select the session
that matches the user's operation and target, then inspect
`hovel_session_capabilities`. Read current context before writing. Invoke an
advertised operation with `hovel_session_call` only when required by the request,
then read the resulting state.

Do not create a throw to satisfy a request about an already established session.
Do not assume every session is a shell or invent commands absent from its
capabilities. Keep payload installation, throw execution, and session interaction
as distinct lifecycles.

An ordinary retained session may advertise typed commands without an installed
payload record. Discover its actual capabilities and route calls to that existing
session; do not invent a payload record or recreate an owner after explicit close.
A privileged session call does not itself create a confirmed throw, a generic
durable completion event, or a persisted output artifact. If the requested work
needs reviewed execution or durable artifact collection, use the supported
confirmed throw/artifact workflow and verify the resulting evidence.

Detach and explicit close are different: native terminal detach preserves the
session. Native geometry, resize, and controller APIs are not implied by terminal
restoration; use provider-advertised operations only when present. Do not assume
uncollected module-held output will survive daemon or module failure.
