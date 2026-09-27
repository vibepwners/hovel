# Capability map

Use typed discovery tools to obtain current details from the running Hovel:

- identity and collaborators: `hovel_operator_identity`, operator entity tools
- state: `hovel_workspace_snapshot`, operation and chain capability tools
- modules: `hovel_catalog_snapshot`, `hovel_module_search`, `hovel_module_inspect`
- construction: `hovel_chain_suggest`, `hovel_chain_apply`, validation tools
- execution: `hovel_launch_key_policy`, `hovel_throw_plan`,
  `hovel_throw_confirm`, `hovel_throw_start`
- payloads: `hovel_installed_payload_list`, `hovel_payload_capabilities`,
  `hovel_payload_call`
- sessions: session list tools, `hovel_session_capabilities`, `hovel_session_call`
- artifacts: typed artifact list and inspection capability tools

This map is strategic, not a schema reference. Read the MCP tool descriptions and
input schemas exposed by the connected Hovel version before calling a tool.

## Integration choices

| Need | Decision |
| --- | --- |
| Operate an existing retained connection | Inspect its session capabilities, then call the advertised typed operation on the same owner; an installed payload is not required. |
| Refresh stale catalog knowledge | Read authoritative catalog state before replacing working assumptions; report fetch errors and preserve the last usable context. |
| Keep a session available after viewing it | Detach; explicit close ends the retained owner and subsequent calls must fail. |
| Produce durable execution evidence | Use the supported confirmed throw/artifact path and inspect the persisted result; session command output alone is not that evidence. |
| Request resize or controller behavior | Discover provider-owned commands; do not assume a native geometry or controller API. |
| Attach to an arbitrary existing daemon | Follow the integrator's supported attachment policy; build/version metadata is not authentication or an implemented compatibility negotiation contract. |
| Adopt a source fix | Verify the official runtime actually contains it and validate the downstream workflow before removing workarounds. |
