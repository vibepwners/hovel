# Use Mesh for node operations

Hovel will use **Mesh** as the umbrella term for SDK capabilities that own one
or more nodes, links, routes, tasks, surveys, upload/execute operations,
commands, triggers, beacons, streams, datagrams, and protocol-specific flows.
We deliberately rejected "transport" and "tunnel" for the framework name
because both are narrower byte movement concepts already implied by existing
`TransportEndpoint` and session language; a Mesh may expose tunnels, but it is
not only a tunnel.

Local socket forwarding is a daemon-owned **Mesh Bridge**, not a requirement
for every Mesh provider. Providers expose routed session flows; the daemon
binds a loopback TCP or UDP socket, pumps bytes or datagrams to that session,
records lifecycle in Mesh operation bookkeeping, and hands ordinary modules a
local endpoint. A bridge is one routed session lifecycle; callers open another
bridge for another independent local socket association. A UDP bridge accepts
one local peer and requires its returned `SessionRef.capabilities` to include
`datagram`; every non-empty session read and write is then exactly one datagram.
The daemon session broker preserves those message boundaries instead of
coalescing them into its normal byte stream. A provider datagram that arrives
before the first local packet waits for that peer instead of being discarded.
Non-socket protocols such as ICMP or raw IP stay in the Mesh task/session
contract unless Hovel adds an explicit raw/TUN/TAP-style local adapter.

The loopback endpoint is a local-user trust boundary, not an authentication
mechanism. Hovel never binds a Mesh Bridge to a non-loopback address, but an
untrusted process running as the operator could still race the intended client
for a newly opened endpoint. Deployments must protect the operator account and
daemon host accordingly.

Mesh requests distinguish the pivot from the reached system. `nodeId` and
`route` identify the Mesh path; `destinationHost`, optional
`destinationPort`, and `protocol` identify a service or protocol reachable
through that path. Providers advertise which task kinds accept node, route, or
destination targets with `targetScopes`. This keeps "throw an exploit through a
node" as an SDK/runtime contract without making Mesh providers responsible for
implementing every exploit module.
