# Use Mesh for node operations

Hovel will use **Mesh** as the umbrella term for SDK capabilities that own one
or more nodes, links, routes, tasks, surveys, upload/execute operations,
commands, triggers, beacons, and byte streams. We deliberately rejected
"transport" and "tunnel" for the framework name because both are narrower byte
movement concepts already implied by existing `TransportEndpoint` and session
language; a Mesh may expose tunnels, but it is not only a tunnel.

Mesh requests distinguish the pivot from the reached system. `nodeId` and
`route` identify the Mesh path; `destinationHost`, `destinationPort`, and
`protocol` identify a service reachable through that path. Providers advertise
which task kinds accept node, route, or destination targets with
`targetScopes`. This keeps "throw an exploit through a node" as an SDK/runtime
contract without making Mesh providers responsible for implementing every
exploit module.
