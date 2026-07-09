# Hovel

Hovel is the local, auditable operator platform for scoped red-team emulation.
This context records product language that should stay stable across daemon,
SDK, docs, and module examples.

## Language

**Mesh**:
An addressable node operations plane owned by a module or service.
_Avoid_: Transport, tunnel, C2

**Mesh Node**:
One operator-addressable participant in a Mesh, such as the controller, a
target-side agent, a relay, or a managed implant.
_Avoid_: Peer, hop

**Mesh Link**:
A communication edge between two Mesh Nodes.
_Avoid_: Transport

**Mesh Route**:
An ordered path across Mesh Nodes and Mesh Links used for a task or stream.
_Avoid_: Tunnel

**Mesh Task**:
A requested node, route, or destination operation, such as survey, upload,
execute, upload_execute, command, load, or stream setup.
_Avoid_: Payload command when the operation is not tied to installed payload inventory

**Mesh Destination**:
A host or service reachable through a Mesh Node or Mesh Route but not itself a
Mesh Node. This is how Hovel models pivoted tooling, such as running an exploit
against a service connected to a relay node.
_Avoid_: Overloading Target when the distinction between pivot node and reached
host matters

**Beacon**:
A time-stamped signal from a Mesh Node that proves the node is alive or has
new work/status to report.
_Avoid_: Callback when referring to repeated node liveness

**Trigger**:
A declared condition that can cause a Mesh Task or Beacon transition.
_Avoid_: Schedule when the condition is not time based

## Relationships

- A **Mesh** contains one or more **Mesh Nodes**.
- A **Mesh Node** may connect to other **Mesh Nodes** through **Mesh Links**.
- A **Mesh Route** crosses one or more **Mesh Nodes** and zero or more
  **Mesh Links**.
- A **Mesh Task** targets one **Mesh Node**, one **Mesh Route**, or one
  **Mesh Destination** reached through a node or route.
- A **Mesh Destination** is described by destination host, destination port, and
  protocol on task and stream requests.
- A **Beacon** belongs to exactly one **Mesh Node**.
- A **Trigger** belongs to one **Mesh** and may reference one **Mesh Node**.
- A **TransportEndpoint** remains a narrower chain capability for byte movement;
  it is not the umbrella name for node tasking, surveys, triggers, or beacons.

## Example dialogue

> **Dev:** "Should the Rust tunnel module be modeled as a Transport?"
> **Domain expert:** "No — the module owns a **Mesh**. It may expose a
> **Mesh Route** that Hovel later bridges to a local port, but the same
> **Mesh** also supports **Mesh Tasks** such as survey, upload, execute,
> command, triggers, and beacons."

## Flagged ambiguities

- "transport" was used for the whole framework and for byte movement; resolved:
  **Mesh** is the umbrella, **TransportEndpoint** is the byte-movement
  capability.
- "tunnel" was used for the whole framework and for local port forwarding;
  resolved: local forwarding is a stream operation over a **Mesh Route**.
