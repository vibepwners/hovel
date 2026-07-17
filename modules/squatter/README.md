# Squatter

Squatter is Hovel's first core payload provider. The provider is a Go
`payload_provider` module that speaks Hovel JSON-RPC over stdio. The Windows
payload is a separate C payload target for Windows x86. The provider currently
reports a Windows 7 compatibility floor; the C payload keeps XP SP3 as a
low-level lab support floor in its headers, but Hovel should not claim XP
compatibility until provider metadata and tests do.

Squatter installs are intended to become durable Hovel installed payload
records. Install steps return explicit descriptors naming the Squatter provider,
payload ID, target, transport endpoint, reconnect schema, and cleanup schema.
Hovel core owns SQLite persistence and assigns operator-facing handles such as
`p1`; Squatter owns reconnect and cleanup semantics. Successful reconnects create
normal Hovel sessions.

The provider also exposes a destination-scoped Mesh surface for surveying and
opening Squatter TCP-bind endpoints. Each surveyed or dialed host/port becomes
a stable destination node beneath the provider root, with its own direct link
and route. Stream requests validate the selected node, route, host, and port as
one fail-closed routing decision, so concurrent Squatter endpoints remain
distinct. Raw `squatter` streams preserve the existing transport.
`squatter+tls` streams require the PKI assignment selected
for the `mesh-stream-tls-server` runtime credential slot. Hovel delivers a full
`hovel.pki.bundle/v1` package, the provider validates its certificate path,
purpose, validity, key, revocation data, and TLS named-group policy, then
terminates TLS before proxying plaintext Squatter frames to the target. This
protects the Mesh client-to-provider stream; it does not claim that the Windows
payload itself speaks TLS.

The integration contract is exercised through Task:

- `task modules:squatter:coverage` runs the aggregate Squatter Go suites and
  enforces the 90% line-coverage floor (currently 90.61%).
- `task modules:wine-test` runs both x86 and x64 host-Wine test transitions.
- `task modules:wine-docker-test` builds the concrete 32-bit and 64-bit payloads
  and runs the real Go functional harness against each one in isolated Wine
  prefixes inside Docker.
- Provider tests create two live TCP-bind endpoints, select one by its Mesh
  route, and carry a real Squatter frame through it. The TLS variant delivers a
  runtime credential bundle, completes a verified TLS 1.3 handshake, and
  carries the same wire frame across the encrypted Hovel session.

The current payload includes the multiplexed runtime, TCP bind/reverse TCP/SMB
named-pipe transports, and a small module table:

- the provider module location,
- the Windows payload build target,
- `cmd`, which opens an interactive `cmd.exe` with no args or runs
  `cmd.exe /c <command...>` for one-shot commands,
- `echo`, for mux smoke tests,
- `getfile` and `putfile`, for bounded-memory file transfer,
- the pinned MinGW build helper,
- and PE/source-contract tests that protect the no-import-table payload shape.

The client shell is `//payloads/squatter/client/cmd/squatterctl`.
