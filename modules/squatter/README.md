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
