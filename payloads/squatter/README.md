# Squatter

Squatter is Hovel's first core payload provider. The provider is a Go
`payload_provider` module that speaks Hovel JSON-RPC over stdio. The Windows
payload is a separate C payload target built for Windows XP SP3 x86.

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
