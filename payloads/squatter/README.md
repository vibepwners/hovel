# Squatter

Squatter is Hovel's first core payload provider. The provider is a Go
`payload_provider` module that speaks Hovel JSON-RPC over stdio. The Windows
payload is a separate C payload target built for Windows XP SP3 x86.

This first scaffold is intentionally nonfunctional. It establishes:

- the provider module location,
- the Windows payload build target,
- the pinned MinGW build helper,
- and the PE inspection test that protects the no-import-table placeholder.

The agent protocol, listener, SMB named-pipe transport, IOCP/threading model,
PEB API resolver, and command handlers are deferred to later implementation
passes.
