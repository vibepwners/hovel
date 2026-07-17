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
`squatter+tls` TCP-bind streams are end-to-end encrypted to the payload. The provider
advertises one `payload-tls-server` stamp slot, validates a complete
`hovel.pki.bundle/v1`, and writes a versioned, integrity-bound certificate,
PKCS#8 private key, chain, trust, and revocation manifest into the generated
PE. The Windows payload loads that material directly into statically linked
wolfSSL and terminates TLS 1.3 itself. Mesh only routes the encrypted bytes.
The stamp operation rejects callback and named-pipe artifacts; the validated
TLS server role currently belongs to configured TCP-bind payloads.

The integration contract is exercised through Task:

- `task modules:squatter:coverage` runs the aggregate Squatter Go suites and
  enforces the 90% line-coverage floor (currently 90.59%).
- `task modules:wine-test` runs both x86 and x64 host-Wine test transitions.
- `task modules:wine-docker-test` builds the concrete 32-bit and 64-bit payloads
  and runs the real Go functional harness against each one in isolated Wine
  prefixes inside Docker.
- Provider tests create two live TCP-bind endpoints, select one by its Mesh
  route, and carry a real Squatter frame through it. The Docker TLS variant
  generates and configures the PE, stamps its PKI bundle, launches it under
  Wine, completes a verified TLS 1.3 handshake with payload wolfSSL, carries
  OPEN/DATA/CLOSE frames, and proves mutations to both the manifest and stamped
  state header fail closed on startup.

The payload pins wolfSSL 5.9.2 and builds a deliberately small, no-CRT TLS 1.3
profile. The wolfSSL portion is compiled against the Windows NT 4.0 API surface
and does not use Schannel, Secur32, Crypt32, CNG, or a Windows certificate
store. This keeps TLS from raising Squatter's legacy Windows API floor. The
provider still reports Windows 7 as its tested compatibility floor for the
complete payload until older Windows environments are part of the automated
matrix.

wolfSSL is dual-licensed under GPLv3 or a commercial license. Hovel's static
payload integration is marked as a restricted dependency; distributors that
cannot satisfy GPLv3 terms need an appropriate commercial wolfSSL license.

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
