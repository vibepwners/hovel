# Use workspace PKI for certificate management

Status: accepted

## Context

Hovel needs to create, import, track, issue, renew, rotate, revoke, package,
and distribute X.509 certificates for local services, Mesh providers,
listening posts, Mesh nodes, implants, and stagers. The same behavior must be
available from interactive front ends, the daemon API, declarative automation,
and each supported Hovel SDK. A provider or implant developer should not need
to recreate certificate-authority workflows or write a custom Hovel front end.

Calling this only "TLS configuration" would be too narrow. The durable model
has trust anchors, root and subordinate authorities, certificate generations,
private-key custody, revocation, assignments, and rollover policy. TLS is the
first and most important consumer of that model.

## Decision

Hovel will own a workspace-scoped **PKI** application capability. It will be a
core service, not a Mesh-provider feature and not a CLI-only utility.

The domain will model:

- certificate authorities with independent root/subordinate roles, generated
  or imported origins, and local, external, or trust-only signer modes;
- root and subordinate authority relationships;
- reusable certificate profiles and complete operator-authored templates;
- immutable issued-certificate generations;
- logical assignments from consumers to active generations;
- renewal, key rotation, revocation, and CA rollover operations;
- credential stamps that connect certificate generations to generated
  artifacts and installed payload provenance;
- optional, capability-negotiated delivery and stamping contracts, including
  strict standard slots and typed provider-defined patch targets;
- lifecycle policy, audit events, and secret-export policy.

The daemon and application service will own lifecycle and bookkeeping. Crypto,
key storage, and external signing will be ports behind that service. CLI,
future TUI, MCP, REST/OpenAPI, manifests, and language SDKs will be adapters
over the same typed use cases.

Operators may select a **crypto backend** independently from a Mesh or payload
provider. The built-in backend establishes the baseline, while versioned
backend capabilities allow implementations based on Mbed TLS, wolfSSL,
platform key stores, HSMs, or future libraries. A separate compatibility target
selects consumer-safe algorithms and encodings. This distinction matters:
choosing Mbed TLS for an implant does not require Mbed TLS to issue its
certificate, and choosing an external issuer does not force a runtime TLS
library on the consumer.

Post-quantum key establishment and certificate authentication are separate
capabilities. The Go 1.26 compatibility target may require hybrid ML-KEM TLS
named groups to protect recorded sessions from later decryption while still
using a classical X.509 identity signature. Hovel must report that distinction
plainly and must not label a classical certificate chain as fully post-quantum.
Future ML-DSA or other standardized signature support enters through versioned
backend and compatibility capabilities rather than a special-case lifecycle.

Backends advertise typed key, signature, certificate, extension, import,
export, and signer-handle capabilities. The resolved backend ID, version,
package digest, and capability snapshot are persisted in every plan and
generation. A backend owns cryptographic mechanics only; it cannot bypass
Hovel's planning, confirmation, policy, storage, assignment, or audit
lifecycle. Backend installation and private-key access are privileged,
explicitly approved operations; ordinary module input cannot select or install
a new backend.

## Bundle contract

The portable contract will be a versioned, JSON-safe credential bundle.
Binary members will use base64-encoded DER rather than base64-wrapped PEM:

- leaf or authority certificate as X.509 DER;
- public key as optional SubjectPublicKeyInfo DER;
- intermediate certificates ordered from the leaf's issuer toward the trust
  anchor, excluding the separately encoded leaf and trust anchors;
- trust anchors as X.509 DER;
- optional current CRLs as X.509 CRL DER;
- an exportable private key as unencrypted PKCS #8 DER, or a non-exportable
  key reference, never both.

SDKs will expose decoded byte containers and helpers for DER, PEM, TLS-library
configuration, and safe file materialization. List and inspect operations will
never include private-key bytes. Resolving or exporting private material will
be a separate, policy-checked, audited use case.

## Lifecycle semantics

Terms are explicit:

- **renew** issues a new certificate generation with the existing key;
- **rotate** generates a new key and a new certificate generation;
- **revoke** records the invalid generation and updates revocation material;
- **roll over** replaces an authority through publish, activate, retire, and
  remove phases with an overlap trust set;
- **stamp** binds exact credential generations and their hashes to a generated
  artifact or provider-owned deployment.

Automated leaf lifecycle defaults to rotation. Renewal with key reuse remains
available when a constrained consumer requires it. Historical generations and
events are immutable.

Consumers bind to a logical assignment rather than hard-coding one certificate
ID. Assignment activation is transactional so old and new generations can
overlap during a rollout. A root rollover cannot be represented as an atomic
certificate replacement.

Credential consumption is capability-based like Mesh. A provider may support
no Hovel delivery, runtime bundles, protected files, standard named stamp
slots, advanced file offsets or virtual addresses, symbols/markers, or its own
versioned target type. It implements only the capability it uses. Standard
slots and projections have strict schemas and are the recommended seamless
path; advanced targets remain possible without weakening the defaults.

Hovel never guesses an address or silently patches an artifact. Every stamp
plan binds the input artifact hash, target address space, expected existing
bytes or hash, material projection, bounds, and provider capability version.
The result records the resolved target, byte count, and output hash without
logging secret replacement bytes.

## Operator configurability

Every semantically controllable field supported by the selected crypto backend
will be available in the typed template and declarative manifest. This includes
subject names, serial number, validity, key and signature algorithms, SANs,
basic constraints and path length, key usage, extended key usage, key
identifiers, policies, name constraints, authority-information and revocation
locations, criticality, and custom extensions.

Fields derived by X.509 construction are not raw-editable: signature bytes,
the encoded to-be-signed certificate, issuer identity for a selected parent,
and public-key bytes for a generated key. Hovel will expose the choices that
produce those fields and provide a custom-extension escape hatch, but it will
not let an adapter manufacture structurally inconsistent certificates.

Profiles supply safe defaults without reducing operator control. The default
profile will use ECDSA P-256 with SHA-256, positive cryptographically random
128-bit serials, a small clock-skew backdate, role-appropriate key usage and
EKU, and bounded validity. Compatibility profiles will include RSA 2048, and
optional embedded compatibility targets may be continuously tested against
Mbed TLS, wolfSSL, or another registered consumer. Mbed OS is not a PKI
completion criterion. Defaults are resolved into the persisted
issuance plan before confirmation so they are reviewable and reproducible as
recorded intent.

## Front ends and automation

The canonical non-interactive surface is a versioned PKI manifest accepted by
`hovel pki plan` and `hovel pki apply`. Imperative `hovel pki` commands and a
Huh-based interactive wizard call the same application service. Huh owns only
form presentation; shared domain constructors and application validation own
all rules.

The existing module/provider SDK and the new daemon control client remain
separate namespaces in Go, Python, Rust, and C:

- provider and implant integrations consume typed bundle and assignment
  contracts;
- operator automation and tests call daemon PKI use cases and assertion
  helpers;
- neither API requires terminal automation.

The stable daemon API and OpenAPI document remain the source of truth for
external clients, including a future web or Elixir control plane.

Wire enums, media types, schema versions, operation names, profile names, and
policy defaults will each have one canonical typed definition or generated
schema. Adapters must not reproduce protocol strings or lifecycle thresholds.

## Key custody

Private keys are not stored as plaintext JSON in the workspace database. The
built-in local implementation uses AES-256-GCM envelopes and authenticates
immutable generation metadata with a separately domain-separated HMAC. Both
are rooted in a versioned workspace master key. The baseline provider stores
those master keys in the owner-only
`secrets/pki-master-keys.json` file; initialization and ordinary open are
separate so a missing file after restore fails closed instead of creating an
unrelated key. The provider port must also
support non-exportable external signers such as an OS key store, PKCS #11,
KMS, or an offline root workflow.

Root keys are locked by default and are not used for routine leaf issuance.
The recommended topology is an offline or operator-unlocked root plus an
online subordinate authority. Unlocking grants a bounded signing lease or one
operation; it does not persist plaintext key material or leave an authority
indefinitely unlocked. Secret display, export, backup, restore, destruction,
and signer use produce audit events without logging key bytes.

## Consequences

- Certificate management becomes reusable infrastructure for Mesh, implants,
  stagers, services, and future front ends.
- The database needs additive migrations for PKI metadata, generations,
  assignments, policies, revocations, stamps, and events.
- Hovel needs a secret-provider and signer abstraction before it can claim
  safe private-key persistence.
- SDK publication expands from module-side contracts to a stable daemon
  control client and test helpers.
- Providers remain responsible for target-specific embedding or deployment,
  but Hovel owns the operator workflow, lifecycle policy, package format,
  bookkeeping, and audit trail.
- Simple providers can adopt strict standard credential slots; unusual
  providers can add optional typed stamping capabilities without implementing
  unrelated PKI features.
- Documentation demos must be generated from real commands and backed by
  non-visual verification tests.

## Rejected alternatives

### Store PEM strings directly in provider config

This leaks lifecycle and secret handling into every provider, provides no
authority inventory or rollover bookkeeping, and double-encodes poorly over
JSON APIs.

### Make certificate management part of Mesh

Non-Mesh services and artifacts also need certificates. Mesh should reference
PKI assignments and credential stamps rather than own the PKI lifecycle.

### Implement only an interactive wizard

Terminal-only behavior cannot support CI, external control planes, SDK tests,
or reproducible implant builds. The wizard must remain an adapter over typed
and declarative use cases.

### Return private keys from ordinary inspect calls

This makes accidental disclosure likely and prevents non-exportable signer
support. Secret resolution must be explicit and audited.

### Require every provider to implement the complete PKI surface

Simple Mesh providers, external listening posts, and operators that only need
exported files should not carry unused stamping or signer code. Optional
capabilities preserve small implementations, while strict standard contracts
make the common path interoperable.

## Detailed plan

The implementation sequence, contracts, acceptance evidence, and documentation
demo plan are defined in
[`docs/plans/tls-certificate-management.md`](../plans/tls-certificate-management.md).
