# TLS certificate-management implementation plan

Status: proposed

Decision record:
[`ADR-0002`](../adr/0002-use-workspace-pki-for-certificate-management.md)

This document is an implementation plan, not a description of shipped
behavior. Each slice must update its status and supporting docs as it lands.

## How to use this plan

The plan is intentionally complete, but most readers need only part of it:

| Reader or task | Read first |
| --- | --- |
| Product or architecture review | Goal, required outcomes, architecture, and implementation sequence. |
| Core PKI implementation | Domain model, certificate-template surface, custody, lifecycle, persistence, and verification. |
| Mesh, payload, or implant integration | Credential stamp, optional delivery/stamping, integration, bundle, and provider SDK sections. |
| CLI, web, or automation client | Operator surfaces, daemon API, control-client SDK, and documentation plan. |
| Embedded or TLS-library integration | Backend/compatibility target, bundle, provider consumption, and interoperability tests. |
| Security review | Key custody, lifecycle, secret-bearing API rules, and security verification. |

The short version is: the daemon owns certificate lifecycle and bookkeeping;
consumers bind to logical assignments; portable bundles carry material;
providers advertise only the delivery or stamping capabilities they support;
and every front end calls the same application use cases.

## Goal

Make Hovel the operator-facing certificate and trust-management layer for
listening posts, C2 services, Mesh providers, Mesh nodes, implants, stagers,
and ordinary services. Operators must be able to configure, automate, inspect,
and test the complete lifecycle without writing a custom front end. Provider
and implant authors should consume a stable credential package instead of
reimplementing CA workflows.

## Required outcomes

1. Create, import, inspect, track, export, lock, unlock, retire, and roll over
   root and subordinate certificate authorities.
2. Issue, import, inspect, renew, rotate, revoke, and archive leaf and
   subordinate certificates.
3. Make every supported semantic X.509 template field operator-configurable,
   with safe profile defaults and cryptographically random identity material.
4. Persist immutable certificate generations, active assignments, lifecycle
   policy, revocation state, credential stamps, and audit events in the daemon.
5. Deliver a typed, versioned bundle containing certificate, public key,
   chain, trust anchors, and either private-key bytes or a non-exportable key
   reference.
6. Bind logical credentials to Mesh providers, listeners, nodes, implants,
   stagers, generated artifacts, installed payloads, and future services.
7. Support interactive Huh workflows, imperative commands, declarative
   manifests, MCP, REST/OpenAPI, and external control planes through the same
   application service.
8. Add Go, Python, Rust, and C SDK support for control-plane automation,
   provider-side bundle consumption, and certificate assertions.
9. Publish operator and developer Book pages with real VHS demos,
   explanations, examples, and troubleshooting. Every demo must have
   non-visual verification.
10. Let operators choose a versioned crypto backend and an independent
    consumer compatibility target, with capability negotiation for built-in,
    Mbed TLS, wolfSSL, platform-native, HSM, and future implementations.
11. Keep provider integration capability-based: strict standard credential
    slots and stamp targets are easy, while no-stamp, raw offset/address,
    symbol/marker, and provider-defined cases remain optional and possible.

## Current-state findings

- Hovel has no tracked certificate or CA domain today.
- The daemon HTTP/JSON RPC and OpenAPI artifact are the stable external
  front-end contract.
- Go, Python, and Rust SDKs currently focus on module/provider JSON-RPC over
  stdio; there is no public daemon control client and no C SDK.
- The existing Huh form is a CLI adapter over shared configuration behavior,
  which is the pattern the PKI wizard should follow.
- SQLite migrations already persist workspace state, throws, artifacts,
  events, and installed payload inventory.
- Payload stamps already connect generated artifacts to installed inventory;
  credential stamps should extend that provenance instead of replacing it.
- Mesh listeners and node operations are daemon-visible and already expose
  stable IDs suitable for PKI assignment subjects.
- VHS demos are Bazel-declared host-service actions, and standard demos have a
  fast non-visual verification test.

## Terminology

| Term | Meaning |
| --- | --- |
| Authority | Logical root or subordinate issuer with local, external, or no signing capability. |
| Certificate | Logical identity whose key and issued bytes may change over time. |
| Certificate generation | One immutable X.509 certificate and its metadata within a certificate lineage. |
| Profile | Reusable defaults and constraints for an authority or leaf role. |
| Template | Fully resolved operator intent used for one issuance. |
| Assignment | Logical consumer slot whose active generation may change. |
| Bundle | Portable certificate, chain, trust, and key material contract. |
| Renew | New certificate using the existing key. |
| Rotate | New key and new certificate. |
| Rollover | Staged authority replacement with overlapping trust. |
| Stamp | Immutable link between credential generations and an artifact or deployment. |
| Crypto backend | Selectable implementation of key, signing, parsing, and certificate operations. |
| Compatibility target | Consumer TLS/key constraints, such as Mbed TLS or wolfSSL, independent of crypto backend. |

The internal package and API namespace is `pki`. The operator command group is
also `pki`; it is precise, short, and covers more than TLS connection settings.
Documentation should introduce it as "TLS and certificate management" before
using PKI terminology.

## Architecture

```text
CLI / Huh / MCP / REST / control SDK / manifest
                         |
                         v
                 PKI application service
        plan / apply / issue / assign / rotate / revoke
             |              |               |              |
             v              v               v              v
       metadata store   key custody   crypto backends   consumer coordination
          SQLite       encrypted or   built-in/plugin   Mesh/payload/service
                        key handle     native/external       adapters
                                             |
                                             v
                                      local/external signer
```

### Dependency direction

- `core/internal/domain/pki` contains pure value objects and invariants.
- `core/internal/app/pki` defines use cases and ports for metadata, keys,
  signing, clocks, IDs, randomness, events, and consumer coordination.
- `core/internal/adapters/storage/sqlite` persists non-secret PKI state.
- a dedicated infrastructure adapter encrypts local keys and implements the
  key-store port;
- a crypto-backend registry implements typed capability discovery and selects
  built-in, packaged plugin, or platform-native implementations;
- `core/internal/adapters/daemonrpc`, CLI, MCP, and future TUI call the
  application service;
- Mesh, payload, and service packages depend on assignment/bundle contracts,
  not concrete key storage.

Crypto generation must use `crypto/rand` in production. Tests inject clocks,
IDs, and policy, but production code must not accept a deterministic random
source through an operator-facing option.

Protocol enum values, schema versions, media types, operation names, profile
names, and policy thresholds must come from canonical domain definitions or
generated contracts. Do not scatter magic strings, validity durations, or
rotation ratios through adapters and SDKs.

### Crypto backend and compatibility target

`BackendID` selects cryptographic mechanics. A versioned backend descriptor
advertises:

- key generation/import and supported key parameters;
- signature, CSR, certificate, CRL, parse, and verify operations;
- supported semantic extensions and custom-extension handling;
- local, external, hardware, and non-exportable key capabilities;
- accepted and emitted DER/PEM/key formats;
- backend version, package digest, implementation provenance, and optional
  compliance mode.

The built-in Go X.509 backend is the required reference implementation. Mbed
TLS, wolfSSL, PKCS #11, KMS, OS-keystore, and future implementations may be
registered behind the same port. External implementations follow Hovel's
existing packaged-plugin and versioned JSON-RPC conventions, but use a distinct
`pki-backend` capability rather than masquerading as an exploit, payload, or
Mesh module. Backend calls receive the minimum scoped operation data; authority
keys remain handles whenever the backend can keep them non-exportable.

Crypto backends are privileged code. Installation, enabling, upgrade, and any
permission to receive private bytes require explicit operator approval and
audit. A manifest supplied by a module cannot install or silently select a
backend. Backend packages are pinned by content digest, run with the narrowest
available process permissions, and must never receive unrelated workspace
configuration or credentials.

`CompatibilityTargetID` is separate. It constrains algorithms, usages, chain
shape, key encoding, and delivery helpers for a consumer such as `go-tls`,
`mbedtls`, `wolfssl`, or a platform-native stack. Its version and capability
snapshot include relevant library major/minor and compile-time feature
configuration; a nominal library name alone is insufficient for an embedded
build. A certificate issued by the built-in backend can target wolfSSL, while
an external backend can issue for an Mbed TLS consumer. Profiles provide a
default pair, and operators can override either after capability validation.
Compatibility descriptors are data contracts and may ship with core, an SDK
adapter, or a provider package; adding a future TLS library does not require a
new PKI lifecycle use case.

The resolved plan persists backend ID/version/digest, compatibility target
ID/version, and the exact capability snapshot used for validation. Apply fails
closed if the backend changes incompatibly or disappears; it never silently
falls back to another crypto backend.

Backend output is not trusted merely because the backend advertised support.
Before persistence, Hovel independently parses and verifies the returned
certificate, public-key match, signature chain, requested identity, serial,
validity, usages, constraints, and extension set against the resolved template.
Semantic equivalence is required; byte-for-byte DER equality is not. Backend
health and contract tests exercise every advertised capability.

## Domain model

### Authority

```text
AuthorityID
Name
Role: root | subordinate
Origin: generated | imported
SignerMode: local | external | none
ParentAuthorityID
State: pending | active | locked | retiring | retired | compromised | destroyed
ActiveGenerationID
ProfileID
SignerRef
ExportPolicy
CreatedAt / UpdatedAt
Labels
```

An authority record is logical. Its certificate and key can rotate through
immutable certificate generations. Role, origin, and signing capability are
orthogonal: an imported root may be a trust-only anchor, while an imported
subordinate may use an external signer. A subordinate must reference a parent
generation and satisfy the parent's path-length and name constraints.

### Certificate generation

```text
CertificateID
CertificateGenerationID
Generation
OwningAuthorityID
IssuerAuthorityID
IssuerGenerationID
ProfileID
TemplateSnapshot
BackendID / BackendVersion
BackendPackageDigest / BackendCapabilityHash
CompatibilityTargetID / CompatibilityTargetVersion
SerialNumber
FingerprintSHA256
SubjectKeyID / AuthorityKeyID
NotBefore / NotAfter
State: pending | active | superseded | expired | revoked | invalid
Revocation
KeyRef
CertificateDER
ChainGenerationIDs
CreatedAt
```

`CertificateID` identifies a logical lineage across renewal or rotation;
`CertificateGenerationID` uniquely identifies immutable bytes, and
`Generation` is monotonic within that lineage. `OwningAuthorityID` is present
only when the generation represents an authority. `IssuerAuthorityID` and
`IssuerGenerationID` identify its signer; they may be absent for an imported
certificate whose issuer is not managed.
Authority certificates and leaves use this one generation model rather than
parallel authority-certificate storage. Certificate bytes, template, issuer
identity, hashes, and timestamps are immutable after issuance. State
transitions and assignment changes are separate records.

### Assignment

```text
AssignmentID
Purpose: tls-server | tls-client | mtls-server | mtls-client | dual-role-mtls |
         code-signing | custom
ConsumerType: mesh-provider | mesh-listener | listening-post | mesh-node |
              implant | stager | payload | c2-service | service | external
ConsumerID
ProfileID
ActiveGenerationID
StagedGenerationID
TrustSetID
RotationPolicyID
State
UpdatedAt
```

Assignments are the integration boundary. A Mesh node or generated implant
refers to an assignment, not a raw key path. Activation uses compare-and-swap
or equivalent transaction semantics to prevent concurrent rotations from
silently replacing one another.

### Policy and profile

Profiles contain defaults plus constraints. Policies schedule and gate renew,
rotate, rollover, revocation publication, overlap, and expiry warnings.
Templates resolve profile values and explicit overrides into one complete,
reviewable issuance plan.

### Credential stamp

A credential stamp records:

- stamp ID and payload stamp ID when applicable;
- assignment ID and exact certificate generation IDs;
- trust-set generation;
- hashes of every bundle member;
- provider/module, operation, chain, throw, run, target, listener, and node
  references when available;
- artifact ID/hash or deployment reference;
- creation time and lifecycle status.

Hovel does not patch arbitrary implant binaries in core. A payload or Mesh
provider receives a typed resolved bundle and owns format-specific embedding,
file generation, or deployment. Hovel owns the operator workflow, secret
authorization, assignment resolution, stamping record, and resulting artifact
provenance.

### Optional delivery and stamp capability

Provider integration uses small optional capabilities, not one required PKI
interface. The absence of a capability is valid and affects only operations
that request it:

- `none`: track or export credentials without provider delivery;
- `runtime`: resolve a scoped bundle when an operation starts;
- `files`: materialize selected members to protected temporary files;
- `stamp-standard`: fill a provider-declared named slot or placeholder;
- `stamp-advanced`: accept typed offset, address, symbol, marker, pattern, or
  provider-defined targets.

The recommended standard contract is intentionally strict. A credential slot
declares a stable name, purpose, endpoint role, accepted bundle versions,
profiles, compatibility targets, projections, maximum encoded size, padding,
and whether a private key or signer handle is permitted. Providers built to
this contract need no custom Hovel forms or lifecycle code.

Advanced stamping uses generated tagged unions rather than an unstructured
map:

```text
StampTarget = NamedSlot | FileOffset | VirtualAddress | Symbol | Marker |
              BytePattern | ProviderDefinedTarget
StampMaterial = Bundle | CertificateDER | PrivateKeyPKCS8 | PublicKeySPKI |
                ChainDER | TrustDER | CRLDER | ProviderEncoding | LiteralBytes
```

Targets carry an explicit address space, unsigned width-checked offset or
address, optional image base/section, expected existing bytes or hash, maximum
length, alignment, padding rule, pattern mask/occurrence, and provider target
schema version as applicable. Material carries a credential-generation
reference or secret-aware literal reference, encoding, and expected hash;
private replacement bytes are resolved only during the authorized operation
and are not persisted in the plan or event.

Domain addresses and offsets are unsigned integer value objects. JSON/YAML
wire contracts encode them as canonical strings rather than IEEE-754 numbers,
so 64-bit addresses round-trip through JavaScript and future web/Elixir
clients. Advanced raw targets require explicit advanced-mode intent in the
persisted plan and confirmation; they are never inferred from a standard slot.

Every stamp operation verifies the input artifact ID/hash and target
precondition, rejects overflow, ambiguity, out-of-bounds writes, and size
mismatch, then records requested and provider-resolved locations, capability
version, byte count, material hashes, and output artifact hash. Virtual-address
translation and provider-defined target resolution remain provider-owned.
Hovel never guesses a target, patches after a failed precondition, or treats a
provider's reported success as proof without validating the returned artifact
and stamp result.

### Revocation-list generation

CRLs are immutable generations with their own ID, issuer generation, CRL
number, `thisUpdate`, `nextUpdate`, DER, hash, publication state, and superseded
generation. Hovel tracks distribution and consumer acknowledgement separately
from certificate revocation. An OCSP URL is emitted only when a configured
external or future Hovel responder can actually serve it; the initial
implementation does not advertise a nonexistent responder.

## Complete certificate-template surface

The typed model must cover the complete semantic surface exposed by the
selected crypto backend. Unsupported RFC extensions remain available through a
custom extension with OID, critical flag, and DER value.

### Identity and validity

- explicit or random positive, non-zero serial number within the RFC 5280
  20-octet limit and unique for the issuer generation;
- subject distinguished name: common name, serial number, country,
  organization, organizational unit, locality, province/state, street,
  postal code, and arbitrary OID/value names with an explicit supported ASN.1
  string/value type;
- explicit `notBefore`, `notAfter`, duration, and clock-skew backdate;
- issuer selected by authority generation;
- certificate version fixed to X.509 v3.

### Keys and signatures

- key source: generated, imported, existing key reference, CSR, or external
  signer;
- key algorithm and parameters: ECDSA P-256/P-384/P-521, RSA size, or
  Ed25519 when the consumer profile permits it;
- supported signature algorithm compatible with issuer key;
- SubjectPublicKeyInfo derived from the selected/generated key;
- Subject Key Identifier and Authority Key Identifier mode: automatic,
  explicit, or omitted where standards and profile allow it.

### Names and constraints

- DNS, IP, email, and URI subject alternative names;
- issuer alternative names through typed or custom extensions;
- permitted and excluded DNS, IP range, email, URI-domain, and directory-name
  constraints;
- name-constraints criticality;
- explicit empty subject only when a critical SAN satisfies RFC 5280.

### Usage and authority constraints

- CA flag, basic-constraints criticality, path length, and explicit zero path
  length;
- every key-usage bit;
- named and custom-OID extended key usages plus criticality;
- certificate-policy OIDs and supported qualifiers;
- policy constraints, inhibit-any-policy, and custom policy extensions;
- OCSP server, issuing-certificate URL, CRL distribution points, and custom
  authority-information access extensions.

### Extensions

- all standard extension critical flags that the backend supports;
- custom extensions with duplicate-OID rejection;
- profile validation of contradictory key usage/EKU, invalid CA usage,
  impossible path lengths, unsupported algorithms, negative/oversized serials,
  invalid SANs, and validity beyond issuer bounds.

Raw signature bytes, raw `TBSCertificate`, generated public-key bytes, and the
issuer name for a selected parent are derived, not independently editable.
This is the boundary between full operator control and structurally invalid
ASN.1.

## Default profiles

Defaults are generated once during planning and persisted in the reviewed plan.
Applying the plan does not silently roll new defaults.

| Profile | Key | Default validity | Intended use |
| --- | --- | --- | --- |
| `root-modern` | ECDSA P-256 | 10 years | Offline or locked trust anchor. |
| `subordinate-modern` | ECDSA P-256 | 3 years | Online operational issuer. |
| `tls-server` | ECDSA P-256 | 30 days | LP, C2, provider, and service server identity. |
| `tls-client` | ECDSA P-256 | 30 days | Implant, stager, and Mesh-node client identity. |
| `mtls-server` | ECDSA P-256 | 30 days | Server identity that requires authenticated clients. |
| `mtls-client` | ECDSA P-256 | 30 days | Client identity for an authenticated server. |
| `dual-role-mtls` | ECDSA P-256 | 30 days | Explicit opt-in when one identity genuinely serves both roles. |
| `legacy-rsa-server` | RSA 2048 | 30 days | Compatibility-only server consumers. |
| `legacy-rsa-client` | RSA 2048 | 30 days | Compatibility-only client consumers. |

Compatibility targets remain separate from role profiles. Core supplies a
portable X.509 baseline; the repository registers a versioned Mbed TLS/Mbed OS
5.15.9 target for its existing embedded build, and installed wolfSSL or other
packages register targets containing their exact version and configuration
fingerprint.

Common defaults:

- built-in X.509 backend unless the selected profile or operator chooses
  another installed, healthy backend;
- portable X.509 compatibility target unless the operator or consumer slot
  selects a more constrained target;
- positive random 128-bit serial;
- random stable resource ID and a human-editable name;
- common name `hovel-<role>-<random suffix>` unless identity context supplies
  one;
- five-minute `notBefore` backdate;
- SHA-256 fingerprints and compatible signatures;
- critical basic constraints for CAs;
- CA key usage `certSign` and `crlSign`;
- role-appropriate leaf key usage and EKU;
- SANs derived only from explicit consumer identity or operator input, never
  guessed from an unrelated host;
- automatic SKI/AKI;
- non-exportable keys preferred for authorities;
- renewal warning at one-third of remaining lifetime and automatic rotation
  before the final one-fifth, configurable by policy.

The wizard must show the resolved values before creation. Operators can edit
every default or save the result as a named profile.

Random serial allocation is protected by a unique issuer-generation/serial
constraint and retries a collision before the plan is persisted. The limit and
retry policy are named domain constants, not adapter literals.

## Credential bundle v1

Canonical wire form:

```json
{
  "schemaVersion": "hovel.pki.bundle/v1",
  "bundleId": "bundle-01J...",
  "assignmentId": "assignment-listener-edge",
  "certificateId": "cert-01J...",
  "certificateGenerationId": "certgen-01J...",
  "generation": 4,
  "purpose": "mtls-server",
  "certificate": {
    "mediaType": "application/pkix-cert",
    "encoding": "base64-der",
    "data": "MIIB..."
  },
  "publicKey": {
    "mediaType": "application/pkix-keyinfo",
    "encoding": "base64-der",
    "data": "MFkw..."
  },
  "privateKey": {
    "mediaType": "application/pkcs8",
    "encoding": "base64-der",
    "data": "MIGH..."
  },
  "chain": [
    {
      "certificateGenerationId": "certgen-issuer",
      "mediaType": "application/pkix-cert",
      "encoding": "base64-der",
      "data": "MIIC..."
    }
  ],
  "trustAnchors": [
    {
      "certificateGenerationId": "certgen-root",
      "mediaType": "application/pkix-cert",
      "encoding": "base64-der",
      "data": "MIID..."
    }
  ],
  "certificateRevocationLists": [
    {
      "crlGenerationId": "crlgen-01J...",
      "mediaType": "application/pkix-crl",
      "encoding": "base64-der",
      "data": "MIIB..."
    }
  ],
  "fingerprints": {
    "certificateSha256": "...",
    "publicKeySha256": "..."
  },
  "notBefore": "2026-07-11T19:00:00Z",
  "notAfter": "2026-08-10T19:00:00Z"
}
```

`privateKey` and `privateKeyRef` form a generated tagged union and cannot both
be present. Base64 is canonical RFC 4648 encoding without whitespace; hashes
use lowercase hexadecimal SHA-256; times use UTC RFC 3339. The leaf is not
repeated in `chain`, and trust anchors are not repeated among intermediates.
Decoders reject unknown required schema versions, malformed lengths, duplicate
member IDs, duplicate chain members, and certificate/key mismatches.

For a non-exportable key, `privateKey` is absent and `privateKeyRef` contains a
typed, scoped signer capability reference, not a reusable raw provider locator.
Out-of-process consumers use that reference only through an authorized signing
operation; consumers that cannot use a signer callback must receive exportable
key bytes or use a platform-native key handle. Inspection responses include
neither field's secret resolution data. Bundle export requires an explicit
purpose, caller, and export policy decision and emits an audit event.

SDK helpers provide:

- DER byte access without another base64 layer;
- PEM certificate, chain, CA, public-key, and PKCS #8 rendering;
- CRL decoding, fingerprinting, and freshness helpers;
- atomic owner-only file output;
- native TLS configuration helpers where the language ecosystem supports it;
- zeroization or best-effort clearing guidance for secret buffers;
- no secret values in `String`, `Debug`, `repr`, logs, or assertion failures.

## Key custody and recovery

### Initial local implementation

1. A workspace master key comes from an explicit secret provider, not the
   SQLite database.
2. Private-key envelopes use an authenticated encryption scheme with a random
   nonce and bind workspace, key ID, algorithm, and schema version as
   associated data.
3. SQLite stores only the envelope, metadata, key reference, and hashes.
4. File materialization uses owner-only permissions and atomic rename.
5. Root keys start locked and require an explicit, bounded unlock/sign lease;
   plaintext key material is never persisted as an unlocked state.
6. Backup exports are separately encrypted and versioned; restore verifies
   certificate/key correspondence before committing metadata.

The implementation design must choose the workspace secret provider before
writing key-storage code. Candidate providers are OS keyring, operator-supplied
passphrase through a memory-hard KDF, or an external key handle. Environment
variables and plaintext workspace config are not acceptable default custody.

### External and offline signers

The signer port must support:

- a local encrypted key;
- an imported non-exportable key;
- PKCS #11, KMS, or OS-keystore references;
- CSR export and signed-certificate import for an offline root.

The local phase does not pretend an external signer is exportable. APIs return
capabilities such as `sign-certificate`, `sign-csr`, `sign-crl`,
`export-public`, `export-private`, `destroy`, and `attest`.

## Lifecycle workflows

### Create a root and subordinate

1. Resolve profile and operator overrides into a complete plan.
2. Validate names, algorithms, constraints, validity, and custody policy.
3. Show generated IDs, serial, validity, usages, fingerprints-to-be-computed,
   exportability, and warnings.
4. Record confirmation for secret-generating or authority-changing work.
5. Generate/store the root key and self-signed generation under a bounded
   creation lease.
6. Generate and sign the subordinate under that lease, terminate the lease so
   the root is locked, and activate the subordinate. A later subordinate
   operation requires another explicit unlock/sign lease.
7. Emit lifecycle events and durably complete the hierarchy through a
   retry-safe operation. Because key stores and external signers cannot share a
   SQLite transaction, interrupted work is reconciled or compensated rather
   than described as globally transactional.

### Issue and assign a leaf

1. Select consumer and purpose.
2. Resolve names from explicit consumer metadata plus operator overrides.
3. Issue through the active authority generation.
4. Verify the resulting chain and intended EKU before storage.
5. Stage the generation on the assignment.
6. Export or deliver it to the consumer through a policy-checked resolver.
7. Activate after consumer acknowledgement or explicit operator action.

### Renew and rotate

- Renewal keeps the key reference and issues a new certificate generation.
- Renewal of an externally held key requires a signer operation or a fresh CSR
  proving the same public key; Hovel cannot silently reuse a key it does not
  control.
- Rotation creates a new key reference and certificate generation.
- Both stage before activation, retain old generation history, and support an
  overlap deadline.
- Automatic policy uses rotation unless the lifecycle policy explicitly
  selects renewal with key reuse.
- Failed delivery does not move the active assignment.
- Successful activation emits old/new generation and consumer references.

### CA rollover

1. Create the next authority generation or replacement authority.
2. Publish a trust set containing old and new anchors/chains.
3. Wait for tracked consumers to acknowledge the new trust generation.
4. Activate the new issuer for new leaf rotations.
5. Rotate assigned leaves and verify both old and new paths during overlap.
6. Retire the old issuer, then remove old trust only after policy and consumer
   acknowledgements permit it.
7. Preserve historical metadata and mark destroyed keys separately.

### Revocation and compromise

- Revoke by reason and effective time; never delete the generation.
- Generate and track CRLs for issuing authorities.
- Publish immutable CRL generations and keep an assignment degraded until its
  required trust/revocation material is acknowledged or policy allows an
  explicit override.
- Mark affected assignments degraded and queue rotation.
- Authority compromise identifies all descendant generations and assignments,
  starts rollover, and prevents further issuance immediately.
- Root distrust is represented by trust-set and authority state, not by
  pretending a self-signed root can revoke itself.

## Mesh, listener, implant, and stager integration

PKI is independent of Mesh but has first-class assignment subjects:

```text
mesh-provider:<module-id>
mesh-listener:<module-id>/<listener-id>
listening-post:<provider-id>/<listening-post-id>
mesh-node:<module-id>/<node-id>
implant:<provider>/<implant-id>
stager:<provider>/<stager-id>
payload:<provider>/<payload-id>/<stamp-id>
c2-service:<provider>/<service-id>
service:<service-id>
```

`mesh-listener` is the existing Mesh listening-post resource and remains
separate from its provider. `listening-post` and `c2-service` cover non-Mesh
integrations without forcing them into a Mesh implementation.

Mesh descriptors may advertise credential-slot requirements without embedding
secret config:

```json
{
  "credentialSlots": [
    {
      "name": "control-plane-mtls",
      "purpose": "mtls-server",
      "endpointRole": "server",
      "consumerScope": "listener",
      "acceptedBundleVersions": ["hovel.pki.bundle/v1"],
      "acceptedProfiles": ["mtls-server"],
      "acceptedProjections": ["bundle", "certificate-der", "private-key-pkcs8"],
      "maximumEncodedBytes": 16384,
      "privateMaterial": "allowed",
      "acceptedCompatibilityTargets": [
        {"family": "mbedtls", "requiredCapabilities": ["x509", "tls12"]},
        {"family": "wolfssl", "requiredCapabilities": ["x509", "tls12"]}
      ]
    }
  ],
  "deliveryCapabilities": ["runtime", "files", "stamp-standard"],
  "stampCapabilities": {
    "targetKinds": ["named-slot", "file-offset", "virtual-address"],
    "addressSpaces": ["file", "elf-virtual-address"],
    "providerTargetSchemas": []
  }
}
```

The provider receives a short-lived resolved bundle or a key reference through
the module runtime only when invoking an operation that declares the slot. The
descriptor, listener list, topology, beacons, and normal config inspection must
not echo private material.

For payload generation, Hovel resolves the assignment before provider
invocation and records the returned artifact against both the payload stamp and
credential stamp. Rotation can then identify which artifacts or installed
payloads still carry an old trust or identity generation.

Providers advertise only the delivery and stamp capabilities they implement.
No-stamp, runtime, protected-file, standard-slot, and advanced-target paths all
share the same assignment, policy, confirmation, and bookkeeping. Hovel owns
forms, commands, manifests, lifecycle, and audit; provider authors implement
only their transport/build-specific consumption hooks. An operation that asks
for an unsupported capability fails validation before material is resolved,
while unrelated provider operations continue to work.

## Operator surfaces

### Commands

```text
pki status
pki backend list|inspect|doctor
pki profile list|inspect|create|delete
pki authority list|inspect|create|import|export|lock|unlock|retire|rollover
pki certificate list|inspect|issue|import|renew|rotate|revoke|export
pki assignment list|inspect|bind|stage|activate|rotate|unbind
pki trust list|inspect|export
pki stamp list|inspect
pki plan <manifest>
pki apply <manifest>
pki doctor
```

All commands support `--json`. Commands that disclose private material require
an explicit `--include-private` and protected export destination or an SDK
request carrying the same policy intent; private bytes are never written to
ordinary human output or operation JSON. Human output redacts secrets.

### Declarative manifest

```yaml
apiVersion: hovel.dev/pki/v1alpha1
kind: PKIPlan
metadata:
  name: edge-mesh
defaults:
  cryptoBackend:
    id: builtin-x509
  compatibilityTarget:
    id: mbedtls/mbed-os-5.15.9
authorities:
  - name: edge-root
    role: root
    profile: root-modern
    custody:
      kind: local-encrypted
  - name: edge-issuer
    role: subordinate
    parent: edge-root
    profile: subordinate-modern
certificates:
  - name: listener-edge
    issuer: edge-issuer
    profile: mtls-server
    subject:
      commonName: listener-edge
    sans:
      dns: [listener.edge.internal]
assignments:
  - name: edge-listener-mtls
    consumer:
      kind: mesh-listener
      id: mesh-provider/listener-edge
    certificate: listener-edge
```

An unusual provider can opt into an explicit target without changing the
lifecycle contract:

```yaml
delivery:
  mode: stamp-advanced
  target:
    kind: virtual-address
    addressSpace: elf-virtual-address
    address: "0x401000"
    maximumLength: 4096
    expectedBytesSha256: 8f1d...
  material:
    projection: bundle
    assignment: edge-listener-mtls
```

`delivery.mode: none` is equally valid when Hovel should issue and track the
credential but the provider or operator handles delivery elsewhere.

`pki plan` resolves all defaults, serials, IDs, validity, and implicit
dependencies into a canonical, persisted plan with a stable ID and hash.
Re-reading a saved plan does not regenerate random values. `pki apply` executes
only a confirmed matching plan, and a repeated idempotency key returns the
recorded outcome. This follows Hovel's existing plan-before-action safety
pattern without pretending certificate issuance is a throw.

### Huh wizard

The Huh adapter uses grouped, dynamic pages:

1. resource type and intended consumer;
2. crypto backend, compatibility target, and capability review;
3. authority hierarchy and signer custody;
4. profile, key, signature, and validity;
5. subject and SANs;
6. usages, constraints, policies, and advanced extensions;
7. delivery, assignment, export, and rotation policy;
8. resolved-plan review and confirmation.

Use `Select` and `MultiSelect` for finite vocabularies, `Input`/`Text` for
names and custom OIDs, `Confirm` for advanced/secret operations, dynamic fields
for role-specific pages, and accessible mode when configured. The same request
types and validation power imperative commands, manifests, and SDK calls.

## Daemon API and external interfaces

Add typed RPC methods and OpenAPI schemas for:

- backend and compatibility-target list, inspect, capability, and health;
- consumer delivery/stamp capability discovery, stamp planning, execution, and
  result inspection;
- authority/profile/certificate/assignment/trust/stamp list and inspect;
- create/import/plan/apply/issue/renew/rotate/revoke/rollover;
- bundle resolve/export and public trust export;
- lifecycle event list and health/expiry status;
- consumer acknowledgement and assignment activation.

Each request carries workspace/client context and an idempotency key for
mutating calls. Long-running rotations and rollovers return operation records
that front ends can poll or stream through the existing event rail. Secret
responses are marked in schema and are never stored in daemon operation
records or logs.

Secret-bearing methods require an authenticated principal, an explicit
authorization decision, and a confidential transport. They return no-store
responses and are unavailable through an unauthenticated remote listener. A
future web or Elixir control plane can manage public metadata and lifecycle
without receiving key material; private export remains a separately granted
operation.

The OpenAPI artifact remains usable by a future web or Elixir application.
No external interface imports `core/internal` packages.

## SDK plan

The public SDK has three explicit roles that share generated wire contracts but
do not expose one another's authority.

### Control clients

| Language | Namespace/package | Required capability |
| --- | --- | --- |
| Go | `hovel/control` and `hovel/pki` | Typed daemon client, manifests, assertions. |
| Python | `hovel_sdk.control` and `hovel_sdk.pki` | Sync client first, pytest helpers. |
| Rust | `hovel::control` and `hovel::pki` | Typed client consistent with the current dependency-minimal SDK policy. |
| C | `hovel_control.h` and `hovel_pki.h` | Stable ABI, explicit buffers/errors, bundle assertions. |

The control API is contract-tested against the daemon OpenAPI and protocol
fixtures. It must work against a real temporary daemon in language-specific
integration tests.

### Provider and implant consumption

Each language gets bundle parsing, validation, PEM/DER conversion, fingerprint,
chain, SAN, EKU, and expiry helpers. Provider SDKs get credential-slot
descriptor types, compatibility-target helpers, and operation-context
resolution. The C package includes an allocation-free view over decoded bundle
members suitable for constrained consumers, plus an owned form for desktop
providers. Library adapters cover at least Go TLS, Mbed TLS, and wolfSSL
without making one adapter part of the canonical bundle model.

Provider SDKs register optional delivery/stamp capabilities rather than
implementing a wide interface with unsupported methods. Standard targets and
materials use generated enums and tagged unions. A provider-defined target is
an opaque-to-core envelope with provider ID, schema version, declared JSON
Schema, and SDK-side typed decoder; it is not an unversioned free-form map. C
uses versioned function tables whose absent capability pointers remain null.

### Crypto backend implementations

Backend-author SDKs expose the versioned descriptor and typed key, CSR,
certificate, CRL, parse, verify, purpose-scoped sign, import, export, and
health requests.
They integrate through the existing package discovery and JSON-RPC runtime
conventions but have a distinct capability and permission set. Contract tests
are generated for every SDK language; a backend declares whether it accepts
scoped private bytes, owns non-exportable handles, or delegates signing to a
platform service. Ordinary provider/implant SDK users cannot invoke this
dispatch surface.

Signer requests are purpose-scoped (`certificate`, `CSR`, or `CRL`) and bind
the planned operation and expected algorithm. A generic arbitrary-data signing
oracle is not part of the default backend contract.

Mbed TLS interoperability is an explicit acceptance target for the embedded
compatibility target. Tests must prove certificate and private-key loading,
chain validation, full-duplex encrypted traffic, and mutual TLS with both
client and server authentication using material issued by Hovel. At least one
fixture must compile through the repository's checked-out Mbed OS 5.15.9
target task; it must not assume Linux filesystems, processes, sockets, or
environment variables. A host-side Mbed TLS harness covers runtime handshakes
when the Mbed OS compile target cannot execute in CI.

The C SDK accepts caller-owned input and output buffers with explicit lengths.
An embedded consumer may use provider-generated static DER arrays and avoid
shipping a JSON parser or base64 decoder in the implant; the JSON bundle
remains the canonical exchange and fixture format, not a required on-device
storage format.

### Test and assertion examples

Python:

```python
with HovelTestDaemon() as hovel:
    ca = hovel.pki.create_authority(profile="root-modern")
    leaf = hovel.pki.issue(issuer=ca.id, profile="tls-server", dns=["lp.test"])
    assert_certificate(leaf).chains_to(ca).has_dns("lp.test").valid_at(hovel.clock.now())
```

Go:

```go
daemon := hoveltest.StartDaemon(t)
ca := daemon.PKI().CreateAuthority(t, pki.RootModern())
leaf := daemon.PKI().Issue(t, pki.TLSServer("lp.test", ca.ID))
hoveltest.AssertCertificate(t, leaf).ChainsTo(ca).HasDNS("lp.test")
```

Rust and C fixtures must express the same workflow and assertions with their
idiomatic error models. Assertion failures print IDs and certificate metadata,
never private bytes. Python suites use pytest rather than `unittest`.

## Persistence and events

Add contiguous SQLite migrations for tables equivalent to:

```text
pki_profiles
pki_backends
pki_backend_capability_snapshots
pki_authorities
pki_certificates
pki_certificate_generations
pki_assignments
pki_trust_sets
pki_rotation_policies
pki_revocations
pki_crl_generations
pki_credential_stamps
pki_operations
pki_events
pki_key_envelopes
```

Normalize fields needed for uniqueness, expiry, active-state, consumer, serial,
fingerprint, issuer, and stamp queries. Preserve the complete typed record as
versioned JSON where that matches current repository practice. Secret envelopes
are never returned by general store interfaces.

Required event types include plan, create, import, issue, resolve, export,
renew, rotate, activate, revoke, lock, unlock, rollover phase, expire,
compromise, CRL publish, backend install/enable/upgrade/health, stamp, backup,
restore, and destroy. Event fields contain IDs, hashes, policy decisions, and
caller context but no private material.

## Documentation and VHS plan

Use the existing Book/Modules split rather than duplicating generic guidance:

- add `docs/site/spec/certificate-management.html` under **Book** for operator
  concepts, lifecycle, commands, manifests, security, and demos;
- add `docs/site/spec/certificate-development.html` under **Book** for generic
  Mesh provider, listener, implant, stager, C2, service, and control-client
  integration contracts, crypto-backend development, and complete Go, Python,
  Rust, and C examples;
- keep provider-specific wiring on that provider's **Modules** pages and link
  back to the generic development guide.

Required demo series:

1. `pki-01-create-authorities.tape` — use the Huh wizard to create a root and
   subordinate with an explicit crypto backend and compatibility target, then
   show the hierarchy and locked root.
2. `pki-02-issue-and-export.tape` — issue a listener mTLS certificate, inspect
   SAN/EKU/fingerprint, and export a redacted/public bundle plus an explicit
   private bundle to a protected path.
3. `pki-03-bind-mesh-listener.tape` — bind an assignment to a Mesh listener,
   start it, and show the credential stamp and daemon operation bookkeeping.
4. `pki-04-rotate.tape` — stage a new generation, show overlap trust, activate,
   and identify the superseded generation.
5. `pki-05-sdk-assertions.tape` — run one language SDK test against a temporary
   daemon and show chain/SAN/expiry plus Mbed TLS/wolfSSL compatibility
   assertions.

The two Book pages together must include:

- trust hierarchy and assignment diagrams;
- the exact bundle schema and secret-redaction behavior;
- default profiles and full-field override examples;
- crypto-backend selection, capability negotiation, and independent Mbed TLS
  and wolfSSL compatibility-target examples;
- declarative manifest and imperative command equivalents;
- Mesh/listener/implant/stager integration examples;
- seamless standard-slot, explicit no-stamp, and advanced address/offset/
  symbol/provider-defined stamping examples with preconditions;
- renewal versus rotation and CA rollover timelines;
- SDK examples for Go, Python, Rust, and C;
- backup, compromise, revocation, and troubleshooting guidance;
- a clear implemented/planned status table while work is phased.

Each tape is a Bazel-declared demo in `STANDARD_DEMOS`. Extend the fast demo
verifier to run the same commands without Chrome and assert authority hierarchy,
chain validity, redaction, assignment/stamp bookkeeping, rotation state, and
SDK behavior. Visual success alone is not evidence.

## Implementation sequence

Each slice ends with domain, storage, daemon, command, SDK, and docs evidence
where applicable. Do not build the wizard first.

### Slice 1: contracts and local issuance

- Add pure domain types, backend/compatibility descriptors, profiles, template
  validation, bundle v1, the built-in issuer, and cryptographic tests.
- Support generated root, subordinate, and leaf certificates in memory.
- Prove DER/PKCS #8 round trips and Go TLS/mTLS handshakes.

### Slice 2: durable custody and inventory

- Choose and document the workspace secret provider.
- Add encrypted local key store, SQLite migrations, authority/certificate list
  and inspect, lock/unlock, import/export, and event audit.
- Add backup/restore and secret-redaction tests before any front-end secret
  export.

### Slice 3: daemon API, commands, manifests, and Huh

- Add application service, RPC/OpenAPI methods, imperative `pki` registry
  commands, plan/apply manifests, and the Huh wizard.
- Add idempotency, confirmation, JSON output, and daemon E2E tests.

### Slice 4: assignments, stamping, Mesh, and payloads

- Add assignment/trust-set activation and credential stamps.
- Add Mesh credential-slot contracts plus optional none/runtime/file,
  standard-slot, and advanced-target delivery.
- Integrate payload stamp provenance and installed-payload generation tracking.
- Prove no descriptor/list output leaks private material.

### Slice 5: lifecycle automation

- Add renew, rotate, expiry health, revocation/CRLs, compromise response, and
  staged CA rollover.
- Add consumer acknowledgement and retry-safe long-running operation records.
- Test interrupted delivery, concurrent rotation, and rollback behavior.

### Slice 6: cross-language SDKs and embedded interoperability

- Publish Go, Python, Rust, and C control clients, bundle consumers, fixtures,
  and assertion APIs.
- Publish the external `pki-backend` contract and reference Mbed TLS/wolfSSL
  compatibility adapters without requiring either library in core.
- Add real-daemon contract suites for every language.
- Add Mbed TLS server/client/mTLS interoperability and Mbed OS target
  compilation for the registered `mbedtls/mbed-os-5.15.9` compatibility
  target through `task picblobs:mbed-compile`.

### Slice 7: Book pages and generated demos

- Add both Book pages, navigation, provider-page links, OpenAPI/API links, five
  tapes, fast verifier, generated GIFs, and troubleshooting examples.
- Run remote-compatible docs checks and host-service site rendering separately.

## Verification matrix

### Domain and crypto

- constructors reject invalid IDs, hierarchy, constraints, validity, usage,
  SANs, serials, algorithms, and duplicate extensions;
- root, subordinate, leaf, imported CSR, and external signer paths verify;
- path-length and name constraints are enforced;
- every default profile has golden semantic assertions, not golden keys;
- capability negotiation rejects unsupported operations and incompatible
  backend/consumer pairs without silently falling back;
- independent post-issuance validation rejects a backend result that differs
  semantically from the resolved template;
- fuzz certificate, CSR, manifest, bundle, and custom-extension parsing;
- fuzz stamp target/material parsing, 64-bit wire-address conversion, and
  provider-defined target envelopes;
- private and public keys are proven to match before persistence or export.

### Security and persistence

- private bytes never appear in list/inspect JSON, events, logs, errors,
  summaries, test failures, OpenAPI examples, or SQLite metadata JSON;
- wrong workspace key, modified envelope, swapped key ID, and truncated data
  fail closed;
- unapproved, digest-changed, over-privileged, or unavailable backends fail
  closed before private material is resolved;
- owner-only atomic file export is tested on supported platforms;
- migration, rollback, backup, restore, lock, unlock, and destroy are tested;
- race tests cover concurrent issue, rotate, activate, and revoke.

### Lifecycle and integrations

- renewal reuses a key and rotation does not;
- failed staging leaves the old generation active;
- overlap trust validates old and new identities during rollover;
- revocation and compromise stop issuance and mark assignments degraded;
- Mesh listener/node and payload stamps point to exact generations;
- installed payload inventory can report outdated credential generations;
- absent stamp capability does not block unrelated provider operations;
- offset/address overflow, out-of-bounds writes, stale artifact hashes,
  expected-byte mismatches, ambiguous patterns, oversized material, and false
  provider success all fail before assignment activation;
- standard slot, no-stamp, file offset, virtual address, symbol/marker, and one
  provider-defined target have contract and bookkeeping tests;
- Go, Python, Rust, C, Mbed TLS, and wolfSSL consume the same fixture bundles.

### Front ends and docs

- CLI, Huh, manifest, MCP, REST/OpenAPI, and SDK calls produce equivalent plans;
- every mutating API is idempotent under a repeated idempotency key;
- OpenAPI, daemon registrations, SDK fixtures, and human docs stay aligned;
- backend descriptors, SDK dispatch, manifest schemas, and daemon capability
  validation stay contract-aligned;
- five fast non-visual demo scenarios pass before VHS rendering;
- `task ci` passes for remote-compatible checks;
- `task docs:site` passes separately on a host with required services.

## Completion evidence

The feature is complete only when all required outcomes have direct evidence:

| Requirement | Required proof |
| --- | --- |
| Root/subordinate/leaf lifecycle | Domain, crypto, store, daemon E2E, and CLI tests. |
| Full field control and defaults | Template matrix tests and rendered plan fixtures. |
| Bundle contract | Cross-language fixtures and redaction/export tests. |
| Key custody | Envelope tamper, lock/lease, backup/restore, external-handle, and secret-leak tests. |
| Tracking and rotation | SQLite lifecycle and interrupted-rollout tests. |
| Revocation and rollover | CRL publication, trust overlap, consumer acknowledgement, and compromise tests. |
| Mesh/implant/stager use | Assignment, slot, stamp, and Mbed TLS integration tests. |
| Flexible stamping | Optional-capability, no-stamp, standard-slot, raw target, bounds, precondition, and result-verification tests. |
| Provider choice | Built-in plus Mbed TLS/wolfSSL compatibility fixtures and backend capability-contract tests. |
| External interface | OpenAPI alignment and real-daemon SDK suites. |
| Cross-language SDKs | Go, pytest-based Python, Rust, and C control/provider/backend contract suites. |
| No custom front-end code | Manifest, CLI/Huh, MCP/API, and SDK parity tests. |
| Developer documentation | Both Book guides, Modules links, smoke/link checks, five verifiers, and rendered GIFs. |

Passing only a crypto unit test, a CLI demo, or one language SDK is not enough
to claim the system is complete.

## Primary references

- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [Go `crypto/x509` package](https://pkg.go.dev/crypto/x509)
- [Charmbracelet Huh](https://github.com/charmbracelet/huh)
- [Mbed TLS documentation](https://mbed-tls.readthedocs.io/en/latest/)
- [wolfSSL keys and certificates](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter07.html)
