# ADR-011: Build Pipeline Security and Toolchain Provenance

## Status
Accepted

## Context

picblobs produces position-independent code blobs used in security research, red teaming, and embedded development. The build pipeline fetches external toolchains from the internet (Bootlin CDN) and produces binary artifacts shipped via PyPI. A compromised toolchain or non-reproducible build could inject malicious code into every blob in the wheel, affecting all downstream consumers.

The build pipeline's integrity is therefore a first-order security concern — not merely a development convenience.

## Decision

The picblobs build pipeline SHALL enforce the following security properties:

### Toolchain Provenance

1. **SHA256 pinning**: Every Bootlin toolchain archive SHALL be pinned by SHA256 hash in the Bazel workspace configuration. Bazel SHALL fail the build if the downloaded archive does not match the pinned hash.
2. **Version pinning**: Toolchain versions SHALL be pinned to specific Bootlin release identifiers (not "latest" or floating tags).
3. **Pinned hash auditing**: When updating a toolchain version, the new SHA256 hash SHALL be obtained by downloading the archive from the canonical Bootlin URL and computing the hash locally. The version bump and hash change SHALL be committed together with a rationale note.

### Reproducible Builds

4. **Bit-for-bit reproducibility**: Given the same source tree and Bazel version, the build SHALL produce identical blob binaries. This is verified by TEST-001.
5. **No host-dependent state**: The build SHALL not depend on the build host's installed compilers, system headers, locale, timezone, or other environment state. Bazel hermeticity and Bootlin toolchains provide this property.
6. **Deterministic linking**: Linker scripts and link flags SHALL not introduce non-determinism (e.g., no timestamps in binaries, no ASLR-dependent section ordering at link time).

### Wheel Integrity

7. **Build hash embedding**: Each blob binary SHALL embed a build hash in its metadata (REQ-013) that can be independently recomputed from source to verify provenance.
8. **No external runtime dependencies**: The wheel SHALL not fetch or execute code at install time or import time. All blob binaries are pre-compiled and included in the wheel.

## Alternatives Considered

- **Signed toolchain binaries**: Bootlin does not currently provide GPG signatures on toolchain archives. SHA256 pinning against a known-good download provides equivalent tamper detection for our use case.

- **Reproducible build attestation (e.g., SLSA)**: Valuable but heavyweight for a v1 library. SHA256 pinning plus Bazel hermeticity provides the core property (reproducibility) without requiring a full SLSA framework. SLSA attestation MAY be added in future.

- **Self-hosted toolchain mirror**: Reduces dependence on Bootlin CDN availability but introduces mirror maintenance overhead. Not justified for v1 — Bazel caches toolchains locally after first download.

## Rationale

The core insight is that picblobs' build pipeline is a high-value target precisely because its output is designed to execute as position-independent code. A compromised blob is, by definition, executable shellcode. The cost of build pipeline integrity is low (SHA256 pinning is already in place via ADR-002; reproducibility is a natural consequence of Bazel hermeticity), while the cost of a supply chain compromise would be severe.

## Consequences

- Toolchain version bumps require explicit hash updates and review.
- CI SHOULD verify reproducibility by building twice and comparing outputs.
- The build cannot silently pick up a new toolchain version.
- Future adoption of SLSA or sigstore attestation has a clean foundation to build on.

## Related Requirements
- REQ-011
- REQ-013
- REQ-017

## Related Decisions
- ADR-002
