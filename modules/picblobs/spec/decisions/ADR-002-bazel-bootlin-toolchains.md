# ADR-002: Bazel with Bootlin Toolchains for Build System

## Status
Accepted

## Context

picblobs must cross-compile C code for 7+ architectures from a single build host. The build system must be hermetic (no reliance on system-installed compilers), reproducible (same commit = same output), and capable of expressing the complex build graph (C compilation -> custom linking -> ELF extraction -> metadata generation -> Python codegen -> wheel packaging).

## Decision

The build system SHALL be Bazel, with cross-compilation toolchains sourced from toolchains.bootlin.com.

**Bazel** because:
- Hermetic builds: Bazel sandboxes each action and fetches external dependencies (including toolchains) as declared inputs.
- Cross-compilation: Bazel's toolchain resolution and platform system natively support building the same source for many target platforms.
- Build graph: Bazel can express the full pipeline from C source to Python wheel as a single queryable graph with correct incremental rebuilds.
- Caching: Bazel's action cache and remote caching support fast incremental builds across the 96-blob matrix.

**Bootlin** because:
- Pre-built archives: Bootlin provides downloadable GCC cross-compiler archives for a wide range of architectures (x86_64, i686, aarch64, arm, mips, mipsel, and more).
- Version pinning: Each archive has a stable URL and can be checksummed for reproducibility.
- Bazel integration: Bootlin archives can be registered as Bazel CC toolchains with straightforward configuration.
- No system dependency: Developers and CI do not need to `apt install` cross-compilers.

## Alternatives Considered

- **Make + system GCC**: Simple but not hermetic, not reproducible, and requires manual cross-compiler installation. Rejected.
- **CMake**: Good cross-compilation support but weaker hermeticity and more complex multi-platform configuration. Rejected.
- **Docker-based builds**: Hermetic at the container level but heavyweight, slower iteration, and harder to integrate with Python packaging. Rejected.
- **Zig cc as CC proxy**: Zig bundles LLVM and supports many targets without separate toolchains. Considered but rejected for v1: less mature Bazel integration and less community experience with obscure architecture targets (armv5, mips).
- **Nix**: Excellent for reproducibility but steeper learning curve and a full system-level dependency. Rejected for the build system role (Nix could still be used to provision the developer environment).

## Consequences

- All developers and CI systems need only Bazel (and its launcher, Bazelisk) installed. Toolchains are fetched automatically.
- The Bazel WORKSPACE (or MODULE.bazel) will contain toolchain fetch rules for each Bootlin archive, with SHA256 checksums.
- Toolchain updates (new GCC version from Bootlin) require updating the archive URLs and checksums.
- Bazel's learning curve is non-trivial, but the payoff in hermeticity and caching is significant for a project with 96+ build targets.

## Related Requirements
- REQ-011
