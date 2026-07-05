# ADR-016: Bazel 9 with bzlmod and Module Extensions for Project Structure

## Status
Accepted

## Context

ADR-002 decided on Bazel with Bootlin toolchains but did not specify the Bazel version or module system. Bazel has two dependency management approaches: the legacy WORKSPACE system and the newer bzlmod (MODULE.bazel) system. Bazel 9 is the current release and makes bzlmod the default.

The project also needs to integrate several external rule sets: rules_cc for C compilation, rules_python for build tools, and custom toolchain definitions for Bootlin cross-compilers.

## Decision

The project SHALL use Bazel 9 with bzlmod (MODULE.bazel) as the module system. Bootlin toolchain provisioning SHALL be implemented as a module extension (`//modules/picblobs/toolchains:bootlin.bzl`) rather than WORKSPACE repository rules.

The project layout SHALL be:

```
MODULE.bazel          — bzlmod dependencies and toolchain extension
platforms/            — 16 OS/arch platform definitions
toolchains/           — Bootlin CC toolchain registrations
bazel/                — custom Starlark rules (blob, lint, uv, qemu_test)
src/                  — C source tree (include/, syscall/, blob/, linker/)
tests/runners/        — test runner binaries (linux/, freebsd/, windows/)
tools/                — Python build tools (extractor, codegen)
python/               — Python package and pyproject.toml
```

## Alternatives Considered

- **WORKSPACE file**: Legacy approach, still works in Bazel 9 but deprecated. Module extensions provide better dependency resolution and are the forward-compatible path. Rejected.
- **Monorepo with external rule repos**: Vendoring rules_cc etc. into the repo. Unnecessary overhead given bzlmod's registry. Rejected.

## Rationale

bzlmod provides hermetic dependency resolution from the Bazel Central Registry, eliminates WORKSPACE ordering issues, and is the recommended approach for all new Bazel projects. Module extensions cleanly encapsulate the Bootlin toolchain download logic.

## Consequences

- Developers need Bazel 9+ (pinned via .bazelversion).
- All external dependencies are declared in MODULE.bazel with version pins.
- Bootlin toolchain archives are fetched via the custom `bootlin` module extension.
- The MODULE.bazel.lock file is gitignored to avoid noisy diffs; reproducibility is ensured by SHA256 pins on toolchain archives.

## Related Requirements
- REQ-011
