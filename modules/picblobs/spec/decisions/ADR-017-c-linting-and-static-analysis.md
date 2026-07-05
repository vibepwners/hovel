# ADR-017: clang-tidy and cppcheck for C Linting and Static Analysis

## Status
Accepted

## Context

The project compiles freestanding C code for multiple architectures. Static analysis is important because the code runs without libc protections, handles raw memory operations, and must be correct across 7 instruction set architectures. The linting and analysis tooling must integrate with Bazel so it participates in the build graph and CI.

## Decision

Two complementary tools SHALL be used for C code quality:

1. **clang-tidy** — integrated as a Bazel aspect (`//modules/picblobs/bazel:lint.bzl#clang_tidy_aspect`). Invoked via `bazel build --config=picblobs_lint //modules/picblobs/src/...`. Checks are configured in `.clang-tidy` at the repo root, tuned for freestanding C: no libc API checks, naming conventions enforced, portability and bugprone checks enabled.

2. **cppcheck** — integrated as a Bazel test rule (`//modules/picblobs/bazel:lint.bzl#cppcheck_test`). The rule invokes a Bazel-managed cppcheck wheel through `//modules/picblobs/tools:run_cppcheck`, so CI and local Bazel tests do not depend on a host `cppcheck`, `make`, or C++ compiler installation. Each source directory can define a `cppcheck_test` target that runs cppcheck and fails on warnings. This catches issues clang-tidy misses (e.g., some buffer overflows, null dereference paths).

clang-tidy degrades gracefully if not installed unless CI enforcement is enabled. cppcheck is resolved by Bazel and must run when its test targets are selected.

## Alternatives Considered

- **rules_lint from aspect-build**: Community Bazel rules for multi-language linting. Mature but heavyweight for a C-only project. Rejected for v1; may reconsider if the project adds more languages.
- **Coverity / PVS-Studio**: Commercial static analyzers with deeper analysis. Overkill for project size and budget. Not rejected permanently — can be added later for security-sensitive paths.
- **GCC -fanalyzer**: GCC's built-in static analyzer. Good for some checks but less configurable than clang-tidy and doesn't support the same breadth of checks. May be added as a supplemental check later.

## Consequences

- CI must have clang-tidy installed when lint enforcement is enabled; cppcheck is provided by Bazel.
- `.clang-tidy` config is tuned for freestanding code (no standard library checks).
- `--config=picblobs_lint` in .bazelrc enables the clang-tidy aspect.
- Each C source directory should define a `cppcheck_test` target.

## Related Requirements
- REQ-011 (build system)

## Supersedes
- None
