# ADR-022: Registry-Driven Code Generation

## Status
Accepted

## Context

The original design (ADR-004) positioned C headers as the single source of truth for config structs, with pycparser-based codegen producing Python mirrors. During Sprint 1 implementation, the project grew to support 8 Linux architectures and 3 operating systems, each with distinct syscall numbers, mmap flags, calling conventions, and toolchain configurations. Maintaining C headers, Bazel BUILD files, platform definitions, and test runners by hand across this matrix proved error-prone and difficult to keep consistent.

A Python registry emerged as a more practical single source of truth for the entire platform and build infrastructure. `tools/registry.py` contains:

- **Architecture dataclass definitions**: name, gcc_define, qemu_binary, bootlin_arch, gcc_triple, extra_cflags, cpu_constraint, and behavioral traits (`uses_mmap2`, `needs_got_reloc`, `uses_old_mmap`, etc.).
- **OS definitions** with supported architecture lists.
- **Syscall number tables** per OS per architecture.
- **mmap flag tables** with per-architecture overrides (e.g., MIPS `MAP_ANONYMOUS = 0x0800`).
- **Syscall wrapper definitions** (`SyscallDef` dataclass with name, params, custom_body, and constants).

ADR-004 still applies specifically to config structs (pycparser-based codegen from C headers). ADR-022 covers the broader platform, syscall, and build infrastructure.

## Decision

`tools/registry.py` SHALL be the single source of truth for architecture definitions, syscall numbers, platform configurations, and build config. `tools/generate.py` SHALL read this registry and generate:

- **C headers**: `src/include/picblobs/arch.h`, `syscall.h`, `picblobs.h`, and all `sys/*.h` wrappers.
- **Bazel config**: `platforms/BUILD.bazel`, `toolchains/BUILD.bazel`, `.bazelrc` platform section.
- **Test runners**: `tests/runners/{os}/runner.c`.

All generated files SHALL be committed to git so that changes are reviewable in code review. The generator SHALL support a `--check` mode that verifies generated files match the registry without modifying them. CI SHALL run `generate.py --check` to enforce freshness.

## Alternatives Considered

- **Hand-maintained C headers and BUILD files**: The straightforward approach, but error-prone across 8 architectures and 3 operating systems. A single typo in a syscall number or a forgotten BUILD target creates silent failures. Does not scale.
- **Bazel macros generating everything**: Keeps generation inside the build system, but Starlark is limited in expressiveness and difficult to debug. Complex codegen in `.bzl` files is opaque and hard to test independently.
- **Separate per-concern registries**: One file for architectures, another for syscalls, another for Bazel config. Rejected: fragmented sources are hard to keep consistent, and cross-cutting concerns (e.g., an architecture's syscall numbers influencing both C headers and BUILD files) require coordination across files.

## Consequences

- Adding a new architecture means adding one entry to `registry.py` and running `generate.py`. All downstream files update automatically.
- All generated files are committed to git, making changes visible in pull requests and preserving the ability to build without running the generator.
- CI enforces freshness via `--check` mode: if a developer modifies `registry.py` but forgets to regenerate, the build fails.
- The generator is a development-time dependency only; it does not affect the build or runtime.
- ADR-004 remains in effect for config struct codegen (pycparser path). The two codegen systems are complementary: registry.py handles platform/syscall/build infrastructure, pycparser handles config struct mirroring.

## Related Requirements
- REQ-001
- REQ-018
