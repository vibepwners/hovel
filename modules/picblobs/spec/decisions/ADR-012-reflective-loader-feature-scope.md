# ADR-012: Reflective Loader Feature Scope — All Major ELF and PE Features in v1

## Status
Accepted

## Context

REQ-008 (Reflective ELF Loader) and REQ-009 (Reflective PE Loader) define reflective loading but do not explicitly bound which ELF/PE features are supported. Each unsupported feature is a potential silent runtime failure. A clear scope decision is needed so that implementation can be bounded and verification artifacts can cover every feature.

## Decision

Both reflective loaders SHALL support all major features of their respective formats in v1. Specifically:

### ELF (REQ-008)

The reflective ELF loader SHALL support:

- **PT_LOAD segment mapping** with correct alignment and permissions.
- **ET_EXEC and ET_DYN** (PIE) images.
- **Relocations**: R_*_RELATIVE, R_*_GLOB_DAT, R_*_JUMP_SLOT, R_*_64/R_*_32, and architecture-specific relocation types for all supported architectures.
- **TLS** (`PT_TLS` segment): allocate and initialize thread-local storage for the main thread, set TLS base via architecture-appropriate mechanism.
- **IFUNC resolvers**: resolve `STT_GNU_IFUNC` symbols by calling the resolver function and using the returned address.
- **GNU hash and sysv hash**: support both `.gnu.hash` and `.hash` sections for symbol lookup.
- **Constructors and destructors**: execute `.init_array` entries before entry point transfer; `.fini_array` is documented but not guaranteed to execute (one-shot execution model, see ADR-014).
- **Version symbols**: parse `.gnu.version` and `.gnu.version_r` sections for versioned symbol resolution.
- **Dynamic linking**: resolve `DT_NEEDED` dependencies from already-loaded libraries in the process address space.
- **BSS zero-fill**: correct handling of memory size > file size in PT_LOAD segments.
- **Auxiliary vector**: set up minimal auxv on stack for ELFs that inspect it.

### PE (REQ-009)

The reflective PE loader SHALL support:

- **Section mapping** with correct alignment and page protections.
- **Base relocations**: IMAGE_REL_BASED_DIR64 (x86_64), IMAGE_REL_BASED_ABSOLUTE (no-op), and ARM64-specific relocation types.
- **Import resolution** via PEB walk, including loading DLLs not yet in the process via `LoadLibraryA`.
- **Delay-load imports**: resolved eagerly at load time using the same mechanism as standard imports.
- **TLS callbacks**: invoked with DLL_PROCESS_ATTACH after full image setup, before entry point.
- **Exception directory** (`.pdata` / SEH): registered via `RtlAddFunctionTable` on x86_64 for structured exception handling.
- **Forwarded exports**: followed during import resolution.
- **.NET assemblies**: detected via CLR header; CLR runtime initialized and managed entry point invoked.
- **SxS manifest resolution**: embedded manifests parsed, SxS assembly dependencies resolved.
- **API set resolution**: api-ms-win-* names translated via PEB API set schema map.
- **Module list registration**: loaded image inserted into PEB module lists.

## Alternatives Considered

- **Minimal subset (PT_LOAD + relocations only)**: Simpler to implement but would silently fail on any non-trivial ELF or PE. Rejected — silent failure is worse than implementation effort.
- **Feature flags (opt-in per feature)**: Adds config complexity and code-size overhead for conditional compilation. Rejected for v1 — all features are always present.

## Consequences

- The reflective loaders will be the largest and most complex blobs in the project.
- Verification (TEST-005) must cover each feature explicitly.
- .NET assembly support and SxS resolution on Windows are the highest-risk features and may require iterative development.

## Related Requirements
- REQ-008
- REQ-009
