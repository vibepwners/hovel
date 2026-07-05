# REQ-015: Python Builder-Pattern API

## Status
Accepted

## Statement

picblobs SHALL expose a Python builder-pattern API that allows consumers to select a target OS, architecture, and blob type, configure the blob's parameters, and produce a ready-to-use flat PIC blob as a `bytes` object. The builder SHALL validate all parameters, assemble the config struct, and concatenate the pre-compiled blob binary with the serialized config struct to produce the final output.

## Rationale

A builder pattern provides a fluent, discoverable API that guides the consumer through the required configuration steps and catches errors early (before producing an invalid blob). It is more ergonomic than a single function call with many keyword arguments, and it makes the required vs. optional nature of each parameter explicit through the builder chain.

## Derives From
- VIS-001

## Detailed Requirements

### Builder Interface

The builder API SHALL follow this pattern:

1. **Construction**: `picblobs.Blob(os, arch)` — creates a builder bound to a specific OS and architecture. The `os` and `arch` parameters SHALL accept string values or enum members (see below).
2. **Blob type selection**: `.alloc_jump()`, `.reflective_pe()`, `.stager_tcp()`, `.stager_fd()`, `.stager_pipe()`, `.stager_mmap()` — selects the blob type. Returns a type-specific builder that exposes only the config parameters relevant to that blob type. For reflective ELF loading, use `ul_exec()`.
3. **Configuration**: Type-specific methods to set config parameters. Examples:
   - `.alloc_jump().payload(data: bytes)` — sets the payload to copy and execute.
   - `.stager_tcp().address("192.168.1.1").port(4444)` — sets the connect-back target.
   - `.ul_exec().elf(data: bytes).argv(["./prog"]).envp(["PATH=/usr/bin"])` — sets the ELF image, arguments, and environment.
   - `.reflective_pe().pe(data: bytes).call_dll_main(True)` — sets the PE image and flags.
4. **Build**: `.build() -> bytes` — validates all required parameters are set, serializes the config struct, concatenates the pre-compiled blob binary with the config struct, and returns the complete PIC blob as a `bytes` object.

### Enums

The API SHALL define enums for:

- **OS**: `picblobs.OS.LINUX`, `picblobs.OS.FREEBSD`, `picblobs.OS.WINDOWS`.
- **Arch**: `picblobs.Arch.X86_64`, `picblobs.Arch.I686`, `picblobs.Arch.AARCH64`, `picblobs.Arch.ARMV5_ARM`, `picblobs.Arch.ARMV5_THUMB`, `picblobs.Arch.MIPSEL32`, `picblobs.Arch.MIPSBE32`.

String aliases SHALL also be accepted (e.g., `"linux"`, `"x86_64"`), normalized to the canonical enum values.

### Validation

The `.build()` method SHALL validate:

1. The selected OS/architecture/blob-type combination is supported (exists in the pre-compiled blob set).
2. All required config parameters for the selected blob type have been set.
3. Parameter values are within acceptable ranges (e.g., port numbers 0-65535, payload size > 0).
4. The serialized config struct is well-formed and the correct size.

If validation fails, a descriptive exception SHALL be raised (e.g., `picblobs.ValidationError`).

### Output Format

The `.build()` method returns a `bytes` object containing:

1. The pre-compiled blob binary (from the wheel's bundled assets).
2. Immediately followed by the serialized config struct.

The blob code accesses the config struct via PC-relative addressing to the `__config_start` symbol, which is at a known offset from the start of the blob (recorded in the blob's metadata). The Python API places the config struct at exactly this offset.

### Immutability and Reuse

The builder SHALL be immutable-by-default: each configuration method returns a new builder instance (or a copy), so that a partially-configured builder can be reused as a template. For example:

```
linux_x86 = picblobs.Blob("linux", "x86_64")
tcp_stager = linux_x86.stager_tcp().port(4444)

blob_a = tcp_stager.address("10.0.0.1").build()
blob_b = tcp_stager.address("10.0.0.2").build()
```

### Error Messages

All exceptions SHALL include the specific parameter that failed validation and what was expected vs. what was provided. For unsupported combinations, the error message SHALL list the supported combinations for the given OS or architecture.

## Acceptance Criteria

1. The builder API can produce a valid blob for every supported OS/architecture/blob-type combination.
2. Attempting to build with missing required parameters raises `ValidationError` with a descriptive message.
3. Attempting to build for an unsupported combination raises `ValidationError` listing supported alternatives.
4. The builder is immutable: reusing a partial builder does not corrupt state.
5. String and enum parameter forms are both accepted and produce identical output.
6. The output `bytes` object is a valid PIC blob that executes correctly on the target platform.

## Verified By
- TEST-008
