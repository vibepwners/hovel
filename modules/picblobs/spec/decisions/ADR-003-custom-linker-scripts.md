# ADR-003: Custom Linker Scripts for Blob Binary Layout

## Status
Accepted

## Context

PIC blobs must be flat binaries with a precise, predictable layout: code first, then data, then a config section at a known offset. Standard GCC linker scripts produce ELFs designed for OS loaders, with sections and metadata that are unnecessary and counterproductive for PIC blobs. We need the C code to be able to reference the config section via a symbol, while the extraction tool needs to know where the code ends and the config begins.

## Decision

Each target OS SHALL have a custom GCC LD linker script that defines the blob's memory layout, section ordering, and the config section. The linker scripts SHALL:

1. Merge all code sections into `.text`, all read-only data into `.rodata`, all mutable data into `.data`, and all zero-initialized data into `.bss`.
2. Place a `.config` section at the end with linker-defined symbols (`__config_start`, `__config_end`).
3. Discard unnecessary sections (`.eh_frame`, `.comment`, `.note`, `.dynamic`, `.interp`).
4. Export `__blob_start` and `__blob_end` symbols for the extraction tool.
5. Use minimal alignment to keep blobs small.

## Alternatives Considered

- **`objcopy -O binary`**: Simpler but provides no control over section ordering, no config section mechanism, and no metadata. The blob author would have to use ad hoc conventions (e.g., magic bytes) to locate config data. Rejected.
- **In-blob config via preprocessor**: Define config as a C array with placeholder bytes, patched by Python at known offsets. Works but fragile: any change to the code before the config array shifts the offset. The linker script approach makes the offset a stable linker symbol. Rejected.
- **No config section — append-only**: Compile the blob without any config awareness; Python simply appends data after the blob. The blob would need a runtime mechanism (scan backward for magic, or use blob size as offset) to find the config. Rejected: less reliable than a linker-defined symbol, and the blob would need to know its own size at runtime.

## Consequences

- One linker script per OS must be written and maintained (though they may be nearly identical for Linux and FreeBSD).
- The linker script is a critical build artifact: errors in it produce subtly broken blobs. It must be well-tested.
- The extraction tool (REQ-013) depends on the linker script's section names and symbol names.
- Developers modifying the blob layout must update both the linker script and the extraction tool.

## Related Requirements
- REQ-012
