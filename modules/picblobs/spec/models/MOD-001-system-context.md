# MOD-001: System Context

## Status
Accepted

## Description

This model describes the external context in which picblobs operates: the actors that interact with it, the systems it depends on, and the boundaries of the project.

## Context Diagram

### Actors

1. **Python Consumer**: Any Python program that imports `picblobs` and uses the builder API to produce PIC blobs. This is the primary actor. The consumer provides a target specification (OS, architecture, blob type) and configuration parameters (payload data, network addresses, file paths, etc.) and receives a flat binary blob as output.

2. **Build Operator**: A developer or CI system that runs the Bazel build to produce the pre-compiled blob assets. The build operator does not interact with the Python API at runtime; they produce the wheel that the consumer installs.

### External Systems

1. **Bootlin Toolchain CDN** (build-time only): Provides GCC cross-compiler archives. Fetched by Bazel during the first build and cached locally. Not contacted at runtime.

2. **Target Execution Environment**: The OS and hardware where the blob will ultimately execute. picblobs has no runtime interaction with this environment — it produces bytes that the consumer is responsible for delivering and executing on the target.

3. **PyPI** (distribution): The wheel is published to PyPI (or a private index). Consumers install it via `pip install picblobs` or `uv pip install picblobs`.

### Boundaries

- **Inside the boundary**: C source code, assembly stubs, linker scripts, extraction tool, codegen tool, Python API, pre-compiled blobs, metadata.
- **Outside the boundary**: Payload generation (the consumer provides payload bytes), delivery mechanism (how the blob reaches the target), target OS/hardware, C2 infrastructure, encoding/encryption.

## Data Flow

```
Build time:
  C source + asm stubs + linker scripts
    -> Bazel + Bootlin GCC
    -> Linked ELF (per OS/arch/blob-type)
    -> pyelftools extraction
    -> Flat blob binary + metadata JSON
    -> Config codegen (C headers -> Python ctypes)
    -> uv wheel build
    -> picblobs-X.Y.Z-py3-none-any.whl

Runtime:
  Consumer Python code
    -> picblobs.Blob(os, arch).stager_tcp().address(...).port(...).build()
    -> Reads pre-compiled blob from package data
    -> Serializes config struct (auto-generated ctypes)
    -> Concatenates blob + config
    -> Returns bytes to consumer
```

## Modeled By

This is the top-level context model. All other models are refinements of components within this boundary.
