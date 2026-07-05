# VIS-001: Product Vision

## Status
Accepted

## Specification Intent

This specification describes the aspirational end-state of the picblobs system. Requirements, design models, and verification artifacts define the complete intended capability of the project at full maturity — not a scoped delivery milestone. Individual features and subsystems will be implemented incrementally, and intermediate states of the codebase are not expected to satisfy every requirement simultaneously. The specification exists to ensure that the full vision is captured durably so that incremental implementation decisions remain coherent with the intended whole.

## Mission

picblobs is a general-purpose Python library that provides pre-compiled, position-independent code (PIC) blobs for loading and executing arbitrary payloads on arbitrary operating systems and architectures. It exists so that any project needing raw PIC stubs — offensive security tooling, security research, embedded systems testing, fuzzing harnesses, or cross-platform loaders — can obtain correct, tested blobs through a simple Python API without hand-writing shellcode.

## Problem Statement

Producing correct PIC for a given OS/architecture combination is tedious, error-prone, and repetitive. Each combination requires knowledge of the target's syscall ABI (Linux, FreeBSD) or runtime linking conventions (Windows PEB/TEB), instruction encoding, calling conventions, and position-independent data access patterns. Most projects that need PIC blobs either copy-paste fragile assembly from public repositories or hand-roll single-target stubs that are never tested on other architectures.

There is no widely available, tested, multi-OS, multi-architecture library that produces PIC blobs from a single API, backed by a principled C codebase compiled through a reproducible cross-compilation pipeline.

## Target Users

1. **Security researchers** studying shellcode, exploit primitives, or OS internals across platforms.
2. **Red team and penetration testing operators** who need reliable PIC stubs for authorized engagements.
3. **Tool authors** building frameworks, loaders, or implant generators that target multiple OS/arch pairs.
4. **Embedded systems engineers** who need minimal PIC stubs for bare-metal or constrained environments.
5. **Any developer** whose project requires raw position-independent machine code.

## Value Proposition

- **Correctness**: Every blob is compiled from reviewed C source, not hand-assembled, reducing encoding bugs.
- **Coverage**: One library covers Linux, FreeBSD, and Windows across a broad architecture matrix.
- **Simplicity**: A Python builder API produces ready-to-use bytes — no toolchain installation required by the consumer.
- **Modularity**: The C codebase isolates platform-specific concerns (one assembly stub per architecture, pure C for everything else), making it straightforward to add new targets.
- **Reproducibility**: Blobs are built via Bazel with pinned Bootlin cross-compilation toolchains, ensuring bit-for-bit reproducible output.
- **Introspection**: Rich metadata lets consumers query blob properties, config layouts, and the full OS/arch support matrix.

## Success Criteria

1. A user can `pip install picblobs` and generate a working PIC blob for any supported OS/arch/blob-type combination in under five lines of Python.
2. Every blob in the support matrix passes execution verification under QEMU user-static (Linux/FreeBSD) or equivalent (Windows).
3. Adding a new architecture requires only: one syscall assembly stub, a syscall number table, and a Bazel toolchain registration — no changes to blob logic or the Python API.
4. Adding a new blob type requires only: C source implementing the blob against the existing syscall/PEB abstraction layer — no changes to the build pipeline or assembly stubs.
