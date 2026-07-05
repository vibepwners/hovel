# picblobs-cli

Click-based command-line interface for the
[picblobs](https://pypi.org/project/picblobs/) library. Bundles the
cross-compiled test runners and verifier-only `ul_exec` test ELFs so
that blobs can be executed under `qemu-*-static` without any external
setup.

```bash
pip install picblobs-cli

picblobs-cli run hello linux:aarch64
picblobs-cli build stager_tcp linux:x86_64 \
    --address 10.0.0.1 --port 4444 -o stage.bin
picblobs-cli verify --os linux
```

See `spec/requirements/REQ-020-picblobs-cli.md` for the full command
reference and `spec/decisions/ADR-026-runner-tools-split-into-picblobs-cli.md`
for the design rationale.
