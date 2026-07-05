# TEST-011: Payload Pytest Suite

## Status
Accepted

## Verifies
- REQ-007 (alloc-and-jump)
- REQ-008 (reflective ELF loader)
- REQ-009 (reflective PE loader)
- REQ-010 (bootstrap stagers)
- Plus: hello and hello_windows smoke tests

## Goal

Provide a comprehensive, registry-driven pytest suite that exercises every payload type on every platform it supports. Tests run each blob through its OS-appropriate runner under QEMU and assert functional correctness: expected stdout, stderr patterns, and exit codes.

This suite is distinct from `picblobs verify` (which only runs `hello` as a quick smoke test) and from the existing unit tests in `test_extractor.py` / `test_runner.py` / `test_sync.py` (which test the Python tooling, not the blobs themselves).

## Design Decisions

### D1: Registry-Driven Test Matrix

The test matrix is **blob_type x os x arch**, derived at collection time from two sources:

1. **Platform support**: `tools/registry.py` defines which architectures each OS supports.
2. **Blob targets**: `src/payload/BUILD.bazel` defines which blob types exist and which OSes they target.

A payload's OS eligibility is determined by naming convention and an explicit mapping in the test infrastructure:

| Blob type | Target OSes |
|---|---|
| `hello` | linux, freebsd |
| `hello_windows` | windows |
| `alloc_jump` | linux, freebsd, windows |
| `reflective_pe` | windows |
| `stager_tcp` | linux, freebsd, windows |
| `stager_fd` | linux, freebsd, windows |
| `stager_pipe` | linux, freebsd, windows |
| `stager_mmap` | linux, freebsd |

This mapping lives in a Python dict (`PAYLOAD_PLATFORMS`) in the test module, not generated from the registry. The registry provides the arch list per OS; the test infrastructure intersects this with the payload's OS support.

**Rationale**: Blob-to-OS mapping requires human knowledge (e.g., `reflective_pe` is Windows-only). Arch lists within an OS are mechanical and should track the registry automatically.

### D2: Unimplemented Payloads Skip Gracefully

Tests for payloads that don't yet have a built `.so` are skipped at collection time via the existing `@pytest.mark.requires_blobs` marker. The test parametrization is generated for all payload types in `PAYLOAD_PLATFORMS`, but individual test instances skip when the blob file doesn't exist on disk.

This means:
- Adding a new payload `.c` file + BUILD rule + building it is sufficient to activate its tests.
- No `xfail` — skip is the correct semantic (the test isn't expected to fail, it's expected to not run yet).
- `picblobs test --type hello` still filters to just hello tests via the existing env filter mechanism.

### D3: Expected Behavior Registry

Each payload type defines its expected behavior in a Python dataclass:

```python
@dataclass(frozen=True)
class PayloadExpectation:
    """What a payload should produce when executed."""
    blob_type: str
    stdout: bytes | None       # exact match (None = don't check)
    stdout_contains: bytes | None  # substring match (None = don't check)
    exit_code: int
    needs_config: bool         # whether the test must supply a config struct
    needs_infrastructure: bool # whether the test needs external setup (TCP listener, FIFO, etc.)
    timeout: float = 30.0      # per-test timeout in seconds
```

The registry of expectations:

```python
EXPECTATIONS = {
    "hello": PayloadExpectation(
        blob_type="hello",
        stdout=b"Hello, world!\n",
        stdout_contains=None,
        exit_code=0,
        needs_config=False,
        needs_infrastructure=False,
        timeout=10.0,
    ),
    "hello_windows": PayloadExpectation(
        blob_type="hello_windows",
        stdout=b"Hello, world!\n",
        stdout_contains=None,
        exit_code=0,
        needs_config=False,
        needs_infrastructure=False,
        timeout=10.0,
    ),
    "alloc_jump": PayloadExpectation(
        blob_type="alloc_jump",
        stdout=b"PASS",
        stdout_contains=None,
        exit_code=0,
        needs_config=True,
        needs_infrastructure=False,
        timeout=15.0,
    ),
    "reflective_pe": PayloadExpectation(
        blob_type="reflective_pe",
        stdout_contains=b"LOADED",
        stdout=None,
        exit_code=0,
        needs_config=True,
        needs_infrastructure=False,
        timeout=15.0,
    ),
    "stager_tcp": PayloadExpectation(
        blob_type="stager_tcp",
        stdout=b"TCP_OK",
        stdout_contains=None,
        exit_code=0,
        needs_config=True,
        needs_infrastructure=True,
        timeout=30.0,
    ),
    "stager_fd": PayloadExpectation(
        blob_type="stager_fd",
        stdout=b"FD_OK",
        stdout_contains=None,
        exit_code=0,
        needs_config=True,
        needs_infrastructure=True,
        timeout=15.0,
    ),
    "stager_pipe": PayloadExpectation(
        blob_type="stager_pipe",
        stdout_contains=b"PIPE_OK",
        stdout=None,
        exit_code=0,
        needs_config=True,
        needs_infrastructure=True,
        timeout=15.0,
    ),
    "stager_mmap": PayloadExpectation(
        blob_type="stager_mmap",
        stdout=b"MMAP_OK",
        stdout_contains=None,
        exit_code=0,
        needs_config=True,
        needs_infrastructure=False,
        timeout=15.0,
    ),
}
```

**Rationale**: Centralizing expectations makes it trivial to add a new payload (one dict entry + one config builder) and prevents assertion drift across tests.

### D4: Test Payloads Are pic_blob() Targets

Payloads that carry an inner blob (alloc_jump, stagers, reflective loaders) need **test payloads** — tiny PIC programs that write a marker string and exit. These are compiled as `pic_blob()` targets:

```
src/payload/test_pass.c       → writes "PASS\0" to stdout, exit_group(0)
src/payload/test_loaded.c     → writes "LOADED\0" to stdout, exit_group(0)
src/payload/test_tcp_ok.c     → writes "TCP_OK\0" to stdout, exit_group(0)
src/payload/test_fd_ok.c      → writes "FD_OK\0" to stdout, exit_group(0)
src/payload/test_pipe_ok.c    → writes "PIPE_OK\0" to stdout, exit_group(0)
src/payload/test_mmap_ok.c    → writes "MMAP_OK\0" to stdout, exit_group(0)
```

These are built for every Linux architecture (they use Linux syscalls — same as the actual test payloads described in MOD-006). They are staged alongside production blobs into `_blobs/linux/{arch}/test_pass.so` etc.

For **Windows mock runner** tests, the test payloads don't need to actually execute — the mock runner verifies control flow, not payload execution. The test payload is a fixed byte sequence (e.g., `b"\xcc"` trap) whose presence in the allocated region is verified by the mock.

For **FreeBSD shim** tests, same: the shim verifies syscall arguments, not payload execution. A dummy payload suffices.

**Rationale**: Compiling test payloads as `pic_blob()` targets reuses the existing build infrastructure, ensures they work on every architecture, and keeps them small (< 100 bytes each). The build cost is negligible — they're trivial C programs.

### D5: Use `run_blob()` for Execution

All payload tests use `picblobs.runner.run_blob()` as the execution interface. This function already handles:
- Runner discovery (embedded in package or bazel-bin)
- QEMU binary selection
- Native execution detection (skip QEMU when host arch matches)
- Blob preparation (code + config → temp file)
- Timeout enforcement
- Result capture (stdout, stderr, exit code, duration)

Tests do NOT shell out to QEMU directly or reimplement runner logic.

**Rationale**: `run_blob()` is the public API. Testing through it validates the full stack. If `run_blob()` has a bug, the unit tests in `test_runner.py` catch it; the payload tests catch blob bugs.

### D6: Runner Pass/Fail via stdout and Exit Code

All three runner types (Linux, FreeBSD shim, Windows mock) encode their results into **stdout and exit code**:

- **Linux runner**: passes blob stdout through directly. Exit code is the blob's exit code.
- **FreeBSD shim runner**: the shim validates syscall arguments inline. If validation fails, the shim writes a diagnostic to stderr and calls exit_group with a non-zero code. If all syscalls pass, the blob completes normally and the runner exits 0. Stdout carries the blob's output (which may be a dummy marker).
- **Windows mock runner**: mock API functions pass blob stdout through (WriteFile → Linux write). Exit code is the blob's exit code (ExitProcess → exit_group). The mock validates control flow inline — if the blob resolves wrong hashes or calls APIs in wrong order, the mock can detect some classes of errors (wrong function called) but primarily, correct stdout + exit code 0 implies correct API resolution.

Pytest does **not** parse a separate verification log. The runner is responsible for encoding pass/fail into the standard Unix interface (stdout/stderr/exit code).

**Rationale**: Keeps the Python test layer simple. The C runners are themselves testable artifacts (and are tested via the sync tests). Adding structured verification log parsing adds complexity with diminishing returns — if the blob produces the right output with the right exit code, the control flow was correct.

### D7: Infrastructure Fixtures for Stager Tests

Stager tests that need external infrastructure get dedicated pytest fixtures:

```python
@pytest.fixture
def tcp_listener():
    """Start a TCP listener that serves a length-prefixed test payload.
    Yields (host, port). Tears down on exit."""

@pytest.fixture
def fifo_path(tmp_path):
    """Create a FIFO and spawn a writer thread that sends a
    length-prefixed test payload. Yields the FIFO path."""

@pytest.fixture
def payload_file(tmp_path):
    """Write a test payload to a temp file. Yields the file path."""
```

These fixtures:
- Run the server/writer in a background thread.
- Use ephemeral ports (TCP) or temp paths (FIFO, file) to avoid conflicts.
- Handle cleanup in the fixture teardown.
- Are architecture-aware: the test payload bytes they serve are for the specific target arch being tested.

TCP tests use QEMU's user-mode networking, which shares the host's network stack — `127.0.0.1` works between the host fixture and the QEMU guest.

### D8: File Organization

```
python/tests/
    conftest.py                    # existing + new payload fixtures
    test_payload_hello.py          # hello + hello_windows
    test_payload_alloc_jump.py     # alloc_jump
    test_payload_reflective.py     # reflective_pe
    test_payload_stager.py         # stager_tcp, stager_fd, stager_pipe, stager_mmap
    test_extractor.py              # existing (unchanged)
    test_runner.py                 # existing (unchanged)
    test_sync.py                   # existing (unchanged)
    test_cli.py                    # existing (unchanged)
```

One file per payload **category**, not per payload type. This groups related tests (all stagers share infrastructure patterns) and keeps the file count manageable.

Shared fixtures and the `PayloadExpectation` registry live in `conftest.py`.

### D9: Timeouts and CI

- Default per-test timeout: `30.0s` (same as `run_blob()` default).
- Simple payloads (hello, alloc_jump): `10-15s` timeout override in the expectation.
- Network payloads (stager_tcp): `30s` (socket setup under QEMU is slow).
- CI runs the **full matrix** on every PR. The matrix is ~170 test instances at full buildout (10 payload types x 17 platforms, minus exclusions), each taking 1-10s under QEMU. Total wall time with parallelism (`pytest -x -n auto`): < 5 minutes.
- The existing `PICBLOBS_TEST_OS` / `PICBLOBS_TEST_ARCH` / `PICBLOBS_TEST_TYPE` env filters apply to payload tests identically to all other tests, via the existing `pytest_collection_modifyitems` hook in conftest.py.
- Rosetta detection (`is_arch_skip_rosetta()`) auto-skips MIPS on Apple Silicon Docker Desktop.

### D10: Debug Builds Are Out of Scope

Debug vs. release is an orthogonal axis (ADR-024). This test suite runs against whatever blobs are staged in `_blobs/`. To test debug builds, the developer runs `task stage -- --debug` then `task test`. The pytest suite does not distinguish build modes.

**Rationale**: Debug builds add PIC_LOG output to stderr but don't change functional behavior. Asserting on PIC_LOG presence/absence is a debug tooling concern, not a payload correctness concern.

## Test Procedures

### Fixture: `blob_for_platform`

A parametrized fixture that yields `(blob_type, target_os, target_arch)` tuples for all valid combinations. Generated at collection time from `PAYLOAD_PLATFORMS` x `OPERATING_SYSTEMS[os].architectures`:

```python
def _all_payload_combos() -> list[tuple[str, str, str]]:
    combos = []
    for blob_type, os_list in PAYLOAD_PLATFORMS.items():
        for os_name in os_list:
            for arch in OPERATING_SYSTEMS[os_name].architectures:
                combos.append((blob_type, os_name, arch))
    return sorted(combos)

@pytest.fixture(
    params=_all_payload_combos(),
    ids=[f"{bt}:{os}:{arch}" for bt, os, arch in _all_payload_combos()],
)
def blob_for_platform(request):
    return request.param
```

### Fixture: `test_payload_blob`

For payload types that need an inner blob (alloc_jump, stagers, reflective loaders), this fixture loads the appropriate test payload `.so` for the target architecture:

```python
@pytest.fixture
def test_payload_blob(blob_for_platform):
    blob_type, target_os, target_arch = blob_for_platform
    exp = EXPECTATIONS[blob_type]
    if not exp.needs_config:
        return None
    # Map blob_type to its test payload type
    test_payload_type = TEST_PAYLOAD_MAP[blob_type]  # e.g., "alloc_jump" -> "test_pass"
    # Load from staged blobs (always linux, since test payloads use Linux syscalls)
    return get_blob(test_payload_type, "linux", target_arch)
```

### Fixture: `build_config`

Per-payload config builder. Returns the config bytes for a given payload type, using the test payload blob and any infrastructure addresses:

```python
@pytest.fixture
def build_config(blob_for_platform, test_payload_blob, request):
    blob_type, target_os, target_arch = blob_for_platform
    # Dispatch to per-payload config builder
    builder = CONFIG_BUILDERS[blob_type]
    return builder(test_payload_blob, target_arch, request)
```

Where `CONFIG_BUILDERS` maps blob type to a function:

```python
CONFIG_BUILDERS = {
    "hello": lambda *_: b"",
    "hello_windows": lambda *_: b"",
    "alloc_jump": build_alloc_jump_config,
    "stager_tcp": build_stager_tcp_config,
    # ...
}
```

Each builder packs the config struct using `struct.pack()` per the C header definition (REQ-014).

### Test 11.1: Payload Functional Correctness

The core test — runs every blob on every supported platform and asserts expected output:

```python
@pytest.mark.requires_blobs
@pytest.mark.requires_runners
@pytest.mark.requires_qemu
class TestPayloadExecution:

    def test_payload_produces_expected_output(
        self, blob_for_platform, build_config
    ):
        blob_type, target_os, target_arch = blob_for_platform
        exp = EXPECTATIONS[blob_type]

        blob = get_blob(blob_type, target_os, target_arch)
        result = run_blob(
            blob,
            config=build_config,
            timeout=exp.timeout,
        )

        assert result.exit_code == exp.exit_code, (
            f"exit_code={result.exit_code}, "
            f"stderr={result.stderr!r}"
        )
        if exp.stdout is not None:
            assert result.stdout == exp.stdout
        if exp.stdout_contains is not None:
            assert exp.stdout_contains in result.stdout
```

This single test function, combined with the parametrized `blob_for_platform` fixture, generates one test instance per `(blob_type, os, arch)` combination.

### Test 11.2: Allocation Failure Handling (alloc_jump)

```python
class TestAllocJumpEdgeCases:

    @pytest.mark.requires_blobs
    @pytest.mark.requires_runners
    @pytest.mark.requires_qemu
    def test_absurd_payload_size_exits_cleanly(self, linux_arch):
        blob = get_blob("alloc_jump", "linux", linux_arch)
        # Config with payload_size = 0xFFFFFFFF (4GB), empty payload
        config = struct.pack("<I", 0xFFFFFFFF)
        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0  # clean failure, not crash
```

### Test 11.3: Stager Connection Refused (stager_tcp)

```python
class TestStagerTcpEdgeCases:

    @pytest.mark.requires_blobs
    @pytest.mark.requires_runners
    @pytest.mark.requires_qemu
    def test_connection_refused_exits_cleanly(self, linux_arch):
        blob = get_blob("stager_tcp", "linux", linux_arch)
        # Config pointing to a port with no listener
        config = build_stager_tcp_config_with_addr("127.0.0.1", 1, linux_arch)
        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0
```

### Test 11.4: Stager FD with Piped Input (stager_fd)

```python
class TestStagerFdEdgeCases:

    @pytest.mark.requires_blobs
    @pytest.mark.requires_runners
    @pytest.mark.requires_qemu
    def test_eof_on_stdin_exits_cleanly(self, linux_arch):
        blob = get_blob("stager_fd", "linux", linux_arch)
        config = build_stager_fd_config(fd=0, arch=linux_arch)
        # run_blob with empty stdin (immediate EOF)
        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0
```

### Test 11.5: Blob Size Sanity

```python
class TestBlobSize:

    @pytest.mark.requires_blobs
    def test_hello_under_512_bytes(self, platform_pair):
        os_name, arch = platform_pair
        # hello only on linux/freebsd
        if os_name == "windows":
            pytest.skip("hello is not a windows payload")
        blob = get_blob("hello", os_name, arch)
        assert len(blob.code) < 512

    @pytest.mark.requires_blobs
    def test_alloc_jump_under_512_bytes(self, platform_pair):
        os_name, arch = platform_pair
        try:
            blob = get_blob("alloc_jump", os_name, arch)
        except FileNotFoundError:
            pytest.skip("alloc_jump not built")
        assert len(blob.code) <= 512
```

## Environment Interaction

### Markers

Tests use the existing markers from conftest.py:

| Marker | Meaning | Auto-skip condition |
|---|---|---|
| `requires_blobs` | Test needs staged `.so` files | No `.so` found for the requested combination |
| `requires_runners` | Test needs compiled C runners | `bazel-bin/tests/runners/linux/runner` missing |
| `requires_qemu` | Test needs QEMU user-static | `qemu-x86_64-static` not on PATH |

### Environment Filters

The existing `PICBLOBS_TEST_OS`, `PICBLOBS_TEST_ARCH`, and `PICBLOBS_TEST_TYPE` environment variables filter the payload test matrix. These are set by the `picblobs test --os/--arch/--type` CLI flags.

The conftest `pytest_collection_modifyitems` hook applies these filters to parametrized payload tests by matching against the `target_os`, `target_arch`, and `blob_type` parameter names in the fixture's `callspec`.

### Running

```bash
# All payload tests (full matrix)
picblobs test -k test_payload

# Single payload type
picblobs test --type hello

# Single platform
picblobs test --os linux --arch x86_64

# Single combination
picblobs test --type hello --os linux --arch aarch64

# With verbose output
picblobs test -v -k test_payload
```

## Relationship to Existing Test Documents

| Document | Scope | Relationship |
|---|---|---|
| TEST-004 | Alloc-jump verification procedures | This suite **implements** TEST-004 procedures 4.1-4.6 as pytest |
| TEST-005 | Reflective loader verification | This suite **implements** TEST-005 procedures 5.1-5.10 as pytest |
| TEST-006 | Bootstrap stager verification | This suite **implements** TEST-006 procedures 6.1-6.10 as pytest |
| TEST-001 | Build pipeline integrity | Orthogonal — covers Bazel build correctness |
| TEST-008 | Python API verification | Orthogonal — covers get_blob/list_blobs/extract API |
| `picblobs verify` | Quick smoke test | Subset — verify runs only `hello` on all Linux arches |

This document does NOT supersede TEST-004/005/006. Those define the verification **procedures** at the specification level. This document defines the pytest **implementation** that realizes those procedures.

## Incremental Buildout

The suite is designed for incremental delivery:

1. **Phase 1** (now): `test_payload_hello.py` — hello + hello_windows on all platforms. Tests the full pytest infrastructure with the two existing payloads.
2. **Phase 2**: `test_payload_alloc_jump.py` — when `alloc_jump.c` lands. Adds config building and test payload loading.
3. **Phase 3**: `test_payload_stager.py` — when stager `.c` files land. Adds infrastructure fixtures (TCP, FIFO, file).
4. **Phase 4**: `test_payload_reflective.py` — when reflective loaders land. Adds ELF/PE test binary compilation.

Each phase is independently useful. The parametrized test matrix automatically picks up new blobs as they're built and staged.

## Related Decisions
- ADR-010 (testing infrastructure strategy — QEMU + shim + mock)
- ADR-021 (embedded cross-compiled runners)
- ADR-022 (registry-driven code generation)

## Related Models
- MOD-006 (test architecture)
