"""Tests for picblobs.runner module."""

from __future__ import annotations

import errno
import subprocess
from pathlib import Path

import pytest
from picblobs import runner
from picblobs._extractor import BlobData
from picblobs.runner import (
    QEMU_BINARIES,
    RunResult,
    _text_end,
    build_blob_command,
    build_linux_elf_command,
    can_run,
    exec_command,
    find_qemu,
    find_runner,
    prepare_blob,
    qemu_launcher,
    run_blob,
)


class TestQemuBinaryMap:
    """Test QEMU binary name resolution."""

    def test_all_architectures_mapped(self) -> None:
        # Sync test (test_sync.py) verifies completeness against the registry.
        # Here we just check the map is non-empty and values look like QEMU binaries.
        assert len(QEMU_BINARIES) > 0
        for arch, binary in QEMU_BINARIES.items():
            assert binary.startswith("qemu-"), (
                f"{arch}: {binary} doesn't look like a QEMU binary"
            )
            assert binary.endswith("-static"), (
                f"{arch}: {binary} doesn't end with -static"
            )

    def test_unknown_arch_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown architecture"):
            find_qemu("not-a-real-arch")

    @pytest.mark.requires_qemu
    def test_find_qemu_x86_64(self) -> None:
        path = find_qemu("x86_64")
        assert path.exists()


@pytest.fixture
def _clear_launcher_cache():
    """Reset launcher discovery state around a test."""
    runner._LAUNCHER_CACHE.clear()
    runner._binfmt_handler_enabled.cache_clear()
    yield
    runner._LAUNCHER_CACHE.clear()
    runner._binfmt_handler_enabled.cache_clear()


class TestFindQemuFallback:
    """find_qemu accepts the non-static qemu-user binary name too."""

    def test_prefers_static_then_bare_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # qemu-aarch64-static absent, qemu-aarch64 present.
        seen: list[str] = []

        def fake_which(name: str) -> str | None:
            seen.append(name)
            return "/usr/bin/qemu-aarch64" if name == "qemu-aarch64" else None

        monkeypatch.setattr("picblobs.runner.shutil.which", fake_which)
        path = find_qemu("aarch64")
        assert path == Path("/usr/bin/qemu-aarch64")
        assert seen == ["qemu-aarch64-static", "qemu-aarch64"]

    def test_missing_everywhere_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("picblobs.runner.shutil.which", lambda _name: None)
        with pytest.raises(FileNotFoundError, match="No qemu-user interpreter"):
            find_qemu("aarch64")


class TestQemuLauncher:
    """qemu_launcher chooses direct exec vs an explicit qemu interpreter."""

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_native_runs_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: True)
        assert qemu_launcher("x86_64") == []

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_binfmt_runs_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: False)
        monkeypatch.setattr("picblobs.runner._binfmt_handler_enabled", lambda _a: True)
        assert qemu_launcher("aarch64") == []

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_falls_back_to_qemu_interpreter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: False)
        monkeypatch.setattr("picblobs.runner._binfmt_handler_enabled", lambda _a: False)
        monkeypatch.setattr(
            "picblobs.runner.find_qemu", lambda _a: Path("/usr/bin/qemu-s390x")
        )
        assert qemu_launcher("s390x") == ["/usr/bin/qemu-s390x"]

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_no_handler_returns_empty_for_direct_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Nothing can run it yet: caller still attempts a direct exec, and the
        # exec-format fallback handles the failure.
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: False)
        monkeypatch.setattr("picblobs.runner._binfmt_handler_enabled", lambda _a: False)

        def _no_qemu(_a):
            raise FileNotFoundError("nope")

        monkeypatch.setattr("picblobs.runner.find_qemu", _no_qemu)
        assert qemu_launcher("s390x") == []

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_build_linux_elf_command_prepends_launcher(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: False)
        monkeypatch.setattr("picblobs.runner._binfmt_handler_enabled", lambda _a: False)
        monkeypatch.setattr(
            "picblobs.runner.find_qemu", lambda _a: Path("/usr/bin/qemu-arm")
        )
        cmd = build_linux_elf_command(Path("/tmp/blob.elf"), "armv5_arm")
        assert cmd == ["/usr/bin/qemu-arm", "/tmp/blob.elf"]


class TestCanRun:
    """can_run reports whether a blob arch is executable on this host."""

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_true_when_binfmt_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: False)
        monkeypatch.setattr("picblobs.runner._binfmt_handler_enabled", lambda _a: True)
        assert can_run("aarch64") is True

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_false_when_nothing_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _a: False)
        monkeypatch.setattr("picblobs.runner._binfmt_handler_enabled", lambda _a: False)

        def _no_qemu(_a):
            raise FileNotFoundError("nope")

        monkeypatch.setattr("picblobs.runner.find_qemu", _no_qemu)
        assert can_run("aarch64") is False


class _FakeRun:
    """Stateful subprocess.run replacement: raise once, then succeed."""

    def __init__(self, errno_value: int | None) -> None:
        self.errno_value = errno_value
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **_kwargs):
        self.calls.append(list(cmd))
        if len(self.calls) == 1 and self.errno_value is not None:
            raise OSError(self.errno_value, "boom")
        return subprocess.CompletedProcess(cmd, 0, stdout=b"PASS", stderr=b"")


class TestExecCommandFallback:
    """exec_command retries under qemu when a direct exec can't run."""

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_direct_success_no_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeRun(errno_value=None)
        monkeypatch.setattr("picblobs.runner.subprocess.run", fake)
        proc, cmd = exec_command(["./blob.elf"], "aarch64")
        assert proc.stdout == b"PASS"
        assert cmd == ["./blob.elf"]
        assert len(fake.calls) == 1

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_enoexec_retries_under_qemu(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("picblobs.runner.qemu_launcher", lambda _a: [])
        monkeypatch.setattr(
            "picblobs.runner.find_qemu", lambda _a: Path("/usr/bin/qemu-aarch64")
        )
        fake = _FakeRun(errno_value=errno.ENOEXEC)
        monkeypatch.setattr("picblobs.runner.subprocess.run", fake)
        proc, cmd = exec_command(["./blob.elf"], "aarch64")
        assert proc.stdout == b"PASS"
        assert cmd == ["/usr/bin/qemu-aarch64", "./blob.elf"]
        assert fake.calls == [["./blob.elf"], ["/usr/bin/qemu-aarch64", "./blob.elf"]]

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_enoexec_without_qemu_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("picblobs.runner.qemu_launcher", lambda _a: [])

        def _no_qemu(_a):
            raise FileNotFoundError("nope")

        monkeypatch.setattr("picblobs.runner.find_qemu", _no_qemu)
        monkeypatch.setattr(
            "picblobs.runner.subprocess.run", _FakeRun(errno_value=errno.ENOEXEC)
        )
        with pytest.raises(FileNotFoundError, match="Cannot execute aarch64 binary"):
            exec_command(["./blob.elf"], "aarch64")

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_other_oserror_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("picblobs.runner.qemu_launcher", lambda _a: [])
        monkeypatch.setattr(
            "picblobs.runner.subprocess.run", _FakeRun(errno_value=errno.EACCES)
        )
        with pytest.raises(OSError) as exc_info:
            exec_command(["./blob.elf"], "aarch64")
        assert exc_info.value.errno == errno.EACCES

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_no_retry_when_already_under_qemu(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # qemu_launcher reports a qemu prefix -> we were already using it, so
        # an ENOEXEC must not loop back into another qemu attempt.
        monkeypatch.setattr(
            "picblobs.runner.qemu_launcher", lambda _a: ["/usr/bin/qemu-aarch64"]
        )
        monkeypatch.setattr(
            "picblobs.runner.subprocess.run", _FakeRun(errno_value=errno.ENOEXEC)
        )
        with pytest.raises(OSError) as exc_info:
            exec_command(["/usr/bin/qemu-aarch64", "./blob.elf"], "aarch64")
        assert exc_info.value.errno == errno.ENOEXEC


class _RecordingRun:
    """subprocess.run replacement that records the kwargs of each call."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout=None, stderr=None)


class TestExecCommandInteractive:
    """Interactive mode inherits the terminal instead of capturing output."""

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_interactive_inherits_stdio(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _RecordingRun()
        monkeypatch.setattr("picblobs.runner.subprocess.run", fake)
        proc, _ = exec_command(["./blob.elf"], "x86_64", interactive=True)
        assert proc.returncode == 0
        kwargs = fake.calls[0]
        # No capture, no fed stdin, no timeout — the child owns the tty.
        assert "capture_output" not in kwargs
        assert "input" not in kwargs
        assert kwargs.get("timeout") is None

    @pytest.mark.usefixtures("_clear_launcher_cache")
    def test_non_interactive_captures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _RecordingRun()
        monkeypatch.setattr("picblobs.runner.subprocess.run", fake)
        exec_command(["./blob.elf"], "x86_64", stdin_data=b"hi", timeout=5.0)
        kwargs = fake.calls[0]
        assert kwargs["capture_output"] is True
        assert kwargs["input"] == b"hi"
        assert kwargs["timeout"] == 5.0


class TestFindRunner:
    """Test runner binary discovery."""

    def test_missing_runner_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            find_runner("linux", search_paths=[Path("/nonexistent")])

    @pytest.mark.requires_runners
    def test_find_windows_runner(self) -> None:
        runner = find_runner("windows", "x86_64")
        assert runner.exists()
        assert runner.is_file()


class TestPrepareBlob:
    """Test blob preparation (writing code + config to temp file)."""

    def _make_blob(self, code: bytes = b"\xcc") -> BlobData:
        return BlobData(
            code=code,
            config_offset=len(code),
            entry_offset=0,
            blob_type="test",
            target_os="linux",
            target_arch="x86_64",
            sha256="",
            sections={},
        )

    def test_writes_code(self, tmp_path: Path) -> None:
        blob = self._make_blob(b"\x90\x90\x90")
        path = prepare_blob(blob, output_dir=tmp_path)
        assert path.exists()
        assert path.read_bytes() == b"\x90\x90\x90"

    def test_writes_code_with_config(self, tmp_path: Path) -> None:
        blob = self._make_blob(b"\x90\x90")
        config = b"\xde\xad"
        path = prepare_blob(blob, config=config, output_dir=tmp_path)
        data = path.read_bytes()
        assert data[:2] == b"\x90\x90"
        assert data[2:4] == b"\xde\xad"

    def test_pads_to_config_offset(self, tmp_path: Path) -> None:
        blob = BlobData(
            code=b"\x90",
            config_offset=8,
            entry_offset=0,
            blob_type="test",
            target_os="linux",
            target_arch="x86_64",
            sha256="",
            sections={},
        )
        config = b"\xff\xff"
        path = prepare_blob(blob, config=config, output_dir=tmp_path)
        data = path.read_bytes()
        assert len(data) >= 10
        assert data[8:10] == b"\xff\xff"


class TestTextEnd:
    """_text_end bounds the FreeBSD syscall patcher to the code region."""

    def _blob_with_sections(self, sections: dict[str, tuple[int, int]]) -> BlobData:
        return BlobData(
            code=b"\x00" * 256,
            config_offset=256,
            entry_offset=0,
            blob_type="test",
            target_os="freebsd",
            target_arch="x86_64",
            sha256="",
            sections=sections,
        )

    def test_single_text_section(self) -> None:
        blob = self._blob_with_sections({".text": (0, 0x40), ".rodata": (0x40, 0x10)})
        assert _text_end(blob) == 0x40

    def test_multiple_text_sections_takes_max(self) -> None:
        blob = self._blob_with_sections(
            {".text.pic_entry": (0, 0x30), ".text.helper": (0x40, 0x20)}
        )
        assert _text_end(blob) == 0x60

    def test_no_text_section_returns_zero(self) -> None:
        blob = self._blob_with_sections({".rodata": (0, 0x10)})
        assert _text_end(blob) == 0


class TestRunResult:
    """Test RunResult dataclass."""

    def test_fields(self) -> None:
        r = RunResult(
            stdout=b"PASS",
            stderr=b"",
            exit_code=0,
            duration_s=0.1,
            command=["./runner", "blob.bin"],
        )
        assert r.stdout == b"PASS"
        assert r.exit_code == 0
        assert r.duration_s == pytest.approx(0.1)


class TestRunBlobDryRun:
    def test_dry_run_does_not_prepare_temp_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        blob = BlobData(
            code=b"\x90",
            config_offset=1,
            entry_offset=0,
            blob_type="test",
            target_os="linux",
            target_arch="x86_64",
            sha256="",
            sections={},
        )

        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda arch: True)

        def _boom(*args, **kwargs):
            raise AssertionError("prepare_linux_elf should not be called in dry_run")

        monkeypatch.setattr("picblobs.runner.prepare_linux_elf", _boom)

        result = run_blob(blob, dry_run=True)
        assert result.exit_code == 0
        assert result.command == ["test_linux_x86_64.elf"]
        assert result.blob_file == "test_linux_x86_64.elf"


class TestBuildBlobCommand:
    def test_freebsd_includes_text_end(self, monkeypatch: pytest.MonkeyPatch) -> None:
        blob = BlobData(
            code=b"\x00" * 64,
            config_offset=64,
            entry_offset=0,
            blob_type="test",
            target_os="freebsd",
            target_arch="x86_64",
            sha256="",
            sections={".text": (0, 0x20), ".rodata": (0x20, 0x10)},
        )

        monkeypatch.setattr(
            "picblobs.runner._build_command",
            lambda runner_path, blob_file, arch, extra=None: [
                str(runner_path),
                str(blob_file),
                *(extra or []),
            ],
        )

        cmd = build_blob_command(blob, Path("/runner"), Path("/blob.bin"))
        assert cmd == ["/runner", "/blob.bin", "0x20"]

    def test_linux_has_no_freebsd_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        blob = BlobData(
            code=b"\x00" * 64,
            config_offset=64,
            entry_offset=0,
            blob_type="test",
            target_os="linux",
            target_arch="x86_64",
            sha256="",
            sections={".text": (0, 0x20)},
        )

        monkeypatch.setattr(
            "picblobs.runner._build_command",
            lambda runner_path, blob_file, arch, extra=None: [
                str(runner_path),
                str(blob_file),
                *(extra or []),
            ],
        )

        cmd = build_blob_command(blob, Path("/runner"), Path("/blob.bin"))
        assert cmd == ["/runner", "/blob.bin"]
