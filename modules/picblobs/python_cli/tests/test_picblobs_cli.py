"""TEST-012: picblobs-cli verification.

Exercises every sub-command in ``picblobs_cli.cli`` plus the
``find_runner`` discovery contract (picblobs-cli bundle preferred over
the Bazel build tree).
"""

from __future__ import annotations

import stat
import struct
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace

import picblobs
import picblobs_cli
import pytest
from click.testing import CliRunner
from picblobs_cli.cli import main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def qemu_available() -> bool:
    """True if this host can execute a *cross* (non-native) architecture.

    The CLI runtime tests below dispatch to another arch (e.g. aarch64), so
    they gate on cross-arch execution support -- a binfmt_misc qemu-user
    handler or a qemu-user interpreter on PATH -- not on host-native
    execution. Host-native always works, so gating on it would turn a
    missing-capability skip into a runtime failure for the cross-arch cases.
    """
    import platform

    from picblobs.runner import can_run

    cross_arch = "aarch64" if platform.machine() != "aarch64" else "x86_64"
    return can_run(cross_arch)


def _require_qemu(flag: bool) -> None:
    if not flag:
        pytest.skip("cross-architecture execution is unavailable on this host")


# ---------------------------------------------------------------------------
# 12.1 Package imports
# ---------------------------------------------------------------------------


class TestPackageImports:
    def test_picblobs_cli_importable(self) -> None:
        assert picblobs_cli.__version__

    def test_version_matches_cli_distribution(self) -> None:
        assert picblobs_cli.__version__ == metadata.version("picblobs-cli")

    def test_main_is_click_command(self) -> None:
        import click

        assert isinstance(main, click.Command)

    def test_runners_dir_resolves(self) -> None:
        p = picblobs_cli.runners_dir()
        assert p.exists(), p
        assert not (p / "linux").exists()
        assert (p / "freebsd" / "x86_64" / "runner").exists()
        assert (p / "windows" / "x86_64" / "runner").exists()

    def test_ul_exec_test_binary_resolves(self) -> None:
        p = picblobs_cli.test_binaries_dir()
        assert p.exists(), p
        data = picblobs_cli.ul_exec_test_binary("linux", "x86_64")
        assert data is not None
        assert data.startswith(b"\x7fELF")

    def test_ul_exec_test_binary_rejects_path_segments(self) -> None:
        assert picblobs_cli.ul_exec_test_binary("linux", "../x86_64") is None


# ---------------------------------------------------------------------------
# 12.2 Console script entry point
# ---------------------------------------------------------------------------


class TestConsoleScript:
    def test_help_exits_zero(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["--help"])
        assert r.exit_code == 0

    def test_help_lists_commands(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["--help"])
        for cmd in (
            "run",
            "verify",
            "build",
            "list",
            "info",
            "extract",
            "listing",
            "disasm",
            "test",
            "list-runners",
        ):
            assert cmd in r.output, cmd

    def test_version_flag(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["--version"])
        assert r.exit_code == 0
        assert picblobs_cli.__version__ in r.output

    def test_python_dash_m_entry(self) -> None:
        """``python -m picblobs_cli --help`` works as a console entry."""
        r = subprocess.run(
            [sys.executable, "-m", "picblobs_cli", "--help"],
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0
        assert "picblobs-cli" in r.stdout


# ---------------------------------------------------------------------------
# 12.3 list-runners
# ---------------------------------------------------------------------------


class TestListRunners:
    def test_lists_all_runners(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["list-runners"])
        assert r.exit_code == 0
        for kind in ("freebsd", "windows"):
            assert kind in r.output
        rows = [
            line
            for line in r.output.splitlines()
            if line and not line.startswith(("RUNNER", "-"))
        ]
        assert not any(line.startswith("linux") for line in rows)

    def test_linux_filter_reports_no_packaged_runners(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["list-runners", "--os", "linux"])
        assert r.exit_code != 0
        assert "no runners found" in r.output

    def test_arch_filter(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["list-runners", "--arch", "x86_64"])
        assert r.exit_code == 0

    def test_bogus_filter_fails_clean(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["list-runners", "--os", "nonesuch"])
        assert r.exit_code != 0


# ---------------------------------------------------------------------------
# 12.4 / 12.5 Build command — parity with builder API
# ---------------------------------------------------------------------------


class TestBuildCommand:
    def test_alloc_jump_parity(self, runner: CliRunner, tmp_path: Path) -> None:
        payload = b"CAFEBABE" * 4
        payload_file = tmp_path / "payload.bin"
        payload_file.write_bytes(payload)
        out_file = tmp_path / "out.bin"

        r = runner.invoke(
            main,
            [
                "build",
                "alloc_jump",
                "linux:x86_64",
                "--payload",
                str(payload_file),
                "-o",
                str(out_file),
            ],
        )
        assert r.exit_code == 0, r.output

        expected = (
            picblobs.Blob("linux", "x86_64").alloc_jump().payload(payload).build()
        )
        assert out_file.read_bytes() == expected

    def test_stager_tcp_parity(self, runner: CliRunner, tmp_path: Path) -> None:
        out_file = tmp_path / "stg.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "stager_tcp",
                "linux:aarch64",
                "--address",
                "10.0.0.1",
                "--port",
                "4444",
                "-o",
                str(out_file),
            ],
        )
        assert r.exit_code == 0, r.output

        expected = (
            picblobs.Blob("linux", "aarch64")
            .stager_tcp()
            .address("10.0.0.1")
            .port(4444)
            .build()
        )
        assert out_file.read_bytes() == expected

    def test_stager_fd(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "fd.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "stager_fd",
                "linux:x86_64",
                "--fd",
                "3",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0
        expected = picblobs.Blob("linux", "x86_64").stager_fd().fd(3).build()
        assert out.read_bytes() == expected

    def test_stager_pipe(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "pipe.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "stager_pipe",
                "linux:x86_64",
                "--path",
                "/tmp/my.fifo",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0
        expected = (
            picblobs.Blob("linux", "x86_64").stager_pipe().path("/tmp/my.fifo").build()
        )
        assert out.read_bytes() == expected

    def test_stager_mmap(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "mmap.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "stager_mmap",
                "linux:x86_64",
                "--path",
                "/tmp/x",
                "--size",
                "64",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0
        expected = (
            picblobs.Blob("linux", "x86_64")
            .stager_mmap()
            .path("/tmp/x")
            .size(64)
            .build()
        )
        assert out.read_bytes() == expected

    def test_reflective_pe(self, runner: CliRunner, tmp_path: Path) -> None:
        pe_file = tmp_path / "dummy.pe"
        dummy = b"MZ" + b"\x00" * 126
        pe_file.write_bytes(dummy)
        out = tmp_path / "refl.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "reflective_pe",
                "windows:x86_64",
                "--pe",
                str(pe_file),
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0
        expected = picblobs.Blob("windows", "x86_64").reflective_pe().pe(dummy).build()
        assert out.read_bytes() == expected

    def test_hello_windows(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "hello_windows.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "hello_windows",
                "windows:x86_64",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0, r.output
        expected = picblobs.Blob("windows", "x86_64").hello_windows().build()
        assert out.read_bytes() == expected

    def test_elf_format_wraps_linux_output(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        out = tmp_path / "hello"
        r = runner.invoke(
            main,
            [
                "build",
                "hello",
                "linux:x86_64",
                "--format",
                "elf",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0, r.output
        expected = picblobs.wrap_elf(
            picblobs.Blob("linux", "x86_64").hello().build(),
            "linux",
            "x86_64",
        )
        assert out.read_bytes() == expected
        assert out.stat().st_mode & stat.S_IXUSR

    def test_elf_format_rejects_windows(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        out = tmp_path / "hello.exe"
        r = runner.invoke(
            main,
            [
                "build",
                "hello_windows",
                "windows:x86_64",
                "--format",
                "elf",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code != 0
        assert "linux" in r.output.lower()

    def test_wrap_elf_flag_wraps_linux_output(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        out = tmp_path / "hello"
        r = runner.invoke(
            main,
            [
                "build",
                "hello",
                "linux:x86_64",
                "--wrap-elf",
                "-o",
                str(out),
            ],
        )
        assert r.exit_code == 0, r.output
        expected = picblobs.wrap_elf(
            picblobs.Blob("linux", "x86_64").hello().build(),
            "linux",
            "x86_64",
        )
        assert out.read_bytes() == expected
        assert out.stat().st_mode & stat.S_IXUSR

    # --- Negative / validation ---

    def test_hello_rejects_unrelated_option(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        r = runner.invoke(
            main,
            [
                "build",
                "hello",
                "linux:x86_64",
                "--address",
                "1.2.3.4",
                "-o",
                str(tmp_path / "x.bin"),
            ],
        )
        assert r.exit_code != 0
        assert "not valid for this blob type" in r.output

    def test_missing_required_payload(self, runner: CliRunner, tmp_path: Path) -> None:
        r = runner.invoke(
            main,
            [
                "build",
                "alloc_jump",
                "linux:x86_64",
                "-o",
                str(tmp_path / "x.bin"),
            ],
        )
        assert r.exit_code != 0
        assert "requires --payload" in r.output

    def test_missing_port(self, runner: CliRunner, tmp_path: Path) -> None:
        r = runner.invoke(
            main,
            [
                "build",
                "stager_tcp",
                "linux:x86_64",
                "--address",
                "1.2.3.4",
                "-o",
                str(tmp_path / "x.bin"),
            ],
        )
        assert r.exit_code != 0

    def test_unsupported_os(self, runner: CliRunner, tmp_path: Path) -> None:
        r = runner.invoke(
            main,
            [
                "build",
                "hello",
                "macos:x86_64",
                "-o",
                str(tmp_path / "x.bin"),
            ],
        )
        assert r.exit_code != 0

    def test_invalid_target_format(self, runner: CliRunner, tmp_path: Path) -> None:
        r = runner.invoke(
            main,
            [
                "build",
                "hello",
                "linux_x86_64",  # missing colon
                "-o",
                str(tmp_path / "x.bin"),
            ],
        )
        assert r.exit_code != 0

    def test_reflective_pe_not_on_linux(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        pe_file = tmp_path / "x.pe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 126)
        r = runner.invoke(
            main,
            [
                "build",
                "reflective_pe",
                "linux:x86_64",
                "--pe",
                str(pe_file),
                "-o",
                str(tmp_path / "out.bin"),
            ],
        )
        assert r.exit_code != 0


# ---------------------------------------------------------------------------
# 12.7 Run command
# ---------------------------------------------------------------------------


class TestRunCommand:
    def test_hello_native(self, runner: CliRunner, qemu_available: bool) -> None:
        _require_qemu(qemu_available)
        r = runner.invoke(main, ["run", "hello", "linux:x86_64"])
        assert r.exit_code == 0
        assert "Hello, world!" in r.output

    def test_hello_cross_arch(self, runner: CliRunner, qemu_available: bool) -> None:
        _require_qemu(qemu_available)
        r = runner.invoke(main, ["run", "hello", "linux:aarch64"])
        assert r.exit_code == 0
        assert "Hello, world!" in r.output

    def test_nonexistent_blob(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["run", "nonexistent", "linux:x86_64"])
        assert r.exit_code != 0
        assert "No blob" in r.output

    def test_invalid_target(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["run", "hello", "bogus_target"])
        assert r.exit_code != 0

    def test_interactive_rejects_stdin(self, runner: CliRunner, tmp_path: Path) -> None:
        stdin_file = tmp_path / "in.bin"
        stdin_file.write_bytes(b"x")
        r = runner.invoke(
            main,
            ["run", "hello", "linux:x86_64", "-i", "--stdin", str(stdin_file)],
        )
        assert r.exit_code != 0
        assert "mutually exclusive" in r.output

    def test_interactive_rejects_dry_run(self, runner: CliRunner) -> None:
        r = runner.invoke(
            main, ["run", "hello", "linux:x86_64", "--interactive", "--dry-run"]
        )
        assert r.exit_code != 0
        assert "mutually exclusive" in r.output

    def test_interactive_runs_native(
        self, runner: CliRunner, qemu_available: bool
    ) -> None:
        """Interactive mode runs the blob and exits with its code."""
        _require_qemu(qemu_available)
        r = runner.invoke(main, ["run", "hello", "linux:x86_64", "-i"])
        assert r.exit_code == 0

    def test_stdin_piping(
        self,
        runner: CliRunner,
        qemu_available: bool,
        tmp_path: Path,
    ) -> None:
        """stager_fd reads a length-prefixed payload from stdin."""
        _require_qemu(qemu_available)
        inner = picblobs.get_blob("test_fd_ok", "linux", "x86_64").code

        stdin_file = tmp_path / "stdin.bin"
        stdin_file.write_bytes(struct.pack("<I", len(inner)) + inner)

        config_file = tmp_path / "cfg.bin"
        config_file.write_bytes(struct.pack("<I", 0))

        r = runner.invoke(
            main,
            [
                "run",
                "stager_fd",
                "linux:x86_64",
                "--payload",
                str(config_file),
                "--stdin",
                str(stdin_file),
            ],
        )
        assert r.exit_code == 0, r.output
        assert "FD_OK" in r.output


# ---------------------------------------------------------------------------
# 12.7a Run command — --file (from-disk) mode
# ---------------------------------------------------------------------------


class TestRunFromFile:
    """run --file: execute an already-assembled blob straight from disk."""

    def _build_alloc_jump(
        self, runner: CliRunner, tmp_path: Path, arch: str = "x86_64"
    ) -> Path:
        """Helper: build alloc_jump+test_pass and return the output path."""
        inner_code = picblobs.get_blob("test_pass", "linux", arch).code
        payload_file = tmp_path / f"inner_{arch}.bin"
        payload_file.write_bytes(inner_code)
        out_file = tmp_path / f"aj_{arch}.bin"
        r = runner.invoke(
            main,
            [
                "build",
                "alloc_jump",
                f"linux:{arch}",
                "--payload",
                str(payload_file),
                "-o",
                str(out_file),
            ],
        )
        assert r.exit_code == 0, r.output
        return out_file

    def test_run_file_native(
        self,
        runner: CliRunner,
        qemu_available: bool,
        tmp_path: Path,
    ) -> None:
        _require_qemu(qemu_available)
        blob = self._build_alloc_jump(runner, tmp_path, "x86_64")
        r = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(blob),
                "linux:x86_64",
            ],
        )
        assert r.exit_code == 0, r.output
        assert "PASS" in r.output

    def test_run_file_cross_arch(
        self,
        runner: CliRunner,
        qemu_available: bool,
        tmp_path: Path,
    ) -> None:
        """Cross-arch dispatch via QEMU works for files from disk."""
        _require_qemu(qemu_available)
        blob = self._build_alloc_jump(runner, tmp_path, "aarch64")
        r = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(blob),
                "linux:aarch64",
            ],
        )
        assert r.exit_code == 0, r.output
        assert "PASS" in r.output

    def test_run_file_parity_with_registry(
        self,
        runner: CliRunner,
        qemu_available: bool,
        tmp_path: Path,
    ) -> None:
        """A blob assembled via `build` and run via `--file` produces the
        same stdout / exit code as the registry-mode path with the
        equivalent config."""
        _require_qemu(qemu_available)

        blob_file = self._build_alloc_jump(runner, tmp_path, "x86_64")
        r_file = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(blob_file),
                "linux:x86_64",
            ],
        )

        inner = picblobs.get_blob("test_pass", "linux", "x86_64").code
        cfg_file = tmp_path / "aj_cfg.bin"
        cfg_file.write_bytes(struct.pack("<I", len(inner)) + inner)
        r_registry = runner.invoke(
            main,
            [
                "run",
                "alloc_jump",
                "linux:x86_64",
                "--payload",
                str(cfg_file),
            ],
        )

        assert r_file.exit_code == r_registry.exit_code == 0
        assert r_file.stdout == r_registry.stdout

    def test_file_and_blob_type_mutually_exclusive(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        fake = tmp_path / "empty.bin"
        fake.write_bytes(b"\x00" * 16)
        r = runner.invoke(
            main,
            [
                "run",
                "hello",
                "linux:x86_64",
                "--file",
                str(fake),
            ],
        )
        assert r.exit_code != 0
        assert "--file" in r.output

    def test_config_hex_rejected_in_file_mode(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        fake = tmp_path / "empty.bin"
        fake.write_bytes(b"\x00" * 16)
        r = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(fake),
                "linux:x86_64",
                "--config-hex",
                "00",
            ],
        )
        assert r.exit_code != 0

    def test_payload_rejected_in_file_mode(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        fake = tmp_path / "empty.bin"
        fake.write_bytes(b"\x00" * 16)
        stray = tmp_path / "stray.bin"
        stray.write_bytes(b"X")
        r = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(fake),
                "linux:x86_64",
                "--payload",
                str(stray),
            ],
        )
        assert r.exit_code != 0

    def test_missing_file(self, runner: CliRunner, tmp_path: Path) -> None:
        r = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(tmp_path / "does_not_exist.bin"),
                "linux:x86_64",
            ],
        )
        assert r.exit_code != 0

    def test_file_mode_needs_target(self, runner: CliRunner, tmp_path: Path) -> None:
        fake = tmp_path / "empty.bin"
        fake.write_bytes(b"\x00" * 16)
        r = runner.invoke(main, ["run", "--file", str(fake)])
        assert r.exit_code != 0

    def test_registry_mode_needs_two_positionals(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["run", "hello"])
        assert r.exit_code != 0

    def test_file_mode_stdin_piping(
        self,
        runner: CliRunner,
        qemu_available: bool,
        tmp_path: Path,
    ) -> None:
        """--stdin still works in file mode: build a stager_fd, feed it
        a length-prefixed inner payload on stdin."""
        _require_qemu(qemu_available)
        inner = picblobs.get_blob("test_fd_ok", "linux", "x86_64").code

        stage = tmp_path / "stage.bin"
        rb = runner.invoke(
            main,
            [
                "build",
                "stager_fd",
                "linux:x86_64",
                "--fd",
                "0",
                "-o",
                str(stage),
            ],
        )
        assert rb.exit_code == 0, rb.output

        stdin_file = tmp_path / "stdin.bin"
        stdin_file.write_bytes(struct.pack("<I", len(inner)) + inner)

        r = runner.invoke(
            main,
            [
                "run",
                "--file",
                str(stage),
                "linux:x86_64",
                "--stdin",
                str(stdin_file),
            ],
        )
        assert r.exit_code == 0, r.output
        assert "FD_OK" in r.output


# ---------------------------------------------------------------------------
# 12.8 Verify command
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    @pytest.mark.timeout(60)
    def test_hello_only(self, runner: CliRunner, qemu_available: bool) -> None:
        _require_qemu(qemu_available)
        r = runner.invoke(main, ["verify", "--type", "hello", "--os", "linux"])
        assert r.exit_code == 0
        assert "passed" in r.output

    @pytest.mark.timeout(60)
    def test_type_and_os_filter(self, runner: CliRunner, qemu_available: bool) -> None:
        _require_qemu(qemu_available)
        r = runner.invoke(main, ["verify", "--type", "hello", "--os", "linux"])
        assert r.exit_code == 0
        # No freebsd output when --os filter is applied.
        assert "[freebsd]" not in r.output

    def test_verify_filters_freebsd_to_x86_64(self) -> None:
        from picblobs_cli.cli import _filter_verify_combos

        combos = [
            ("hello", "freebsd", "aarch64"),
            ("hello", "freebsd", "x86_64"),
            ("ul_exec", "freebsd", "x86_64"),
            ("hello", "linux", "x86_64"),
        ]
        assert _filter_verify_combos(combos, (), (), ()) == [
            ("hello", "freebsd", "x86_64"),
            ("hello", "linux", "x86_64"),
        ]

    def test_windows_stager_fd_uses_hello_windows_inner_blob(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from picblobs_cli import cli

        calls: list[tuple[str, str, str]] = []

        def _get_blob(blob_type: str, os_name: str, arch: str):
            calls.append((blob_type, os_name, arch))
            return SimpleNamespace(code=b"HELLO", blob_type=blob_type)

        monkeypatch.setattr(cli.picblobs, "get_blob", _get_blob)
        monkeypatch.setattr(
            cli,
            "run_blob",
            lambda *args, **kwargs: SimpleNamespace(
                stdout=b"Hello, world!", stderr=b"", exit_code=0
            ),
        )

        result = cli._verify_stager_fd("windows", "x86_64", 30.0)
        assert result.exit_code == 0
        assert calls == [
            ("hello_windows", "windows", "x86_64"),
            ("stager_fd", "windows", "x86_64"),
        ]

    def test_no_matches(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["verify", "--type", "nothing_matches"])
        assert r.exit_code != 0

    def test_skips_freebsd_when_ptrace_unavailable(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from picblobs_cli import cli

        monkeypatch.setattr(
            cli.picblobs,
            "list_blobs",
            lambda: [("hello", "freebsd", "x86_64")],
        )
        monkeypatch.setattr(cli, "_can_ptrace_traceme", lambda: False)

        def _unexpected_verify(*_args, **_kwargs):
            raise AssertionError("unexpected")

        monkeypatch.setattr(
            cli,
            "_verify_one",
            _unexpected_verify,
        )

        r = runner.invoke(main, ["verify", "--os", "freebsd"])
        assert r.exit_code == 0, r.output
        assert "SKIP (FreeBSD verify requires ptrace" in r.output

    def test_skips_stager_tcp_when_loopback_runtime_unavailable(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from picblobs_cli import cli

        monkeypatch.setattr(
            cli.picblobs,
            "list_blobs",
            lambda: [("stager_tcp", "linux", "x86_64")],
        )
        monkeypatch.setattr(cli, "_can_bind_localhost", lambda: True)
        monkeypatch.setattr(
            cli,
            "_verify_one",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PermissionError(1, "Operation not permitted")
            ),
        )

        r = runner.invoke(main, ["verify", "--type", "stager_tcp"])
        assert r.exit_code == 0, r.output
        assert "SKIP (Local TCP runtime is unavailable)" in r.output

    def test_skips_nacl_e2e_when_loopback_runtime_unavailable(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from picblobs_cli import cli

        monkeypatch.setattr(
            cli.picblobs,
            "list_blobs",
            lambda: [
                ("nacl_client", "linux", "x86_64"),
                ("nacl_server", "linux", "x86_64"),
            ],
        )
        monkeypatch.setattr(cli, "_can_bind_localhost", lambda: True)
        monkeypatch.setattr(
            cli,
            "_verify_nacl_e2e",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PermissionError(1, "Operation not permitted")
            ),
        )

        r = runner.invoke(main, ["verify"])
        assert r.exit_code == 0, r.output
        assert "SKIP (Local TCP runtime is unavailable)" in r.output

    def test_ul_exec_uses_staged_test_binary(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from picblobs_cli import cli

        captured: dict[str, object] = {}

        monkeypatch.setattr(
            cli,
            "ul_exec_test_binary",
            lambda os_name, arch: b"\x7fELF" + b"\x00" * 12,
        )
        monkeypatch.setattr(
            cli.picblobs,
            "get_blob",
            lambda blob_type, os_name, arch: SimpleNamespace(code=b"BLOB"),
        )

        def _run_blob(blob, **kwargs):
            captured["blob"] = blob
            captured["kwargs"] = kwargs
            return SimpleNamespace(stdout=b"Hello, ul_exec!\n", stderr=b"", exit_code=0)

        monkeypatch.setattr(cli, "run_blob", _run_blob)

        result = cli._verify_ul_exec("linux", "x86_64", 30.0)

        assert result.exit_code == 0
        kwargs = captured["kwargs"]
        assert kwargs["runner_type"] == "linux"
        assert kwargs["timeout"] == 30.0
        assert b"\x7fELF" in kwargs["config"]

    def test_ul_exec_skips_when_test_binary_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from picblobs_cli import cli

        monkeypatch.setattr(cli, "ul_exec_test_binary", lambda os_name, arch: None)

        with pytest.raises(cli._Skip, match="no staged ul_exec test binary"):
            cli._verify_ul_exec("linux", "x86_64", 30.0)


# ---------------------------------------------------------------------------
# 12.9 Runner discovery contract
# ---------------------------------------------------------------------------


class TestRunnerDiscovery:
    def test_prefers_picblobs_cli_bundle(self) -> None:
        from picblobs.runner import find_runner

        p = find_runner("windows", "x86_64")
        # Path points inside picblobs_cli/_runners.
        assert "/picblobs_cli/_runners/" in str(p), p

    def test_error_mentions_picblobs_cli(self, tmp_path: Path) -> None:
        """With every discovery path neutered, the error SHALL name the package."""
        from picblobs.runner import find_runner

        # Use a runner_type that doesn't exist in the bundle and an empty
        # search_paths to bypass both sources.
        with pytest.raises(FileNotFoundError) as exc:
            find_runner(
                "not_a_real_os",
                "not_an_arch",
                search_paths=[tmp_path],
            )
        assert "picblobs-cli" in str(exc.value)


# ---------------------------------------------------------------------------
# 12.10 Wheel purity: picblobs no longer ships runners
# ---------------------------------------------------------------------------


class TestPicblobsWheelPurity:
    def test_no_runners_dir_inside_picblobs(self) -> None:
        picblobs_pkg_dir = Path(picblobs.__file__).parent
        bad = picblobs_pkg_dir / "_runners"
        assert not bad.exists(), (
            f"{bad} should not exist — runners live in picblobs-cli now"
        )

    def test_picblobs_still_works_on_its_own(self) -> None:
        """Basic picblobs.Blob().build() works without touching the runner bundle."""
        out = picblobs.Blob("linux", "x86_64").alloc_jump().payload(b"x").build()
        assert isinstance(out, bytes) and len(out) > 0


# ---------------------------------------------------------------------------
# 12.11 info
# ---------------------------------------------------------------------------


class TestInfo:
    def test_info_prints_versions(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["info"])
        assert r.exit_code == 0
        assert "picblobs:" in r.output
        assert "picblobs-cli:" in r.output
        assert "runner bundle:" in r.output
        assert "Targets:" in r.output

    def test_info_prints_blob_metadata(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["info", "hello", "linux:x86_64"])
        assert r.exit_code == 0, r.output
        assert "Blob:" in r.output
        assert "hello" in r.output
        assert "Entry offset:" in r.output


class TestListCommand:
    def test_list_runs(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["list"])
        assert r.exit_code == 0, r.output
        assert "BLOB TYPE" in r.output


class TestExtractCommand:
    def test_extract_staged_blob(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "hello.bin"
        r = runner.invoke(
            main,
            ["extract", "hello", "linux:x86_64", "-o", str(out)],
        )
        assert r.exit_code == 0, r.output
        assert out.read_bytes() == picblobs.get_blob("hello", "linux", "x86_64").code


class TestRunSoModeRemoved:
    def test_run_so_option_is_not_supported(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        so_path = tmp_path / "blob.so"
        so_path.write_bytes(b"\x7fELF")

        r = runner.invoke(main, ["run", "--so", str(so_path), "--dry-run"])
        assert r.exit_code != 0
        assert "No such option" in r.output


class TestVerifyNaclE2E:
    def test_nacl_e2e_passes_ephemeral_port_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import picblobs_cli.cli as cli

        captured: dict[str, object] = {}

        monkeypatch.setattr(
            cli,
            "_check_nacl_e2e_speed",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(cli, "find_runner", lambda _os, _arch: Path("/tmp/runner"))
        monkeypatch.setattr(
            picblobs,
            "get_blob",
            lambda blob_type, os_name, arch: SimpleNamespace(
                blob_type=blob_type,
                target_os=os_name,
                target_arch=arch,
            ),
        )
        monkeypatch.setattr(
            "picblobs.runner.reserve_tcp_port",
            lambda host="127.0.0.1": 45678,
        )

        def _run_blob_pair(*args, **kwargs):
            captured["kwargs"] = kwargs
            return SimpleNamespace(
                server_stdout=(
                    b"[server] listening\n"
                    b"[server] decrypted: Hello from NaCl PIC blob!\n"
                    b"[server] secure channel OK\n"
                ),
                server_stderr=b"",
                server_exit=0,
                client_stdout=(
                    b"[client] decrypted ACK: OK\n[client] secure channel OK\n"
                ),
                client_stderr=b"",
                client_exit=0,
            )

        monkeypatch.setattr("picblobs.runner.run_blob_pair", _run_blob_pair)

        detail = cli._verify_nacl_e2e("freebsd", "x86_64", 30.0)
        assert "Hello from NaCl PIC blob!" in detail
        kwargs = captured["kwargs"]
        expected = struct.pack("<H", 45678) + cli._NACL_VERIFY_AUTH_KEY
        assert kwargs["server_config"] == expected
        assert kwargs["client_config"] == expected
        # Config must carry the port plus the 32-byte handshake auth key.
        assert len(expected) == 2 + 32


class TestDisasmAndListing:
    def test_disasm_lists_symbols(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import picblobs_cli.cli as cli

        so_path = tmp_path / "hello.so"
        so_path.write_bytes(b"\x7fELF")

        monkeypatch.setattr(cli, "_find_objdump_or_fail", lambda _arch: "objdump")
        monkeypatch.setattr(
            "picblobs._objdump.list_symbols",
            lambda _so, _objdump: [("00000000", "10", "_start")],
        )

        r = runner.invoke(
            main,
            ["disasm", "--so", str(so_path), "-f", ""],
        )
        assert r.exit_code == 0, r.output
        assert "_start" in r.output

    def test_listing_prefers_debug_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import picblobs_cli.cli as cli

        debug_dir = tmp_path / "debug" / "linux" / "x86_64"
        debug_dir.mkdir(parents=True)
        so_path = debug_dir / "hello.so"
        so_path.write_bytes(b"\x7fELF")

        monkeypatch.setattr(cli, "_debug_blob_dir", lambda: tmp_path / "debug")
        monkeypatch.setattr(cli, "_release_blob_dir", lambda: tmp_path / "release")
        monkeypatch.setattr(cli, "_find_objdump_or_fail", lambda _arch: "objdump")
        monkeypatch.setattr("picblobs._objdump.has_debug_info", lambda *_args: False)
        monkeypatch.setattr(
            "picblobs._objdump.disassemble_full",
            lambda so, _objdump, source=True: f"disasm:{Path(so).name}:{source}",
        )

        r = runner.invoke(main, ["listing", "hello", "linux:x86_64"])
        assert r.exit_code == 0, r.output
        assert "disasm:hello.so:False" in r.output


class TestDebugCommand:
    def test_debug_help_mentions_first_instruction(
        self,
        runner: CliRunner,
    ) -> None:
        r = runner.invoke(main, ["debug", "--help"])
        assert r.exit_code == 0, r.output
        assert "first instruction" in r.output

    def test_debug_native_dry_run(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _arch: True)
        monkeypatch.setattr(
            "picblobs._gdb.find_gdb", lambda _arch, native=False: "/usr/bin/gdb"
        )

        r = runner.invoke(main, ["debug", "hello", "linux:x86_64", "--dry-run"])
        assert r.exit_code == 0, r.output
        # Native: gdb launched directly, no qemu gdbstub line.
        assert "/usr/bin/gdb" in r.output
        assert " -x " in r.output
        assert "-g " not in r.output

    def test_debug_cross_dry_run_spawns_qemu_stub(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("picblobs.runner._is_native_arch", lambda _arch: False)
        monkeypatch.setattr(
            "picblobs._gdb.find_gdb", lambda _arch, native=False: "gdb-multiarch"
        )
        monkeypatch.setattr(
            "picblobs.runner.find_qemu", lambda _arch: Path("/usr/bin/qemu-aarch64")
        )

        r = runner.invoke(
            main,
            ["debug", "hello", "linux:aarch64", "--gdb-port", "4567", "--dry-run"],
        )
        assert r.exit_code == 0, r.output
        assert "/usr/bin/qemu-aarch64 -g 4567" in r.output
        assert "gdb-multiarch" in r.output

    def test_debug_rejects_non_linux(self, runner: CliRunner) -> None:
        r = runner.invoke(main, ["debug", "hello_windows", "windows:x86_64"])
        assert r.exit_code == 1
        assert "linux targets only" in r.output

    def test_debug_enforces_required_config(self, runner: CliRunner) -> None:
        # ul_exec needs an embedded ELF; without --elf the builder must reject
        # it rather than wrapping an unconfigured blob that dies at its own
        # runtime check.
        r = runner.invoke(main, ["debug", "ul_exec", "linux:x86_64", "--dry-run"])
        assert r.exit_code == 1
        assert "ul_exec requires --elf" in r.output

    def test_debug_config_error_precedes_gdb_resolution(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # On a host without gdb, an input error (ul_exec missing --elf) must
        # still surface as the actionable config error, not "No gdb found":
        # blob validation happens before debugger resolution.
        def _no_gdb(_arch: str, native: bool = False) -> str:
            raise FileNotFoundError("No gdb found for testing")

        monkeypatch.setattr("picblobs._gdb.find_gdb", _no_gdb)

        r = runner.invoke(main, ["debug", "ul_exec", "linux:x86_64", "--dry-run"])
        assert r.exit_code == 1
        assert "ul_exec requires --elf" in r.output
        assert "No gdb found" not in r.output

    def test_debug_rejects_build_options_with_file(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        fake = tmp_path / "blob.bin"
        fake.write_bytes(b"\x90\x90")
        r = runner.invoke(
            main,
            ["debug", "--file", str(fake), "linux:x86_64", "--elf", str(fake)],
        )
        assert r.exit_code == 1
        assert "no effect with --file" in r.output

    def test_write_gdb_script_native_uses_starti(self, tmp_path: Path) -> None:
        import picblobs_cli.cli as cli

        so = tmp_path / "hello.so"
        so.write_bytes(b"\x7fELF")
        script = cli._write_gdb_script(
            tmp_path / "blob.elf",
            base_vaddr=0x400000,
            entry_pc=0x400000,
            symbol_so=so,
            remote_port=None,
        )
        text = script.read_text()
        assert "starti" in text
        assert "target remote" not in text
        assert f"add-symbol-file {so} -o 0x400000" in text
        script.unlink()

    def test_write_gdb_script_remote_uses_target(self, tmp_path: Path) -> None:
        import picblobs_cli.cli as cli

        script = cli._write_gdb_script(
            tmp_path / "blob.elf",
            base_vaddr=0x400000,
            entry_pc=0x400001,
            symbol_so=None,
            remote_port=1234,
        )
        text = script.read_text()
        assert "target remote :1234" in text
        assert "starti" not in text
        assert "add-symbol-file" not in text
        script.unlink()


class TestTestCommand:
    def test_test_command_sets_filters(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: dict[str, object] = {}

        def _run(cmd, **kwargs):
            calls["cmd"] = cmd
            calls["env"] = kwargs["env"]
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(subprocess, "run", _run)

        r = runner.invoke(
            main,
            [
                "test",
                "--os",
                "linux",
                "--arch",
                "x86_64",
                "--type",
                "hello",
                "-k",
                "smoke",
                "--",
                "python/tests/test_payload_hello.py",
            ],
        )
        assert r.exit_code == 0, r.output
        assert calls["cmd"] == [
            sys.executable,
            "-m",
            "pytest",
            "-k",
            "smoke",
            "python/tests/test_payload_hello.py",
        ]
        env = calls["env"]
        assert env["PICBLOBS_TEST_OS"] == "linux"
        assert env["PICBLOBS_TEST_ARCH"] == "x86_64"
        assert env["PICBLOBS_TEST_TYPE"] == "hello"
