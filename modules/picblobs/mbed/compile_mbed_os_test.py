#!/usr/bin/env python3
"""Tests for the Mbed OS build wrapper."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from compile_mbed_os import (
    EXPECTED_MBED_COMMIT,
    build_lock,
    read_git_head,
    read_version_macro,
    resolve_git_directory,
    resolve_mbed_os,
    validate_artifact,
    validate_blob_configs,
    validate_build_root,
    write_role_config,
)
from materialize_blobs import write_header

LOCK_TEST_TIMEOUT_SECONDS = 2.0
LOCK_TEST_PROBE_SECONDS = 0.05


def test_write_role_config(tmp_path: Path) -> None:
    source = tmp_path / "mbed_app.json"
    destination = tmp_path / "BUILD" / "mbed_app.client.json"
    source.write_text(
        json.dumps(
            {
                "config": {
                    "blob_role": {
                        "value": '"server"',
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    write_role_config(source, destination, "client")

    generated = json.loads(destination.read_text(encoding="utf-8"))
    assert generated["config"]["blob_role"]["value"] == '"client"'


def test_read_version_macro() -> None:
    header = "#define MBED_MAJOR_VERSION 5\n"
    assert read_version_macro(header, "MBED_MAJOR_VERSION") == 5


def test_read_version_macro_rejects_missing_macro() -> None:
    with pytest.raises(ValueError, match="does not define MBED_MAJOR_VERSION"):
        read_version_macro("", "MBED_MAJOR_VERSION")


def test_validate_build_root_rejects_source_descendant(tmp_path: Path) -> None:
    source_root = tmp_path / "project"

    with pytest.raises(ValueError, match="outside the project source tree"):
        validate_build_root(source_root, source_root / "BUILD" / "server")


def test_validate_build_root_accepts_sibling(tmp_path: Path) -> None:
    validate_build_root(tmp_path / "project", tmp_path / "build" / "server")


def test_resolve_mbed_os_from_bazel_version_header(tmp_path: Path) -> None:
    mbed_os = tmp_path / "external" / "mbed_os"
    version_header = mbed_os / "platform" / "mbed_version.h"
    version_header.parent.mkdir(parents=True)
    version_header.touch()

    assert (
        resolve_mbed_os(
            tmp_path,
            source_override=None,
            version_header=str(version_header),
        )
        == mbed_os
    )


def test_resolve_mbed_os_requires_declared_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Mbed OS source is required"):
        resolve_mbed_os(
            tmp_path,
            source_override=None,
            version_header=None,
        )


def test_read_git_head_resolves_symbolic_reference(tmp_path: Path) -> None:
    git_directory = tmp_path / ".git"
    reference = git_directory / "refs" / "heads" / "mbed-5.15"
    reference.parent.mkdir(parents=True)
    (git_directory / "HEAD").write_text(
        "ref: refs/heads/mbed-5.15\n",
        encoding="ascii",
    )
    reference.write_text(f"{EXPECTED_MBED_COMMIT}\n", encoding="ascii")

    assert read_git_head(git_directory) == EXPECTED_MBED_COMMIT


def test_read_git_head_resolves_worktree_packed_reference(tmp_path: Path) -> None:
    common_directory = tmp_path / "common"
    git_directory = common_directory / "worktrees" / "mbed"
    git_directory.mkdir(parents=True)
    (git_directory / "HEAD").write_text(
        "ref: refs/heads/mbed-5.15\n",
        encoding="ascii",
    )
    (git_directory / "commondir").write_text("../..\n", encoding="utf-8")
    (common_directory / "packed-refs").write_text(
        f"{EXPECTED_MBED_COMMIT} refs/heads/mbed-5.15\n",
        encoding="ascii",
    )
    work_tree = tmp_path / "work-tree"
    work_tree.mkdir()
    (work_tree / ".git").write_text(
        f"gitdir: {git_directory}\n",
        encoding="utf-8",
    )

    resolved = resolve_git_directory(work_tree)

    assert resolved == git_directory
    assert read_git_head(resolved) == EXPECTED_MBED_COMMIT


def test_read_git_head_rejects_parent_reference(tmp_path: Path) -> None:
    git_directory = tmp_path / ".git"
    git_directory.mkdir()
    (git_directory / "HEAD").write_text(
        "ref: refs/heads/../../outside\n",
        encoding="ascii",
    )

    with pytest.raises(ValueError, match="invalid Git HEAD reference"):
        read_git_head(git_directory)


def test_validate_artifact_rejects_empty_output(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.bin"
    artifact.touch()

    with pytest.raises(ValueError, match="invalid firmware"):
        validate_artifact(artifact, "firmware")


def test_validate_artifact_rejects_non_elf_output(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.elf"
    artifact.write_bytes(b"not-elf")

    with pytest.raises(ValueError, match="invalid ELF header"):
        validate_artifact(artifact, "ELF", magic=b"\x7fELF")


def test_validate_artifact_accepts_expected_output(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.elf"
    artifact.write_bytes(b"\x7fELFdata")

    validate_artifact(artifact, "ELF", minimum_size=8, magic=b"\x7fELF")


def test_build_lock_serializes_concurrent_builds(tmp_path: Path) -> None:
    first_acquired = threading.Event()
    release_first = threading.Event()
    second_acquired = threading.Event()

    def hold_first_lock() -> None:
        with build_lock(tmp_path):
            first_acquired.set()
            assert release_first.wait(LOCK_TEST_TIMEOUT_SECONDS)

    def wait_for_second_lock() -> None:
        with build_lock(tmp_path):
            second_acquired.set()

    first = threading.Thread(target=hold_first_lock)
    second = threading.Thread(target=wait_for_second_lock)
    first.start()
    assert first_acquired.wait(LOCK_TEST_TIMEOUT_SECONDS)
    second.start()
    assert not second_acquired.wait(LOCK_TEST_PROBE_SECONDS)
    release_first.set()
    first.join(LOCK_TEST_TIMEOUT_SECONDS)
    second.join(LOCK_TEST_TIMEOUT_SECONDS)

    assert not first.is_alive()
    assert not second.is_alive()
    assert second_acquired.is_set()


def test_validate_blob_configs_accepts_matching_peers(tmp_path: Path) -> None:
    key = bytes(range(1, 33))
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    write_header(
        blobs / "nacl_server_blob.h",
        "nacl_server_blob",
        b"server" + b"\x0f\x27" + key,
    )
    write_header(
        blobs / "nacl_client_blob.h",
        "nacl_client_blob",
        b"client" + b"\x0f\x27\xc0\x00\x02\x0a" + key,
    )

    validate_blob_configs(tmp_path)


def test_validate_blob_configs_rejects_mismatched_keys(tmp_path: Path) -> None:
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    write_header(
        blobs / "nacl_server_blob.h",
        "nacl_server_blob",
        b"server" + b"\x0f\x27" + bytes(range(1, 33)),
    )
    write_header(
        blobs / "nacl_client_blob.h",
        "nacl_client_blob",
        b"client" + b"\x0f\x27\xc0\x00\x02\x0a" + bytes(range(2, 34)),
    )

    with pytest.raises(ValueError, match="same nonzero auth key"):
        validate_blob_configs(tmp_path)


def test_validate_blob_configs_rejects_stale_code(tmp_path: Path) -> None:
    key = bytes(range(1, 33))
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    server = b"server" + b"\x0f\x27" + key
    client = b"client" + b"\x0f\x27\xc0\x00\x02\x0a" + key
    write_header(blobs / "nacl_server_blob.h", "nacl_server_blob", server)
    write_header(blobs / "nacl_client_blob.h", "nacl_client_blob", client)
    server_bin = tmp_path / "server.bin"
    client_bin = tmp_path / "client.bin"
    server_bin.write_bytes(b"staler" + server[6:])
    client_bin.write_bytes(client)

    with pytest.raises(ValueError, match="server blob header is stale"):
        validate_blob_configs(tmp_path, server_bin, client_bin)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
