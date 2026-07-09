#!/usr/bin/env python3
"""Tests for the Mbed OS build wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from compile_mbed_os import (
    read_version_macro,
    validate_blob_configs,
    validate_build_root,
    write_role_config,
)
from materialize_blobs import write_header


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
    raise SystemExit(pytest.main([__file__]))
