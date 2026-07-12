#!/usr/bin/env python3
"""Hermetic target-build smoke test for the Mbed OS picblobs runner."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pytest

from compile_mbed_os import (
    build_role,
    resolve_runfile,
    validate_build_root,
    validate_compiler,
    validate_mbed_os,
    validate_project,
)
from materialize_blobs import (
    configure_client_blob,
    configure_server_blob,
    parse_ipv4,
    write_header,
)

TEST_AUTH_KEY = bytes(range(1, 33))
TEST_PORT = 4242
TEST_SERVER_IPV4 = "192.0.2.7"
TEST_BUILD_JOBS = 4
SOURCE_ROOT_PARTS = ("modules", "picblobs", "mbed")
PROJECT_SOURCES = (
    "modules/picblobs/mbed/.mbed",
    "modules/picblobs/mbed/.mbedignore",
    "modules/picblobs/mbed/main.cpp",
    "modules/picblobs/mbed/mbed_app.json",
    "modules/picblobs/mbed/picblobs/net.h",
    "modules/picblobs/mbed/picblobs/platform.h",
    "modules/picblobs/mbed/picblobs/types.h",
    "modules/picblobs/mbed/platform_mbed.cpp",
    "modules/picblobs/mbed/platform_mbed.h",
)
CANONICAL_ABI_HEADERS = (
    "modules/picblobs/src/include/picblobs/net.h",
    "modules/picblobs/src/include/picblobs/platform.h",
    "modules/picblobs/src/include/picblobs/types.h",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-bin", required=True)
    parser.add_argument("--gcc", required=True)
    parser.add_argument("--mbed-version-header", required=True)
    parser.add_argument("--server-bin", required=True)
    return parser.parse_args()


def materialize_project(destination: Path, sources: list[str]) -> None:
    for source_value in sources:
        source = resolve_runfile(source_value)
        relative = project_relative_path(source)
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, output)


def materialize_abi_headers(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for source_value in CANONICAL_ABI_HEADERS:
        source = resolve_runfile(source_value)
        shutil.copy2(source, destination / source.name)


def project_relative_path(source: Path) -> Path:
    parts = source.parts
    width = len(SOURCE_ROOT_PARTS)
    for index in range(len(parts) - width + 1):
        if parts[index : index + width] == SOURCE_ROOT_PARTS:
            relative_parts = parts[index + width :]
            if relative_parts:
                return Path(*relative_parts)
            break
    raise ValueError(f"source is outside the Mbed project: {source}")


def test_real_mbed_os_server_and_client_compile(tmp_path: Path) -> None:
    args = parse_args()
    project = tmp_path / "project"
    materialize_project(project, list(PROJECT_SOURCES))
    materialize_abi_headers(tmp_path / "src" / "include" / "picblobs")

    server_bin = resolve_runfile(args.server_bin)
    client_bin = resolve_runfile(args.client_bin)
    blobs = project / "blobs"
    write_header(
        blobs / "nacl_server_blob.h",
        "nacl_server_blob",
        configure_server_blob(server_bin.read_bytes(), TEST_PORT, TEST_AUTH_KEY),
    )
    write_header(
        blobs / "nacl_client_blob.h",
        "nacl_client_blob",
        configure_client_blob(
            client_bin.read_bytes(),
            TEST_PORT,
            parse_ipv4(TEST_SERVER_IPV4),
            TEST_AUTH_KEY,
        ),
    )

    version_header = resolve_runfile(args.mbed_version_header)
    mbed_os = version_header.parent.parent
    gcc = resolve_runfile(args.gcc)
    build_root = tmp_path / "build"

    validate_project(project, server_bin, client_bin)
    validate_mbed_os(mbed_os)
    validate_compiler(gcc)
    validate_build_root(project, build_root)
    validate_build_root(mbed_os, build_root)

    for role in ("server", "client"):
        assert (
            build_role(
                source_root=project,
                mbed_os=mbed_os,
                build_root=build_root,
                gcc=gcc,
                role=role,
                jobs=TEST_BUILD_JOBS,
            )
            == 0
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
