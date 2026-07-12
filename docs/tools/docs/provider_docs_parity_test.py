#!/usr/bin/env python3
"""Semantic parity checks for provider SDK and developer documentation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

CREDENTIAL_METHODS = (
    "credential.describe",
    "credential.runtime",
    "credential.files",
    "credential.encode",
    "credential.stamp",
)
MESH_METHODS = (
    "mesh.describe",
    "mesh.topology",
    "mesh.beacons",
    "mesh.listeners",
    "mesh.listener.start",
    "mesh.listener.stop",
    "mesh.task",
    "mesh.open_stream",
)
PYTHON_API_TYPES = (
    "CredentialDeliveryDescriptor",
    "CredentialRuntimeRequest",
    "CredentialFilesRequest",
    "CredentialEncodingRequest",
    "CredentialStampExecutionRequest",
    "MeshDescriptor",
    "MeshTaskRequest",
    "MeshStreamRequest",
)


def runfile(relative: str) -> Path:
    root = Path(os.environ["TEST_SRCDIR"])
    for prefix in ("_main", "hovel"):
        candidate = root / prefix / relative
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"missing declared runfile: {relative}")


def read(relative: str) -> str:
    return runfile(relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("method", CREDENTIAL_METHODS + MESH_METHODS)
def test_module_protocol_names_every_provider_method(method: str) -> None:
    assert method in read("docs/site/spec/module-protocol.html")


@pytest.mark.parametrize("method", CREDENTIAL_METHODS + MESH_METHODS)
def test_every_sdk_dispatch_surface_contains_method(method: str) -> None:
    language_sources = {
        "go": (
            "sdk/go/hovel/server.go",
            "sdk/go/hovel/credential_delivery.go",
            "sdk/go/hovel/credential_provider.go",
            "sdk/go/hovel/mesh.go",
        ),
        "python": (
            "sdk/python/hovel_sdk/server.py",
            "sdk/python/hovel_sdk/credential_delivery.py",
            "sdk/python/hovel_sdk/credential_provider.py",
            "sdk/python/hovel_sdk/mesh.py",
        ),
        "rust": (
            "sdk/rust/hovel/src/server.rs",
            "sdk/rust/hovel/src/credential_delivery.rs",
            "sdk/rust/hovel/src/credential_provider.rs",
            "sdk/rust/hovel/src/mesh.rs",
        ),
    }
    for language, paths in language_sources.items():
        source = "\n".join(read(path) for path in paths)
        assert method in source, f"{language} SDK omits {method}"


@pytest.mark.parametrize("readme", ("sdk/go/README.md", "sdk/python/README.md", "sdk/rust/README.md"))
@pytest.mark.parametrize("method", CREDENTIAL_METHODS)
def test_sdk_readmes_document_credential_methods(readme: str, method: str) -> None:
    assert method in read(readme)


@pytest.mark.parametrize("symbol", PYTHON_API_TYPES)
def test_python_exports_and_api_inventory_include_provider_types(symbol: str) -> None:
    assert f'"{symbol}"' in read("sdk/python/hovel_sdk/__init__.py")
    assert f"hovel_sdk.{symbol}" in read("docs/tools/docs/python_api/index.rst")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
