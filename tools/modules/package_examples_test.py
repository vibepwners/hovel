#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tarfile
import tempfile
from pathlib import Path


def load_packager():
    path = Path(__file__).with_name("package_examples.py")
    spec = importlib.util.spec_from_file_location("package_examples", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_squatter_package_includes_provider_and_payload() -> None:
    packager = load_packager()
    with tempfile.TemporaryDirectory(prefix="hovel-package-examples-test-") as raw:
        root = Path(raw)
        examples_bin = root / "examples" / "bin"
        examples_bin.mkdir(parents=True)
        (examples_bin / "squatter-provider").write_text("#!/bin/sh\n", encoding="utf-8")
        (examples_bin / "squatter.exe").write_bytes(b"MZfake-squatter")

        packager.ROOT = root
        packager.OUT = root / "dist" / "modules"
        packager.OUT.mkdir(parents=True)

        _, _, archive = packager.package_native(
            "squatter",
            "v0.1.0",
            "payload_provider",
            "Squatter payload provider module.",
            "examples/bin/squatter-provider",
        )

        with tarfile.open(archive, "r:gz") as tf:
            names = set(tf.getnames())
            payload = tf.extractfile("bin/squatter.exe")
            payload_body = payload.read() if payload is not None else b""

        assert "hovel-module.yaml" in names
        assert "bin/squatter-provider" in names
        assert "bin/squatter.exe" in names
        assert payload_body == b"MZfake-squatter"
