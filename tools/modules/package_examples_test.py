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
        for _, _, host_dir, exe in packager.SUPPORTED_HOSTS:
            host_bin = examples_bin / host_dir
            host_bin.mkdir(parents=True, exist_ok=True)
            (host_bin / f"squatter-provider{exe}").write_bytes(f"provider-{host_dir}".encode())
        (examples_bin / "squatter.exe").write_bytes(b"MZfake-squatter")

        packager.ROOT = root
        packager.OUT = root / "dist" / "modules"
        packager.OUT.mkdir(parents=True)

        _, _, archive = packager.package_native(
            "squatter",
            "v0.1.0",
            "payload_provider",
            "Squatter payload provider module.",
            "squatter-provider",
        )

        with tarfile.open(archive, "r:gz") as tf:
            names = set(tf.getnames())
            manifest = tf.extractfile("hovel-module.yaml")
            manifest_body = manifest.read().decode() if manifest is not None else ""
            payload = tf.extractfile("bin/squatter.exe")
            payload_body = payload.read() if payload is not None else b""

        assert "hovel-module.yaml" in names
        for _, _, host_dir, exe in packager.SUPPORTED_HOSTS:
            provider = f"bin/{host_dir}/squatter-provider{exe}"
            assert provider in names
            assert provider in manifest_body
        assert "bin/squatter.exe" in names
        assert payload_body == b"MZfake-squatter"
