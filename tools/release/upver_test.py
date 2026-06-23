#!/usr/bin/env python3
from __future__ import annotations

import tempfile
from pathlib import Path

import upver


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "VERSION", "0.1.0\n")
        write(root / "MODULE.bazel", 'module(\n    name = "hovel",\n    version = "0.1.0",\n)\n')
        write(root / "sdk/python/pyproject.toml", '[project]\nname = "hovel-sdk"\nversion = "0.1.0"\n')
        write(root / "sdk/python/uv.lock", '[[package]]\nname = "hovel-sdk"\nversion = "0.1.0"\n')
        write(root / "internal/version/version.go", 'package version\n\nconst Version = "0.1.0"\n')

        version = upver.normalize("v1.2.3")
        upver.write_version(root, version)
        upver.sync(root, version)

        assert (root / "VERSION").read_text(encoding="utf-8") == "1.2.3\n"
        assert 'version = "1.2.3"' in (root / "MODULE.bazel").read_text(encoding="utf-8")
        assert 'version = "1.2.3"' in (root / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
        assert 'version = "1.2.3"' in (root / "sdk/python/uv.lock").read_text(encoding="utf-8")
        assert 'const Version = "1.2.3"' in (root / "internal/version/version.go").read_text(encoding="utf-8")


if __name__ == "__main__":
    main()
