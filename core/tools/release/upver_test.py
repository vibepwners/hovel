#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path


def load_upver():
    path = Path(__file__).with_name("upver.py")
    spec = importlib.util.spec_from_file_location("upver", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upver = load_upver()


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def write_release_tree(root: Path, version: str) -> None:
    write(root / "VERSION", version + "\n")
    write(root / "core" / "VERSION", version + "\n")
    write(root / "core" / "MODULE.bazel", f'module(\n    name = "hovel",\n    version = "{version}",\n)\n')
    write(root / "core" / "internal" / "version" / "version.go", f'package version\n\nconst Version = "{version}"\n')
    write(root / "sdk" / "python" / "pyproject.toml", f'[project]\nname = "hovel-sdk"\nversion = "{version}"\n')
    write(root / "sdk" / "python" / "uv.lock", f'[[package]]\nname = "hovel-sdk"\nversion = "{version}"\n')


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_release_tree(root, "0.1.0")

        version = upver.normalize("v1.2.3")
        upver.write_version(root, version)
        upver.sync(root, version)

        assert (root / "VERSION").read_text(encoding="utf-8") == "1.2.3\n"
        assert (root / "core" / "VERSION").read_text(encoding="utf-8") == "1.2.3\n"
        assert 'version = "1.2.3"' in (root / "core" / "MODULE.bazel").read_text(encoding="utf-8")
        assert 'const Version = "1.2.3"' in (root / "core" / "internal" / "version" / "version.go").read_text(encoding="utf-8")
        assert 'version = "1.2.3"' in (root / "sdk" / "python" / "pyproject.toml").read_text(encoding="utf-8")
        assert 'version = "1.2.3"' in (root / "sdk" / "python" / "uv.lock").read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_release_tree(root, "0.2.4")
        write(root / "core" / "VERSION", "0.2.5\n")

        version = upver.read_current(root)
        upver.write_version(root, version)
        upver.sync(root, version)

        assert version == "0.2.5"
        assert (root / "VERSION").read_text(encoding="utf-8") == "0.2.5\n"
        assert (root / "core" / "VERSION").read_text(encoding="utf-8") == "0.2.5\n"
        assert 'version = "0.2.5"' in (root / "core" / "MODULE.bazel").read_text(encoding="utf-8")
        assert 'const Version = "0.2.5"' in (root / "core" / "internal" / "version" / "version.go").read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_release_tree(root, "0.3.0")
        assert upver.release_root(root / "core") == root

        old_workspace = os.environ.get("BUILD_WORKSPACE_DIRECTORY")
        os.environ["BUILD_WORKSPACE_DIRECTORY"] = str(root / "core")
        try:
            assert upver.default_root() == root
            assert upver.resolve_root(Path("..")) == root
        finally:
            if old_workspace is None:
                os.environ.pop("BUILD_WORKSPACE_DIRECTORY", None)
            else:
                os.environ["BUILD_WORKSPACE_DIRECTORY"] = old_workspace


if __name__ == "__main__":
    main()
