#!/usr/bin/env python3
"""Build example Hovel module packages into dist/modules.

Invoked through Task. The script assumes `task modules:build` has already
staged native example binaries into examples/bin/.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "dist" / "modules"


NATIVE_MODULES = [
    ("mock-survey-go", "v0.0.0-example", "survey", "Example Go survey module.", "examples/bin/mock-survey-go"),
    ("mock-exploit-go", "v0.0.0-example", "exploit", "Example Go exploit module.", "examples/bin/mock-exploit-go"),
    (
        "mock-exploit-session-go",
        "v0.0.0-example",
        "exploit",
        "Example Go exploit module that opens a fake shell session.",
        "examples/bin/mock-exploit-session-go",
    ),
    ("mock-survey-rust", "v0.0.0-example", "survey", "Example Rust survey module.", "examples/bin/mock-survey-rust"),
    ("mock-exploit-rust", "v0.0.0-example", "exploit", "Example Rust exploit module.", "examples/bin/mock-exploit-rust"),
    (
        "mock-exploit-session-rust",
        "v0.0.0-example",
        "exploit",
        "Example Rust exploit module that opens a fake shell session.",
        "examples/bin/mock-exploit-session-rust",
    ),
    ("squatter", "v0.1.0", "payload_provider", "Squatter payload provider module.", "examples/bin/squatter-provider"),
]

PYTHON_MODULES = [
    (
        "mock-survey",
        "v0.0.0-example",
        "survey",
        "Example Python survey module.",
        "examples/python/mock_survey",
        "hovel_example_survey",
    ),
    (
        "mock-exploit",
        "v0.0.0-example",
        "exploit",
        "Example Python exploit module.",
        "examples/python/mock_exploit",
        "hovel_example_exploit",
    ),
    (
        "mock-exploit-session",
        "v0.0.0-example",
        "exploit",
        "Example Python exploit module that opens a fake shell session.",
        "examples/python/mock_exploit_session",
        "hovel_example_exploit_session",
    ),
    (
        "ms17-010-survey",
        "v0.1.0",
        "survey",
        "MS17-010 SMBv1 survey module.",
        "examples/python/ms17_010_survey",
        "hovel_ms17_010_survey",
    ),
    (
        "ms17-010-exploit",
        "v1.0.0",
        "exploit",
        "MS17-010 SMBv1 exploit module.",
        "examples/python/ms17_010_exploit",
        "hovel_ms17_010_exploit",
    ),
]


def host_os() -> str:
    name = platform.system().lower()
    if name == "darwin":
        return "darwin"
    if name == "windows":
        return "windows"
    return "linux"


def host_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    return machine


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def copytree(src: Path, dst: Path) -> None:
    ignore = shutil.ignore_patterns(".venv", "__pycache__", "*.pyc", "*.egg-info")
    shutil.copytree(src, dst, ignore=ignore, dirs_exist_ok=True)


def archive_dir(src: Path, dest: Path) -> None:
    with tarfile.open(dest, "w:gz") as tf:
        for path in sorted(src.rglob("*")):
            arcname = path.relative_to(src)
            info = tf.gettarinfo(path, arcname.as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if path.is_file():
                with path.open("rb") as f:
                    tf.addfile(info, f)
            else:
                tf.addfile(info)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def native_manifest(name: str, version: str, module_type: str, summary: str, command: str) -> str:
    return f"""apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: {name}
  version: {version}
  moduleType: {module_type}
  summary: {summary}
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: {os.environ.get("HOVEL_PACKAGE_OS", host_os())}
      arch: {os.environ.get("HOVEL_PACKAGE_ARCH", host_arch())}
    command: ["bin/{command}"]
"""


def python_manifest(name: str, version: str, module_type: str, summary: str, module: str) -> str:
    return f"""apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: {name}
  version: {version}
  moduleType: {module_type}
  summary: {summary}
runtime:
  protocol: jsonrpc-stdio
launch:
  - python:
      managed:
        versions: ["3.12-3.14"]
      requirements: requirements.txt
      command: ["{{python}}", "-m", "{module}"]
"""


def package_native(name: str, version: str, module_type: str, summary: str, binary: str) -> tuple[str, str, Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        command = Path(binary).name
        write(root / "hovel-module.yaml", native_manifest(name, version, module_type, summary, command))
        dst = root / "bin" / command
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / binary, dst)
        dst.chmod(0o755)
        archive = OUT / f"{name}-{version}.tgz"
        archive_dir(root, archive)
        return name, version, archive


def package_python(name: str, version: str, module_type: str, summary: str, source: str, module: str) -> tuple[str, str, Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        copytree(ROOT / source, root)
        write(root / "hovel-module.yaml", python_manifest(name, version, module_type, summary, module))
        write(root / "requirements.txt", "hovel-sdk\n")
        archive = OUT / f"{name}-{version}.tgz"
        archive_dir(root, archive)
        return name, version, archive


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.tgz"):
        old.unlink()

    archives: list[tuple[str, str, Path]] = []
    for item in NATIVE_MODULES:
        archives.append(package_native(*item))
    for item in PYTHON_MODULES:
        archives.append(package_python(*item))

    index_lines = ["apiVersion: hovel.dev/v1alpha1", "kind: ModuleIndex", "modules:"]
    sum_lines = []
    for name, version, archive in sorted(archives, key=lambda item: item[2].name):
        digest = sha256(archive)
        index_lines.extend(
            [
                f"  - name: {name}",
                f"    version: {version}",
                f"    url: {archive.name}",
                f"    sha256: {digest}",
            ]
        )
        sum_lines.append(f"{digest}  {archive.name}")
    write(OUT / "module-index.yaml", "\n".join(index_lines) + "\n")
    write(OUT / "SHA256SUMS", "\n".join(sum_lines) + "\n")
    print(f"packaged {len(archives)} modules into {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
