#!/usr/bin/env python3
"""Build example Hovel module packages into dist/modules.

Invoked through Task. The script assumes `task modules:build` has already
staged native example binaries into examples/bin/. Set
HOVEL_MODULE_RELEASE_BASE_URL to produce an HTTPS bulk-install manifest for a
release, for example https://github.com/Vibe-Pwners/hovel/releases/download/v1.2.3.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "dist" / "modules"


SUPPORTED_HOSTS = [
    ("linux", "amd64", "linux-amd64", ""),
    ("linux", "arm64", "linux-arm64", ""),
    ("windows", "amd64", "windows-amd64", ".exe"),
    ("windows", "arm64", "windows-arm64", ".exe"),
    ("darwin", "arm64", "darwin-arm64", ""),
]

NATIVE_MODULES = [
    ("mock-survey-go", "v0.0.0-example", "survey", "Example Go survey module.", "mock-survey-go"),
    ("mock-exploit-go", "v0.0.0-example", "exploit", "Example Go exploit module.", "mock-exploit-go"),
    (
        "mock-exploit-session-go",
        "v0.0.0-example",
        "exploit",
        "Example Go exploit module that opens a fake shell session.",
        "mock-exploit-session-go",
    ),
    ("mock-survey-rust", "v0.0.0-example", "survey", "Example Rust survey module.", "mock-survey-rust"),
    ("mock-exploit-rust", "v0.0.0-example", "exploit", "Example Rust exploit module.", "mock-exploit-rust"),
    (
        "mock-exploit-session-rust",
        "v0.0.0-example",
        "exploit",
        "Example Rust exploit module that opens a fake shell session.",
        "mock-exploit-session-rust",
    ),
    ("squatter", "v0.1.0", "payload_provider", "Squatter payload provider module.", "squatter-provider"),
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


def module_release_base_url() -> str:
    base = os.environ.get("HOVEL_MODULE_RELEASE_BASE_URL", "").strip()
    if base:
        return base.rstrip("/")
    tag = os.environ.get("HOVEL_RELEASE_TAG", "").strip()
    if tag:
        return f"https://github.com/Vibe-Pwners/hovel/releases/download/{tag}"
    return ""


def module_source(archive: Path, base_url: str) -> str:
    if base_url:
        return f"{base_url}/{archive.name}"
    return archive.name


def native_manifest(name: str, version: str, command: str) -> str:
    lines = [
        "apiVersion: hovel.dev/v1alpha1",
        "kind: ModulePackage",
        "metadata:",
        f"  name: {name}",
        f"  version: {version}",
        "launch:",
    ]
    for os_name, arch, host_dir, exe in SUPPORTED_HOSTS:
        lines.extend(
            [
                "  - selector:",
                f"      os: {os_name}",
                f"      arch: {arch}",
                f'    command: ["bin/{host_dir}/{command}{exe}"]',
            ]
        )
    return "\n".join(lines) + "\n"


def python_manifest(name: str, version: str, module: str) -> str:
    return f"""apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: {name}
  version: {version}
launch:
  - python:
      managed:
        versions: ["3.12-3.14"]
      requirements: requirements.txt
      command: ["{{python}}", "-m", "{module}"]
"""


def package_native(name: str, version: str, _module_type: str, _summary: str, command: str) -> tuple[str, str, Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "hovel-module.yaml", native_manifest(name, version, command))
        for _, _, host_dir, exe in SUPPORTED_HOSTS:
            filename = f"{command}{exe}"
            dst = root / "bin" / host_dir / filename
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "examples" / "bin" / host_dir / filename, dst)
            dst.chmod(0o755)
        if name == "squatter":
            payload = root / "bin" / "squatter.exe"
            shutil.copy2(ROOT / "examples/bin/squatter.exe", payload)
            payload.chmod(0o755)
        archive = OUT / f"{name}-{version}.tgz"
        archive_dir(root, archive)
        return name, version, archive


def package_python(
    name: str,
    version: str,
    _module_type: str,
    _summary: str,
    source: str,
    module: str,
) -> tuple[str, str, Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        copytree(ROOT / source, root)
        write(root / "hovel-module.yaml", python_manifest(name, version, module))
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
    install_lines = ["apiVersion: hovel.dev/v1alpha1", "kind: ModuleInstallSet", "modules:"]
    sum_lines = []
    base_url = module_release_base_url()
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
        install_lines.extend(
            [
                f"  - source: {module_source(archive, base_url)}",
                f"    sha256: {digest}",
            ]
        )
        sum_lines.append(f"{digest}  {archive.name}")
    write(OUT / "module-index.yaml", "\n".join(index_lines) + "\n")
    write(OUT / "module-install-set.yaml", "\n".join(install_lines) + "\n")
    write(OUT / "SHA256SUMS", "\n".join(sum_lines) + "\n")
    print(f"packaged {len(archives)} modules into {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
