#!/usr/bin/env python3
"""Build example Hovel module packages into dist/modules.

Invoked through Task. Native binaries are normally supplied as Bazel runfiles;
direct script use can still consume binaries staged under modules/examples/bin/.
Set HOVEL_MODULE_RELEASE_BASE_URL to produce an HTTPS bulk-install manifest for
a release, for example https://github.com/Vibe-Pwners/hovel/releases/download/v1.2.3.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(
    os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path(__file__).resolve().parents[2])
).resolve()
OUT = ROOT / "dist" / "modules"


MODULE_HOSTS = [
    ("linux", "amd64", "linux-amd64", ""),
    ("linux", "arm64", "linux-arm64", ""),
    ("darwin", "arm64", "darwin-arm64", ""),
]

LINUX_HOSTS = [host for host in MODULE_HOSTS if host[0] == "linux"]

NATIVE_MODULES = [
    ("mock-survey-go", "v0.0.0-example", "survey", "Example Go survey module.", "mock-survey-go", MODULE_HOSTS),
    ("mock-exploit-go", "v0.0.0-example", "exploit", "Example Go exploit module.", "mock-exploit-go", MODULE_HOSTS),
    (
        "mock-exploit-session-go",
        "v0.0.0-example",
        "exploit",
        "Example Go exploit module that opens a fake shell session.",
        "mock-exploit-session-go",
        MODULE_HOSTS,
    ),
    ("mock-survey-rust", "v0.0.0-example", "survey", "Example Rust survey module.", "mock-survey-rust", LINUX_HOSTS),
    ("mock-exploit-rust", "v0.0.0-example", "exploit", "Example Rust exploit module.", "mock-exploit-rust", LINUX_HOSTS),
    (
        "mock-exploit-session-rust",
        "v0.0.0-example",
        "exploit",
        "Example Rust exploit module that opens a fake shell session.",
        "mock-exploit-session-rust",
        LINUX_HOSTS,
    ),
    ("squatter", "v0.1.0", "payload_provider", "Squatter payload provider module.", "squatter-provider", MODULE_HOSTS),
]

PYTHON_MODULES = [
    (
        "mock-survey",
        "v0.0.0-example",
        "survey",
        "Example Python survey module.",
        "modules/examples/python/mock_survey",
        "hovel_example_survey",
    ),
    (
        "mock-exploit",
        "v0.0.0-example",
        "exploit",
        "Example Python exploit module.",
        "modules/examples/python/mock_exploit",
        "hovel_example_exploit",
    ),
    (
        "mock-exploit-session",
        "v0.0.0-example",
        "exploit",
        "Example Python exploit module that opens a fake shell session.",
        "modules/examples/python/mock_exploit_session",
        "hovel_example_exploit_session",
    ),
    (
        "ms17-010-survey",
        "v0.1.0",
        "survey",
        "MS17-010 SMBv1 survey module.",
        "modules/examples/python/ms17_010_survey",
        "hovel_ms17_010_survey",
    ),
    (
        "ms17-010-exploit",
        "v1.0.0",
        "exploit",
        "MS17-010 SMBv1 exploit module.",
        "modules/examples/python/ms17_010_exploit",
        "hovel_ms17_010_exploit",
    ),
]

NATIVE_BINARY_SOURCES: dict[str, Path] = {}


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def copytree(src: Path, dst: Path) -> None:
    ignore = shutil.ignore_patterns(".venv", "__pycache__", "*.pyc", "*.egg-info")
    shutil.copytree(src, dst, ignore=ignore, dirs_exist_ok=True)


def archive_dir(src: Path, dest: Path) -> None:
    with (
        dest.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tf,
    ):
        for path in sorted(src.rglob("*")):
            arcname = path.relative_to(src)
            info = tf.gettarinfo(path, arcname.as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.mode = archive_mode(path)
            if path.is_file():
                with path.open("rb") as f:
                    tf.addfile(info, f)
            else:
                tf.addfile(info)


def archive_mode(path: Path) -> int:
    if path.is_dir():
        return 0o755
    mode = path.stat().st_mode
    return 0o755 if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else 0o644


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


def resolve_binary_source(name: str) -> Path:
    source = NATIVE_BINARY_SOURCES.get(name)
    if source is not None:
        return source
    return ROOT / "modules" / "examples" / "bin" / name


def native_manifest(name: str, version: str, command: str, hosts: list[tuple[str, str, str, str]]) -> str:
    lines = [
        "apiVersion: hovel.dev/v1alpha1",
        "kind: ModulePackage",
        "metadata:",
        f"  name: {name}",
        f"  version: {version}",
        "launch:",
    ]
    for os_name, arch, host_dir, exe in hosts:
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


def package_native(
    name: str,
    version: str,
    _module_type: str,
    _summary: str,
    command: str,
    hosts: list[tuple[str, str, str, str]],
) -> tuple[str, str, Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "hovel-module.yaml", native_manifest(name, version, command, hosts))
        for _, _, host_dir, exe in hosts:
            filename = f"{command}{exe}"
            dst = root / "bin" / host_dir / filename
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(resolve_binary_source(f"{host_dir}/{filename}"), dst)
            dst.chmod(0o755)
        if name == "squatter":
            payload = root / "bin" / "squatter.exe"
            shutil.copy2(resolve_binary_source("squatter.exe"), payload)
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


def parse_module_sources(items: list[str]) -> dict[str, Path]:
    sources = {}
    for item in items:
        name, sep, runfile = item.partition("=")
        if not sep or not name or not runfile:
            raise SystemExit(f"invalid --module value: {item!r}")
        sources[name] = resolve_runfile(runfile)
    return sources


def resolve_runfile(path: str) -> Path:
    raw = Path(path)
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend(
            Path(root) / prefix / path
            for root in runfile_roots()
            for prefix in ("", "_main", "hovel")
        )
        candidates.append(Path.cwd() / path)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    searched = "\n  ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"missing runfile: {path}\nsearched:\n  {searched}")


def runfile_roots() -> list[Path]:
    roots: list[Path] = []
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    argv0 = (
        Path(os.environ.get("PYTHON_BINARY", ""))
        if os.environ.get("PYTHON_BINARY")
        else None
    )
    if argv0:
        roots.append(argv0.parent)
    roots.append(Path.cwd())
    return roots


def main(argv: list[str] | None = None) -> int:
    global NATIVE_BINARY_SOURCES, OUT  # noqa: PLW0603

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        metavar="NAME=RUNFILE",
        help="Native module binary name and Bazel runfile path.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=OUT,
        help="Distribution output directory.",
    )
    args = parser.parse_args(argv)

    NATIVE_BINARY_SOURCES = parse_module_sources(args.module)
    OUT = args.out_dir if args.out_dir.is_absolute() else ROOT / args.out_dir

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
    try:
        output_label = OUT.relative_to(ROOT)
    except ValueError:
        output_label = OUT
    print(f"packaged {len(archives)} modules into {output_label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
