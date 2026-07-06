#!/usr/bin/env python3
"""Build deterministic hovel-sdk wheel and sdist artifacts without host uv."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import os
import shutil
import stat
import tarfile
import zipfile
from email.message import EmailMessage
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_PACKAGE_NAME = "hovel-sdk"
_IMPORT_PACKAGE = "hovel_sdk"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    repo = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    package_root = repo / "sdk" / "python"
    pyproject = tomllib.loads((package_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    version = project["version"]
    out_dir = args.out_dir if args.out_dir.is_absolute() else repo / args.out_dir

    if args.clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    wheel = build_wheel(out_dir, package_root, project, version)
    sdist = build_sdist(out_dir, package_root, project, version)
    print(wheel)
    print(sdist)
    return 0


def build_wheel(out_dir: Path, package_root: Path, project: dict, version: str) -> Path:
    normalized = normalized_name(_PACKAGE_NAME)
    dist_info = f"{normalized}-{version}.dist-info"
    wheel = out_dir / f"{normalized}-{version}-py3-none-any.whl"
    records: list[tuple[str, bytes, int]] = []

    for rel, data, mode in package_files(package_root):
        records.append((rel.as_posix(), data, mode))
    records.append((f"{dist_info}/METADATA", metadata(project).encode(), 0o644))
    records.append((f"{dist_info}/WHEEL", wheel_metadata().encode(), 0o644))

    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        record_rows: list[list[str]] = []
        for path, data, mode in sorted(records):
            write_zip_entry(zf, path, data, mode)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            record_rows.append([path, f"sha256={digest.decode()}", str(len(data))])

        record_path = f"{dist_info}/RECORD"
        record_rows.append([record_path, "", ""])
        write_zip_entry(zf, record_path, csv_body(record_rows).encode(), 0o644)
    return wheel


def build_sdist(out_dir: Path, package_root: Path, project: dict, version: str) -> Path:
    normalized = normalized_name(_PACKAGE_NAME)
    prefix = f"{normalized}-{version}"
    sdist = out_dir / f"{prefix}.tar.gz"
    entries: list[tuple[str, bytes, int]] = [
        (f"{prefix}/PKG-INFO", metadata(project).encode(), 0o644),
        (f"{prefix}/pyproject.toml", (package_root / "pyproject.toml").read_bytes(), 0o644),
    ]

    readme = package_root / "README.md"
    if readme.exists():
        entries.append((f"{prefix}/README.md", readme.read_bytes(), 0o644))
    for rel, data, mode in package_files(package_root):
        entries.append((f"{prefix}/{rel.as_posix()}", data, mode))

    with (
        sdist.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tf,
    ):
        for path, data, mode in sorted(entries):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tf.addfile(info, io.BytesIO(data))
    return sdist


def package_files(package_root: Path) -> list[tuple[Path, bytes, int]]:
    root = package_root / _IMPORT_PACKAGE
    files: list[tuple[Path, bytes, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name.endswith((".pyc", ".pyo")):
            continue
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(package_root)
        mode = path.stat().st_mode & 0o777
        mode = 0o755 if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else 0o644
        files.append((rel, path.read_bytes(), mode))
    return files


def metadata(project: dict) -> str:
    msg = EmailMessage()
    msg["Metadata-Version"] = "2.4"
    msg["Name"] = project["name"]
    msg["Version"] = project["version"]
    msg["Summary"] = project["description"]
    msg["Requires-Python"] = project["requires-python"]
    for dependency in project.get("dependencies", []):
        msg.add_header("Requires-Dist", dependency)
    return str(msg)


def wheel_metadata() -> str:
    return "\n".join(
        [
            "Wheel-Version: 1.0",
            "Generator: hovel-sdk-build-dist",
            "Root-Is-Purelib: true",
            "Tag: py3-none-any",
            "",
        ]
    )


def write_zip_entry(zf: zipfile.ZipFile, path: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(path, _ZIP_TIMESTAMP)
    info.external_attr = (stat.S_IFREG | mode) << 16
    zf.writestr(info, data)


def normalized_name(name: str) -> str:
    return name.replace("-", "_")


def csv_body(rows: list[list[str]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerows(rows)
    return out.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
