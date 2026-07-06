#!/usr/bin/env python3
"""Build deterministic picblobs wheel/sdist artifacts without host packaging tools."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import importlib.util
import io
import os
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_LICENSE_CLASSIFIER = "License :: OSI Approved :: Apache Software License"


@dataclass(frozen=True)
class PackageSpec:
    name: str
    project_dir: str
    import_package: str


PACKAGES = {
    "picblobs": PackageSpec("picblobs", "python", "picblobs"),
    "picblobs-cli": PackageSpec("picblobs-cli", "python_cli", "picblobs_cli"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", choices=sorted(PACKAGES), required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-version")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()

    repo = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    spec = PACKAGES[args.package]
    package_root = repo / "modules" / "picblobs" / spec.project_dir
    pyproject = tomllib.loads((package_root / "pyproject.toml").read_text())
    project = pyproject["project"]
    version = project["version"]

    out_dir = resolve_out_dir(repo, args.out_dir)
    if args.clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    wheel = build_wheel(out_dir, package_root, spec, project, version)
    sdist = build_sdist(out_dir, package_root, spec, project, version)
    print(wheel)
    print(sdist)

    if args.validate:
        return check_dist_main(
            [
                args.package,
                "--dist-dir",
                str(out_dir),
                *(
                    ["--expected-version", args.expected_version]
                    if args.expected_version
                    else []
                ),
            ]
        )
    return 0


def check_dist_main(argv: list[str]) -> int:
    validator = Path(__file__).with_name("check_dist.py")
    spec = importlib.util.spec_from_file_location("check_dist", validator)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {validator}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main(argv)


def resolve_out_dir(repo: Path, out_dir: Path) -> Path:
    return out_dir if out_dir.is_absolute() else repo / out_dir


def build_wheel(
    out_dir: Path,
    package_root: Path,
    spec: PackageSpec,
    project: dict,
    version: str,
) -> Path:
    normalized = normalized_name(spec.name)
    dist_info = f"{normalized}-{version}.dist-info"
    wheel = out_dir / f"{normalized}-{version}-py3-none-any.whl"
    records: list[tuple[str, bytes, int]] = []

    for rel, data, mode in package_files(package_root, spec):
        records.append((rel.as_posix(), data, mode))

    records.append((f"{dist_info}/METADATA", metadata(project).encode(), 0o644))
    records.append((f"{dist_info}/WHEEL", wheel_metadata().encode(), 0o644))
    entry_points = console_entry_points(project)
    if entry_points:
        records.append((f"{dist_info}/entry_points.txt", entry_points.encode(), 0o644))

    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        record_rows: list[list[str]] = []
        for path, data, mode in sorted(records):
            write_zip_entry(zf, path, data, mode)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(
                b"="
            )
            record_rows.append([path, f"sha256={digest.decode()}", str(len(data))])

        record_path = f"{dist_info}/RECORD"
        record_rows.append([record_path, "", ""])
        write_zip_entry(zf, record_path, csv_body(record_rows).encode(), 0o644)
    return wheel


def build_sdist(
    out_dir: Path,
    package_root: Path,
    spec: PackageSpec,
    project: dict,
    version: str,
) -> Path:
    normalized = normalized_name(spec.name)
    prefix = f"{normalized}-{version}"
    sdist = out_dir / f"{prefix}.tar.gz"

    entries: list[tuple[str, bytes, int]] = [
        (f"{prefix}/PKG-INFO", metadata(project).encode(), 0o644),
        (
            f"{prefix}/pyproject.toml",
            (package_root / "pyproject.toml").read_bytes(),
            0o644,
        ),
    ]
    readme = package_root / "README.md"
    if readme.exists():
        entries.append((f"{prefix}/README.md", readme.read_bytes(), 0o644))
    for rel, data, mode in package_files(package_root, spec):
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


def package_files(
    package_root: Path,
    spec: PackageSpec,
) -> list[tuple[Path, bytes, int]]:
    root = package_root / spec.import_package
    files: list[tuple[Path, bytes, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or should_exclude(path.relative_to(package_root)):
            continue
        rel = path.relative_to(package_root)
        mode = path.stat().st_mode & 0o777
        mode = 0o755 if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else 0o644
        files.append((rel, path.read_bytes(), mode))
    return files


def should_exclude(rel: Path) -> bool:
    parts = rel.parts
    if "__pycache__" in parts or rel.suffix in {".pyc", ".pyo"}:
        return True
    return len(parts) >= 2 and parts[1] == "_blobs"


def metadata(project: dict) -> str:
    msg = EmailMessage()
    msg["Metadata-Version"] = "2.4"
    msg["Name"] = project["name"]
    msg["Version"] = project["version"]
    msg["Summary"] = project["description"]
    msg["Requires-Python"] = project["requires-python"]
    msg["License-Expression"] = project["license"]
    authors = project.get("authors", [])
    if authors:
        msg["Author-email"] = ", ".join(
            f"{author['name']} <{author['email']}>" for author in authors
        )
    for classifier in project.get("classifiers", []):
        msg.add_header("Classifier", classifier)
    if _LICENSE_CLASSIFIER not in project.get("classifiers", []):
        msg.add_header("Classifier", _LICENSE_CLASSIFIER)
    keywords = project.get("keywords", [])
    if keywords:
        msg["Keywords"] = ", ".join(keywords)
    for dependency in project.get("dependencies", []):
        msg.add_header("Requires-Dist", dependency)
    for name, url in project.get("urls", {}).items():
        msg.add_header("Project-URL", f"{name}, {url}")
    return str(msg)


def wheel_metadata() -> str:
    return "\n".join(
        [
            "Wheel-Version: 1.0",
            "Generator: picblobs-build-dist",
            "Root-Is-Purelib: true",
            "Tag: py3-none-any",
            "",
        ]
    )


def console_entry_points(project: dict) -> str:
    scripts = project.get("scripts", {})
    if not scripts:
        return ""
    lines = ["[console_scripts]"]
    lines.extend(f"{name} = {target}" for name, target in sorted(scripts.items()))
    return "\n".join(lines) + "\n"


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
