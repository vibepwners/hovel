#!/usr/bin/env python3
"""Build the platform wheel that wraps the Hovel Go binary."""

from __future__ import annotations

import base64
import csv
import hashlib
import os
import platform
import stat
import sys
import zipfile
from pathlib import Path


NAME = "hovel"
NORMALIZED = "hovel"

LAUNCHER = '''"""Python entry point for the packaged Hovel binary."""

from __future__ import annotations

import os
import subprocess
import sys
from importlib import resources


def main() -> None:
    suffix = ".exe" if os.name == "nt" else ""
    binary = resources.files(__package__).joinpath("bin", "hovel" + suffix)
    argv = [str(binary), *sys.argv[1:]]
    if os.name == "nt":
        raise SystemExit(subprocess.call(argv))
    os.execv(str(binary), argv)
'''


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    version = release_version(root)
    platform_tag = os.environ.get("HOVEL_WHEEL_PLATFORM_TAG") or default_platform_tag()
    binary_name = "hovel.exe" if os.name == "nt" else "hovel"
    candidates = [
        root / "bazel-bin" / "cmd" / "hovel" / "hovel_" / binary_name,
        root / "bazel-bin" / "cmd" / "hovel" / binary_name,
    ]
    binary = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
    if not binary.exists():
        print(f"missing built binary: {binary}", file=sys.stderr)
        return 2

    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    wheel = dist / f"{NORMALIZED}-{version}-py3-none-{platform_tag}.whl"
    dist_info = f"{NORMALIZED}-{version}.dist-info"
    records: list[tuple[str, bytes, int]] = []

    def add(path: str, data: bytes, mode: int = 0o644) -> None:
        records.append((path, data, mode))

    add("hovel/__init__.py", f'__version__ = "{version}"\n'.encode())
    add("hovel/__main__.py", LAUNCHER.encode())
    add(f"hovel/bin/{binary.name}", binary.read_bytes(), 0o755)
    add(
        f"{dist_info}/METADATA",
        f"""Metadata-Version: 2.1
Name: {NAME}
Version: {version}
Summary: Hovel operator console packaged as a Go binary wheel
Requires-Python: >=3.10
""".encode(),
    )
    add(
        f"{dist_info}/WHEEL",
        f"""Wheel-Version: 1.0
Generator: hovel-release
Root-Is-Purelib: false
Tag: py3-none-{platform_tag}
""".encode(),
    )
    add(
        f"{dist_info}/entry_points.txt",
        b"[console_scripts]\nhovel = hovel.__main__:main\n",
    )

    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        record_rows: list[list[str]] = []
        for path, data, mode in records:
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(info, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            record_rows.append([path, f"sha256={digest}", str(len(data))])

        record_path = f"{dist_info}/RECORD"
        record_rows.append([record_path, "", ""])
        record_body = csv_body(record_rows).encode()
        zf.writestr(record_path, record_body)

    print(wheel)
    return 0


def release_version(root: Path) -> str:
    if version := os.environ.get("HOVEL_VERSION"):
        return version.removeprefix("v")
    return (root / "VERSION").read_text(encoding="utf-8").strip().removeprefix("v")


def default_platform_tag() -> str:
    machine = platform.machine().lower()
    match sys.platform:
        case "linux":
            if machine in {"x86_64", "amd64"}:
                return "manylinux_2_28_x86_64"
            if machine in {"aarch64", "arm64"}:
                return "manylinux_2_28_aarch64"
        case "darwin":
            if machine == "arm64":
                return "macosx_11_0_arm64"
            if machine == "x86_64":
                return "macosx_10_15_x86_64"
        case "win32":
            if machine in {"amd64", "x86_64"}:
                return "win_amd64"
            if machine in {"arm64", "aarch64"}:
                return "win_arm64"
    raise SystemExit(f"unsupported wheel platform: {sys.platform}/{machine}")


def csv_body(rows: list[list[str]]) -> str:
    from io import StringIO

    out = StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerows(rows)
    return out.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
