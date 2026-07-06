"""Package the canonical release structure into release archives.

This is Stage 3 of the release build pipeline (MOD-007).
Produces:
  - picblobs-{version}.tar.gz
  - SHA-256 checksum files

Python wheels are built by the Bazel-backed dist materializer.

Usage:
    python tools/package_release.py                   # from default paths
    python tools/package_release.py --release-dir .   # custom source
    python tools/package_release.py --output-dir dist/ # custom output
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path


def _project_root() -> Path:
    if workspace := os.environ.get("BUILD_WORKSPACE_DIRECTORY"):
        return Path(workspace).resolve() / "modules" / "picblobs"
    return Path(__file__).resolve().parent.parent


_PROJECT_ROOT = _project_root()


def _get_version(release_dir: Path) -> str:
    """Read version from manifest.json."""
    manifest = release_dir / "manifest.json"
    if manifest.exists():
        data = json.loads(manifest.read_text())
        return data.get("picblobs_version", "0.0.0")
    # Fallback: read from pyproject.toml.
    pyproject = _PROJECT_ROOT / "python" / "pyproject.toml"
    for line in pyproject.read_text().splitlines():
        if line.strip().startswith("version"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _normalize_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = 0o644
    return info


def _write_tar_gz(path: Path, source: Path, arcname: str) -> None:
    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):
        tar.add(str(source), arcname=arcname, filter=_normalize_tarinfo)


def package_release(
    release_dir: Path,
    output_dir: Path,
    *,
    verbose: bool = False,
) -> list[Path]:
    """Package the release structure into archives.

    Args:
        release_dir: Directory containing manifest.json + blobs/.
        output_dir: Where to write the archives.

    Returns:
        List of created archive paths.
    """
    manifest_path = release_dir / "manifest.json"
    blobs_dir = release_dir / "blobs"

    if not manifest_path.exists():
        print(f"manifest.json not found in {release_dir}", file=sys.stderr)
        print("Run: task picblobs:stage-release", file=sys.stderr)
        return []

    if not blobs_dir.exists():
        print(f"blobs/ not found in {release_dir}", file=sys.stderr)
        return []

    version = _get_version(release_dir)
    prefix = f"picblobs-{version}"
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    # Stage into a temp directory with the correct prefix.
    with tempfile.TemporaryDirectory() as tmpdir:
        stage = Path(tmpdir) / prefix
        stage.mkdir()

        # Copy manifest.json.
        shutil.copy2(manifest_path, stage / "manifest.json")

        # Copy blobs/.
        shutil.copytree(blobs_dir, stage / "blobs")

        targz = output_dir / f"{prefix}.tar.gz"
        _write_tar_gz(targz, stage, prefix)
        created.append(targz)
        if verbose:
            print(f"  {targz} ({targz.stat().st_size} bytes)")

    # Create SHA-256 checksum files.
    archives = list(created)  # snapshot before appending
    for archive in archives:
        sha = _sha256_file(archive)
        checksum_file = archive.parent / f"{archive.name}.sha256"
        checksum_file.write_text(f"{sha}  {archive.name}\n")
        created.append(checksum_file)
        if verbose:
            print(f"  {checksum_file}")

    return created


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Package the canonical release structure into archives",
    )
    parser.add_argument(
        "--release-dir",
        type=Path,
        default=_PROJECT_ROOT / "python" / "picblobs",
        help="Directory containing manifest.json + blobs/ (default: python/picblobs)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_PROJECT_ROOT / "dist",
        help="Output directory for archives (default: dist/)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(argv)
    created = package_release(args.release_dir, args.output_dir, verbose=args.verbose)

    if not created:
        return 1

    print(f"Created {len(created)} release artifacts in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
