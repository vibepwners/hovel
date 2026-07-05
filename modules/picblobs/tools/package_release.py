"""Package the canonical release structure into release archives.

This is Stage 3 of the release build pipeline (MOD-007).
Produces:
  - picblobs-{version}.tar.gz
  - picblobs-{version}.tar.zst (if zstd available)
  - SHA-256 checksum files

The wheel is built separately via `python -m build`.

Usage:
    python tools/package_release.py                   # from default paths
    python tools/package_release.py --release-dir .   # custom source
    python tools/package_release.py --output-dir dist/ # custom output
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


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
        print("Run: python tools/extract_release.py", file=sys.stderr)
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

        # Create .tar.gz.
        targz = output_dir / f"{prefix}.tar.gz"
        with tarfile.open(targz, "w:gz") as tar:
            tar.add(str(stage), arcname=prefix)
        created.append(targz)
        if verbose:
            print(f"  {targz} ({targz.stat().st_size} bytes)")

        # Create .tar.zst (if zstd is available).
        if shutil.which("zstd"):
            tarzst = output_dir / f"{prefix}.tar.zst"
            # Create uncompressed tar first, then pipe through zstd.
            tar_uncompressed = Path(tmpdir) / f"{prefix}.tar"
            with tarfile.open(str(tar_uncompressed), "w") as tar:
                tar.add(str(stage), arcname=prefix)
            subprocess.run(
                ["zstd", "-q", "--rm", str(tar_uncompressed), "-o", str(tarzst)],
                check=True,
            )
            created.append(tarzst)
            if verbose:
                print(f"  {tarzst} ({tarzst.stat().st_size} bytes)")
        else:
            print("  zstd not found — skipping .tar.zst", file=sys.stderr)

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
