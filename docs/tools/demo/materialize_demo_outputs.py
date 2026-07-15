#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path


ALL_DEMOS_MODE = "all"
DEMO_ASSET_SUFFIX = ".gif"
MAXIMUM_DEMO_DURATION_SECONDS = 30.0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh checked-in docs demo assets from host-rendered GIFs."
    )
    parser.add_argument("--mode", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    manifest = resolve_runfile(args.manifest)
    outputs = [line.strip() for line in manifest.read_text().splitlines() if line.strip()]
    dest_root = workspace / "docs/site/public/assets/demos"
    dest_root.mkdir(parents=True, exist_ok=True)
    stamp_root = workspace / "docs/demo/out"
    stamp_root.mkdir(parents=True, exist_ok=True)

    sources = [resolve_first_runfile("docs/" + output, output) for output in outputs]
    fingerprint = digest_outputs(args.mode, outputs, sources)
    stamp = stamp_root / f".{args.mode}.sha256"
    if is_current(stamp, fingerprint, dest_root, outputs, sources):
        print(f"demo artifacts are current: {args.mode}")
        return 0

    gif_duration_seconds = load_gif_duration_checker()
    refreshed = refresh_demo_assets(
        args.mode,
        outputs,
        sources,
        dest_root,
        gif_duration_seconds,
    )
    for path, duration in refreshed:
        print(f"{path}: {duration:.2f}s")
        if duration > MAXIMUM_DEMO_DURATION_SECONDS:
            print(
                f"warning: {path} runs {duration:.2f}s, over the "
                f"{MAXIMUM_DEMO_DURATION_SECONDS:g}s GIF duration guideline",
                file=sys.stderr,
            )
    write_stamp(stamp, fingerprint)
    print("refreshed checked-in demo assets:")
    for path, _ in refreshed:
        print(f"  {path.relative_to(workspace)}")
    return 0


def load_gif_duration_checker():
    path = Path(__file__).with_name("check_gif_duration.py")
    spec = importlib.util.spec_from_file_location("check_gif_duration", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.gif_duration_seconds


def digest_outputs(mode: str, outputs: list[str], sources: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(mode.encode())
    digest.update(b"\0")
    for output, source in zip(outputs, sources, strict=True):
        digest.update(output.encode())
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def refresh_demo_assets(
    mode: str,
    outputs: list[str],
    sources: list[Path],
    dest_root: Path,
    duration_checker,
) -> list[tuple[Path, float]]:
    if not outputs:
        raise ValueError("demo output manifest is empty")
    if len(outputs) != len(sources):
        raise ValueError("demo output manifest and source count differ")
    destinations = [demo_asset_path(dest_root, output) for output in outputs]
    destination_names = [path.name for path in destinations]
    if len(destination_names) != len(set(destination_names)):
        raise ValueError("demo output manifest contains duplicate asset names")
    if any(path.suffix.lower() != DEMO_ASSET_SUFFIX for path in destinations):
        raise ValueError("demo output manifest contains a non-GIF asset")

    dest_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{dest_root.name}-refresh-",
        dir=dest_root.parent,
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        staged_root = temporary_root / "staged"
        backup_root = temporary_root / "backup"
        staged_root.mkdir()
        backup_root.mkdir()

        refreshed: list[tuple[Path, float]] = []
        staged_paths: list[Path] = []
        for source, destination in zip(sources, destinations, strict=True):
            staged = staged_root / destination.name
            shutil.copy2(source, staged)
            staged.chmod(0o644)
            refreshed.append((destination, duration_checker(staged)))
            staged_paths.append(staged)

        stale_paths: list[Path] = []
        if mode == ALL_DEMOS_MODE and dest_root.is_dir():
            expected_names = set(destination_names)
            stale_paths = sorted(
                path
                for path in dest_root.glob(f"*{DEMO_ASSET_SUFFIX}")
                if path.name not in expected_names
            )

        commit_demo_assets(
            destinations,
            staged_paths,
            stale_paths,
            backup_root,
        )
        return refreshed


def commit_demo_assets(
    destinations: list[Path],
    staged_paths: list[Path],
    stale_paths: list[Path],
    backup_root: Path,
) -> None:
    dest_root = destinations[0].parent if destinations else None
    if dest_root is not None:
        dest_root.mkdir(parents=True, exist_ok=True)

    affected = [*destinations, *stale_paths]
    existing_names: set[str] = set()
    for path in affected:
        if not path.exists():
            continue
        existing_names.add(path.name)
        shutil.copy2(path, backup_root / path.name)

    try:
        for staged, destination in zip(staged_paths, destinations, strict=True):
            os.replace(staged, destination)
        for stale in stale_paths:
            stale.unlink()
    except Exception:
        for path in affected:
            backup = backup_root / path.name
            if path.name in existing_names:
                os.replace(backup, path)
            else:
                path.unlink(missing_ok=True)
        raise


def write_stamp(stamp: Path, fingerprint: str) -> None:
    stamp.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix=f".{stamp.name}-",
        dir=stamp.parent,
        delete=False,
    ) as temporary:
        temporary.write(fingerprint + "\n")
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, stamp)


def is_current(
    stamp: Path,
    fingerprint: str,
    dest_root: Path,
    outputs: list[str],
    sources: list[Path],
) -> bool:
    if not stamp.exists() or stamp.read_text().strip() != fingerprint:
        return False
    for output, source in zip(outputs, sources, strict=True):
        dest = demo_asset_path(dest_root, output)
        if not dest.is_file() or dest.read_bytes() != source.read_bytes():
            return False
    return True


def demo_asset_path(dest_root: Path, output: str) -> Path:
    return dest_root / Path(output).name


def resolve_runfile(path: str) -> Path:
    return resolve_first_runfile(path)


def resolve_first_runfile(*paths: str) -> Path:
    for path in paths:
        raw = Path(path)
        if raw.is_absolute() and raw.exists():
            return raw.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            for path in paths:
                candidate = Path(root) / prefix / path
                if candidate.exists():
                    return candidate.resolve()
    for path in paths:
        candidate = Path.cwd() / path
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"missing runfile: {' or '.join(paths)}")


if __name__ == "__main__":
    raise SystemExit(main())
