#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy Bazel-built demo GIFs into demo/out/.")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    manifest = resolve_runfile(args.manifest)
    outputs = [line.strip() for line in manifest.read_text().splitlines() if line.strip()]
    dest_root = workspace / "docs/demo/out"
    dest_root.mkdir(parents=True, exist_ok=True)

    sources = [resolve_first_runfile("docs/" + output, output) for output in outputs]
    fingerprint = digest_outputs(args.mode, outputs, sources)
    stamp = dest_root / f".{args.mode}.sha256"
    if is_current(stamp, fingerprint, workspace, outputs, sources):
        print(f"demo artifacts are current: {args.mode}")
        return 0

    copied: list[Path] = []
    for output, src in zip(outputs, sources, strict=True):
        dest = workspace / "docs" / output
        dest.parent.mkdir(parents=True, exist_ok=True)
        make_writable(dest)
        shutil.copy2(src, dest)
        dest.chmod(0o644)
        copied.append(dest)

    gif_duration_seconds = load_gif_duration_checker()
    for path in copied:
        duration = gif_duration_seconds(path)
        print(f"{path}: {duration:.2f}s")
        if duration > 30.0:
            print(
                f"warning: {path} runs {duration:.2f}s, over the 30s GIF duration guideline",
                file=sys.stderr,
            )
    stamp.write_text(fingerprint + "\n")
    print("generated demo artifacts:")
    for path in copied:
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


def is_current(stamp: Path, fingerprint: str, workspace: Path, outputs: list[str], sources: list[Path]) -> bool:
    if not stamp.exists() or stamp.read_text().strip() != fingerprint:
        return False
    for output, source in zip(outputs, sources, strict=True):
        dest = workspace / "docs" / output
        if not dest.is_file() or dest.read_bytes() != source.read_bytes():
            return False
    return True


def make_writable(path: Path) -> None:
    if path.exists():
        path.chmod(0o644)


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
