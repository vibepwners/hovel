#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
from pathlib import Path


def load_helper(name: str):
    path = Path(__file__).with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check_site_links = load_helper("check_site_links")
generate_sdk_api_docs = load_helper("generate_sdk_api_docs")


def main() -> int:
    uv_bin, go_bin, rustdoc_bin = parse_tool_args(sys.argv[1:])
    repo = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    fingerprint = docs_fingerprint(repo)
    site = repo / "_site"
    stamp = site / ".hovel_docs_inputs.sha256"
    if stamp.exists() and (site / ".nojekyll").exists() and stamp.read_text().strip() == fingerprint:
        print("docs site is current: _site")
        return 0

    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    copy_file(repo / "index.html", site / "index.html")
    copy_file(repo / "LICENSE", site / "LICENSE")
    copy_tree(repo / "assets", site / "assets")
    copy_tree(repo / "spec", site / "spec", ignore_names={"BUILD.bazel"})
    replace_version_tokens(site, (repo / "VERSION").read_text().strip())
    copy_demo_outputs(repo, site)

    generate_sdk_api_docs.main_with_paths(
        repo_root=repo,
        site_root=site,
        output=site / "api/sdk",
        uv_bin=uv_bin,
        go_bin=go_bin,
        rustdoc_bin=rustdoc_bin,
    )
    check_site_links.check_site(site)
    (site / ".nojekyll").touch()
    stamp.write_text(fingerprint + "\n")
    return 0


def parse_tool_args(args: list[str]) -> tuple[Path | None, Path | None, Path | None]:
    uv_bin: Path | None = None
    go_bin: Path | None = None
    rustdoc_bin: Path | None = None
    for arg in args:
        key, sep, value = arg.partition("=")
        if sep != "=":
            raise SystemExit(f"unexpected argument: {arg}")
        if key == "--uv-bin":
            uv_bin = resolve_runfile(value)
        elif key == "--go-bin":
            go_bin = resolve_runfile(value)
        elif key == "--rustdoc-bin":
            rustdoc_bin = resolve_runfile(value)
        else:
            raise SystemExit(f"unexpected argument: {key}")
    return uv_bin, go_bin, rustdoc_bin


def docs_fingerprint(repo: Path) -> str:
    paths: set[Path] = {
        repo / "LICENSE",
        repo / "VERSION",
        repo / "go.mod",
        repo / "go.sum",
        repo / "index.html",
        repo / "sdk/python/pyproject.toml",
        repo / "sdk/python/uv.lock",
        repo / "tools/docs/check_site_links.py",
        repo / "tools/docs/generate_sdk_api_docs.py",
        repo / "tools/docs/stage_site.py",
        resolve_runfile("demo/all_gif_manifest.txt"),
    }
    for pattern in (
        "assets/**/*",
        "demo/out/*.gif",
        "sdk/go/**/*.go",
        "sdk/python/hovel_sdk/**/*.py",
        "sdk/rust/hovel/src/**/*.rs",
        "spec/**/*.html",
        "tools/docs/python_api/**/*",
    ):
        paths.update(repo.glob(pattern))

    digest = hashlib.sha256()
    for path in sorted(path for path in paths if path.is_file()):
        digest.update(fingerprint_name(repo, path).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def fingerprint_name(repo: Path, path: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.name


def copy_file(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def copy_tree(src: Path, dest: Path, ignore_names: set[str] | None = None) -> None:
    ignore_names = ignore_names or set()
    for path in src.rglob("*"):
        if any(part in ignore_names for part in path.relative_to(src).parts):
            continue
        if path.is_file():
            copy_file(path, dest / path.relative_to(src))


def replace_version_tokens(site: Path, version: str) -> None:
    replacements = {
        "{{HOVEL_VERSION}}": version,
        "{{HOVEL_RELEASE_TAG}}": "v" + version,
    }
    for path in site.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")


def copy_demo_outputs(repo: Path, site: Path) -> None:
    dest = site / "assets/demos"
    dest.mkdir(parents=True, exist_ok=True)
    manifest = resolve_runfile("demo/all_gif_manifest.txt")
    for output in [line.strip() for line in manifest.read_text().splitlines() if line.strip()]:
        src = repo / output
        if not src.is_file() or src.stat().st_size == 0:
            raise SystemExit(f"missing generated demo artifact: {output}\nrun task docs before staging docs")
        copy_file(src, dest / Path(output).name)


def resolve_runfile(path: str) -> Path:
    raw = Path(path)
    if raw.is_absolute() and raw.exists():
        return raw.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            candidate = Path(root) / prefix / path
            if candidate.exists():
                return candidate.resolve()
    candidate = Path.cwd() / path
    if candidate.exists():
        return candidate.resolve()
    raise SystemExit(f"missing runfile: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
