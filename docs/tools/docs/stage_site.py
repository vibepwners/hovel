#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
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
    source = repo / "docs/site"
    fingerprint = docs_fingerprint(repo)
    site = repo / "_site"
    stamp = site / ".hovel_docs_inputs.sha256"
    if stamp.exists() and (site / ".nojekyll").exists() and stamp.read_text().strip() == fingerprint:
        print("docs site is current: _site")
        return 0

    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    copy_file(source / "index.html", site / "index.html")
    copy_file(repo / "LICENSE", site / "LICENSE")
    copy_tree(source / "assets", site / "assets")
    copy_tree(source / "spec", site / "spec", ignore_names={"BUILD.bazel"})
    copy_tree(source / "modules", site / "modules", ignore_names={"BUILD.bazel"})
    replace_version_tokens(site, (repo / "VERSION").read_text().strip())
    missing_demo_assets = copy_demo_outputs(repo, site)
    remove_missing_demo_figures(site, missing_demo_assets)
    stage_test_report(repo, site)

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
        repo / "core/go.mod",
        repo / "core/go.sum",
        repo / "docs/site/index.html",
        repo / "sdk/python/pyproject.toml",
        repo / "sdk/python/uv.lock",
        repo / "docs/tools/docs/check_site_links.py",
        repo / "docs/tools/docs/generate_sdk_api_docs.py",
        repo / "docs/tools/docs/stage_site.py",
        resolve_first_runfile("docs/demo/all_gif_manifest.txt", "demo/all_gif_manifest.txt"),
    }
    for pattern in (
        "docs/site/assets/**/*",
        "docs/demo/out/*.gif",
        "sdk/go/**/*.go",
        "sdk/python/hovel_sdk/**/*.py",
        "sdk/rust/hovel/src/**/*.rs",
        "docs/site/spec/**/*.html",
        "docs/site/modules/**/*.html",
        "docs/tools/docs/python_api/**/*",
        ".test-report/site/**/*",
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


def copy_demo_outputs(repo: Path, site: Path) -> set[str]:
    dest = site / "assets/demos"
    dest.mkdir(parents=True, exist_ok=True)
    manifest = resolve_first_runfile("docs/demo/all_gif_manifest.txt", "demo/all_gif_manifest.txt")
    missing: set[str] = set()
    for output in [line.strip() for line in manifest.read_text().splitlines() if line.strip()]:
        src = repo / "docs" / output
        if not src.is_file():
            src = repo / output
        if not src.is_file() or src.stat().st_size == 0:
            missing.add(Path(output).name)
            continue
        copy_file(src, dest / Path(output).name)
    return missing


def remove_missing_demo_figures(site: Path, missing_demo_assets: set[str]) -> None:
    if not missing_demo_assets:
        return
    for page in site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        updated = text
        for asset in missing_demo_assets:
            updated = re.sub(
                r"\s*<figure\b[^>]*>\s*<img\b[^>]*assets/demos/"
                + re.escape(asset)
                + r"[^>]*>.*?</figure>",
                "",
                updated,
                flags=re.DOTALL,
            )
        if updated != text:
            page.write_text(updated, encoding="utf-8")


def stage_test_report(repo: Path, site: Path) -> None:
    dest = site / "reports/tests/latest"
    generated = repo / ".test-report/site"
    if generated.is_dir() and (generated / "index.html").is_file():
        copy_tree(generated, dest)
        return
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "index.html").write_text(
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Test Report - Hovel</title>
  <link rel="icon" type="image/png" href="../../../assets/hovel.png">
  <link rel="stylesheet" href="../../../assets/site.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="../../../index.html">
      <img src="../../../assets/hovel.png" alt="" class="brand-mark">
      <span class="brand-name">HOVEL</span>
      <span class="brand-tag">// test report</span>
    </a>
    <nav class="top-nav">
      <a href="../../../index.html">Home</a>
      <a href="../../../spec/index.html">Book</a>
      <a href="../../../api/sdk/index.html">API Docs</a>
      <a href="index.html" aria-current="page">Reports</a>
      <a href="https://github.com/Vibe-Pwners/hovel">Source</a>
    </nav>
  </header>
  <main class="content" style="max-width: 920px; margin: 0 auto;">
    <h1>Test Report</h1>
    <p>No generated test report artifact was present when this docs site was staged.</p>
    <pre data-lang="bash"><code>task test:report
task docs:stage</code></pre>
  </main>
  <footer class="sitefoot">
    <p>Hovel test report · <a href="../../../index.html">home</a> · <a href="https://github.com/Vibe-Pwners/hovel">source</a></p>
  </footer>
</body>
</html>
""",
        encoding="utf-8",
    )


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
