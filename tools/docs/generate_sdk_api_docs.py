#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True)
class ApiPage:
    title: str
    subtitle: str
    href: str
    description: str


GO_PACKAGES = (
    (
        "Go SDK API: hovel",
        "github.com/Vibe-Pwners/hovel/sdk/go/hovel",
        "go/hovel/index.html",
        "Official go doc output for the primary Go SDK package.",
    ),
    (
        "Go SDK API: hoveltest",
        "github.com/Vibe-Pwners/hovel/sdk/go/hoveltest",
        "go/hoveltest/index.html",
        "Official go doc output for Go SDK test helpers.",
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate native SDK API reference pages.")
    parser.add_argument("--output", default="_site/api/sdk", type=Path)
    parser.add_argument("--site-root", default="_site", type=Path)
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()

    repo = args.repo_root.resolve()
    site_root = args.site_root.resolve()
    output = args.output.resolve()

    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    pages = [
        generate_python_docs(repo, output),
        *generate_go_docs(repo, site_root, output),
        generate_rust_docs(repo, output),
    ]
    write_index(output / "index.html", site_root, pages)


def generate_python_docs(repo: Path, output: Path) -> ApiPage:
    source = repo / "tools/docs/python_api"
    with tempfile.TemporaryDirectory(prefix="hovel-sphinx-doctrees-") as doctrees:
        run(
            [
                "uv",
                "run",
                "--project",
                str(repo / "sdk/python"),
                "--group",
                "docs",
                "sphinx-build",
                "-W",
                "--keep-going",
                "-b",
                "html",
                "-d",
                doctrees,
                str(source),
                str(output / "python"),
            ],
            cwd=repo,
            env={"HOVEL_DOCS_REPO_ROOT": str(repo)},
        )
    return ApiPage(
        title="Python SDK API",
        subtitle="hovel_sdk",
        href="python/index.html",
        description="Sphinx autodoc output from the importable Python SDK package.",
    )


def generate_go_docs(repo: Path, site_root: Path, output: Path) -> list[ApiPage]:
    pages: list[ApiPage] = []
    for title, import_path, href, description in GO_PACKAGES:
        text = run(["go", "doc", "-all", import_path], cwd=repo, capture=True)
        page = ApiPage(title=title, subtitle=import_path, href=href, description=description)
        write_go_doc_page(output / href, site_root, page, text)
        pages.append(page)
    return pages


def generate_rust_docs(repo: Path, output: Path) -> ApiPage:
    rust_output = output / "rust"
    rust_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hovel-rustdoc-") as tmp:
        tmp_output = Path(tmp) / "doc"
        run(
            [
                "rustdoc",
                "--crate-name",
                "hovel",
                "--edition=2021",
                str(repo / "sdk/rust/hovel/src/lib.rs"),
                "-o",
                str(tmp_output),
            ],
            cwd=repo,
        )
        copy_tree_contents(tmp_output, rust_output)
    (rust_output / ".lock").unlink(missing_ok=True)
    write_redirect(rust_output / "index.html", "hovel/index.html", "Hovel Rust SDK API")
    write_missing_rustdoc_implementor_files(rust_output)
    return ApiPage(
        title="Rust SDK API",
        subtitle="crate hovel",
        href="rust/hovel/index.html",
        description="rustdoc output from the Rust SDK crate root.",
    )


def write_index(path: Path, site_root: Path, pages: list[ApiPage]) -> None:
    cards = []
    for page in pages:
        cards.append(
            f'<a class="tile" href="{html.escape(page.href)}">'
            f'<span class="tile-label">API</span>'
            f'<span class="tile-title">{html.escape(page.title)}</span>'
            f'<span class="tile-desc">{html.escape(page.subtitle)}</span>'
            f'<span class="tile-desc">{html.escape(page.description)}</span>'
            "</a>"
        )
    body = (
        "<h1>SDK API Reference</h1>"
        "<p>These pages are generated with each SDK language's documentation tooling: "
        "Sphinx autodoc for Python, go doc for Go, and rustdoc for Rust.</p>"
        '<div class="tiles">'
        + "\n".join(cards)
        + "</div>"
    )
    write_hovel_page(path, site_root, "SDK API Reference", body, current="API Docs")


def write_go_doc_page(path: Path, site_root: Path, page: ApiPage, doc_text: str) -> None:
    body = (
        f"<h1>{html.escape(page.title)}</h1>"
        f"<p>{html.escape(page.description)}</p>"
        "<p>"
        f'<a class="cta ghost" href="https://pkg.go.dev/{html.escape(page.subtitle)}">pkg.go.dev</a> '
        '<a class="cta ghost" href="../../../../spec/module-go.html">Guide</a>'
        "</p>"
        f"<p><strong>Import path:</strong> <code>{html.escape(page.subtitle)}</code></p>"
        f'<pre data-lang="go doc"><code>{html.escape(doc_text)}</code></pre>'
    )
    write_hovel_page(path, site_root, page.title, body, current="API Docs")


def write_hovel_page(path: Path, site_root: Path, title: str, body: str, *, current: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    root = relative_prefix(path, site_root)
    nav = [
        ("Home", f"{root}index.html"),
        ("Spec", f"{root}spec/index.html"),
        ("API Docs", f"{root}api/sdk/index.html"),
        ("Source", "https://github.com/Vibe-Pwners/hovel"),
    ]
    nav_html = "\n".join(
        f'<a href="{href}"{" aria-current=\"page\"" if label == current else ""}>{html.escape(label)}</a>'
        for label, href in nav
    )
    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} - Hovel SDK API</title>
  <link rel="icon" type="image/png" href="{root}assets/hovel.png">
  <link rel="stylesheet" href="{root}assets/site.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="{root}index.html">
      <img src="{root}assets/hovel.png" alt="" class="brand-mark">
      <span class="brand-name">HOVEL</span>
      <span class="brand-tag">// api</span>
    </a>
    <nav class="top-nav">
      {nav_html}
    </nav>
  </header>
  <main class="content" style="max-width: 1040px; margin: 0 auto;">
    {body}
  </main>
  <footer class="sitefoot">
    <p>Hovel SDK API · generated from native documentation tools · <a href="{root}spec/module-development.html">module docs</a></p>
  </footer>
</body>
</html>
"""
    path.write_text(html_text)


def write_redirect(path: Path, target: str, title: str) -> None:
    path.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url={html.escape(target)}">
  <title>{html.escape(title)}</title>
</head>
<body>
  <p><a href="{html.escape(target)}">{html.escape(title)}</a></p>
</body>
</html>
"""
    )


def write_missing_rustdoc_implementor_files(rust_output: Path) -> None:
    for page in rust_output.rglob("*.html"):
        text = page.read_text()
        for raw in re.findall(r'<script\s+src="([^"]*trait\.impl/[^"]+\.js)"', text):
            target = urlsplit(raw)
            if target.scheme or target.netloc:
                continue
            path = unquote(target.path)
            resolved = (page.parent / path).resolve()
            try:
                resolved.relative_to(rust_output.resolve())
            except ValueError:
                continue
            if resolved.exists():
                continue
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text("const implementors = Object.fromEntries([]);\n")


def copy_tree_contents(source: Path, dest: Path) -> None:
    for child in source.iterdir():
        target = dest / child.name
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=True)
        else:
            shutil.copy2(child, target)


def relative_prefix(path: Path, site_root: Path) -> str:
    rel = os.path.relpath(site_root, path.parent)
    if rel == ".":
        return ""
    return rel.replace(os.sep, "/").rstrip("/") + "/"


def run(
    args: list[str],
    *,
    cwd: Path,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> str:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    completed = subprocess.run(
        args,
        cwd=cwd,
        env=process_env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout if capture else ""


if __name__ == "__main__":
    main()
