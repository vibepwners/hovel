#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import os
import posixpath
import re
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ApiPage:
    title: str
    subtitle: str
    href: str
    description: str


PKGSITE_VERSION = "v0.2.0"
PKGSITE_PACKAGES = (
    (
        "Go SDK API: hovel",
        "github.com/Vibe-Pwners/hovel/sdk/go/hovel",
        "go/hovel/index.html",
        "go/github.com/Vibe-Pwners/hovel/sdk/go/hovel/index.html",
        "pkgsite snapshot for the primary Go SDK package.",
    ),
    (
        "Go SDK API: hoveltest",
        "github.com/Vibe-Pwners/hovel/sdk/go/hoveltest",
        "go/hoveltest/index.html",
        "go/github.com/Vibe-Pwners/hovel/sdk/go/hoveltest/index.html",
        "pkgsite snapshot for Go SDK test helpers.",
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate native SDK API reference pages.")
    parser.add_argument("--output", default="_site/api/sdk", type=Path)
    parser.add_argument("--site-root", default="_site", type=Path)
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()

    main_with_paths(
        repo_root=args.repo_root.resolve(),
        site_root=args.site_root.resolve(),
        output=args.output.resolve(),
    )


def main_with_paths(repo_root: Path, site_root: Path, output: Path) -> None:
    repo = repo_root.resolve()
    site_root = site_root.resolve()
    output = output.resolve()
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
                "--only-group",
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
    go_output = output / "go"
    with run_pkgsite(repo) as base_url:
        write_go_index(go_output / "index.html", site_root)
        for title, import_path, href, snapshot_href, description in PKGSITE_PACKAGES:
            snapshot_pkgsite_package(base_url, go_output, import_path)
            write_redirect(output / href, relative_href(output / href, output / snapshot_href), title)
            pages.append(ApiPage(title=title, subtitle=import_path, href=href, description=description))
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


@contextmanager
def run_pkgsite(repo: Path):
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="hovel-pkgsite-") as tmp:
        log_path = Path(tmp) / "pkgsite.log"
        with log_path.open("w+") as log:
            process = subprocess.Popen(
                [
                    "go",
                    "run",
                    f"golang.org/x/pkgsite/cmd/pkgsite@{PKGSITE_VERSION}",
                    f"-http=127.0.0.1:{port}",
                    "-list=false",
                ],
                cwd=repo,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                wait_for_pkgsite(base_url, process, log_path)
                yield base_url
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def wait_for_pkgsite(base_url: str, process: subprocess.Popen[str], log_path: Path) -> None:
    package_path = "/" + PKGSITE_PACKAGES[0][1]
    deadline = time.monotonic() + 120
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"pkgsite exited early:\n{log_path.read_text(errors='replace')}")
        try:
            fetch_url(base_url, package_path, timeout=10)
            return
        except (HTTPError, URLError, TimeoutError) as err:
            last_error = err
            time.sleep(1)
    raise RuntimeError(f"pkgsite did not become ready: {last_error}\n{log_path.read_text(errors='replace')}")


def snapshot_pkgsite_package(base_url: str, go_output: Path, import_path: str) -> None:
    page_path = "/" + import_path
    page_output = pkgsite_page_output(go_output, page_path)
    assets: set[str] = set()
    text = fetch_url(base_url, page_path).decode("utf-8")
    page_output.parent.mkdir(parents=True, exist_ok=True)
    page_output.write_text(rewrite_pkgsite_html(text, page_output, go_output, assets))
    snapshot_pkgsite_assets(base_url, go_output, assets)


def rewrite_pkgsite_html(text: str, page_output: Path, go_output: Path, assets: set[str]) -> str:
    def replace_attr(match: re.Match[str]) -> str:
        attr = match.group("attr")
        quote = match.group("quote")
        raw = match.group("url")
        return f"{attr}={quote}{rewrite_pkgsite_url(raw, page_output, go_output, assets)}{quote}"

    def replace_asset_literal(match: re.Match[str]) -> str:
        quote = match.group("quote")
        raw = match.group("path")
        target = urlsplit(raw)
        assets.add(target.path)
        rewritten = url_for_local_path(go_output / target.path.lstrip("/"), page_output, target.query, target.fragment)
        return f"{quote}{rewritten}{quote}"

    text = re.sub(r'(?P<attr>\b(?:href|src))=(?P<quote>["\'])(?P<url>[^"\']+)(?P=quote)', replace_attr, text)
    return re.sub(r'(?P<quote>["\'])(?P<path>/(?:static|third_party)/[^"\']+)(?P=quote)', replace_asset_literal, text)


def rewrite_pkgsite_url(raw: str, page_output: Path, go_output: Path, assets: set[str]) -> str:
    if raw.startswith("#"):
        return raw
    target = urlsplit(raw)
    if target.scheme or target.netloc:
        return raw
    if not target.path.startswith("/"):
        return raw

    path = target.path
    if is_pkgsite_asset_path(path):
        assets.add(path)
        return url_for_local_path(go_output / path.lstrip("/"), page_output, target.query, target.fragment)
    if path == "/":
        return url_for_local_path(go_output / "index.html", page_output, target.query, target.fragment)
    if is_hovel_go_package_path(path):
        return url_for_local_path(pkgsite_page_output(go_output, path), page_output, target.query, target.fragment)
    return urlunsplit(("https", "pkg.go.dev", path, target.query, target.fragment))


def snapshot_pkgsite_assets(base_url: str, go_output: Path, initial_assets: set[str]) -> None:
    seen: set[str] = set()
    pending = list(sorted(initial_assets))
    while pending:
        asset_path = pending.pop()
        if asset_path in seen:
            continue
        seen.add(asset_path)
        data = fetch_url(base_url, asset_path)
        output_path = go_output / asset_path.lstrip("/")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if asset_path.endswith(".css"):
            text, nested_assets = rewrite_pkgsite_css(data.decode("utf-8"), asset_path, output_path, go_output)
            pending.extend(sorted(nested_assets - seen))
            output_path.write_text(text)
        else:
            output_path.write_bytes(data)


def rewrite_pkgsite_css(text: str, asset_path: str, output_path: Path, go_output: Path) -> tuple[str, set[str]]:
    nested_assets: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        quote = match.group("quote") or ""
        raw = match.group("url").strip()
        target = urlsplit(raw)
        if target.scheme or target.netloc or raw.startswith("data:") or raw.startswith("#"):
            return match.group(0)
        if is_pkgsite_asset_path(target.path):
            nested_assets.add(target.path)
            rewritten = url_for_local_path(go_output / target.path.lstrip("/"), output_path, target.query, target.fragment)
            return f"url({quote}{rewritten}{quote})"
        if target.path:
            resolved_path = posixpath.normpath(posixpath.join(posixpath.dirname(asset_path), target.path))
            if not resolved_path.startswith("/"):
                resolved_path = "/" + resolved_path
            if is_pkgsite_asset_path(resolved_path):
                nested_assets.add(resolved_path)
        return match.group(0)

    pattern = r"url\((?P<quote>['\"]?)(?P<url>[^)'\"\s]+)(?P=quote)\)"
    return re.sub(pattern, replace, text), nested_assets


def fetch_url(base_url: str, path: str, *, timeout: int = 30) -> bytes:
    url = urljoin(base_url + "/", path.lstrip("/"))
    request = Request(url, headers={"User-Agent": "hovel-docs"})
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def pkgsite_page_output(go_output: Path, path: str) -> Path:
    return go_output / path.lstrip("/") / "index.html"


def is_hovel_go_package_path(path: str) -> bool:
    return path.startswith("/github.com/Vibe-Pwners/hovel/sdk/go/")


def is_pkgsite_asset_path(path: str) -> bool:
    return path.startswith("/static/") or path.startswith("/third_party/")


def url_for_local_path(target_path: Path, from_file: Path, query: str = "", fragment: str = "") -> str:
    return urlunsplit(("", "", relative_href(from_file, target_path), query, fragment))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
        "Sphinx autodoc for Python, pkgsite for Go, and rustdoc for Rust.</p>"
        '<div class="tiles">'
        + "\n".join(cards)
        + "</div>"
    )
    write_hovel_page(path, site_root, "SDK API Reference", body, current="API Docs")


def write_go_index(path: Path, site_root: Path) -> None:
    cards = []
    for title, import_path, _href, snapshot_href, description in PKGSITE_PACKAGES:
        cards.append(
            f'<a class="tile" href="{html.escape(snapshot_href.removeprefix("go/"))}">'
            '<span class="tile-label">Go</span>'
            f'<span class="tile-title">{html.escape(title)}</span>'
            f'<span class="tile-desc">{html.escape(import_path)}</span>'
            f'<span class="tile-desc">{html.escape(description)}</span>'
            "</a>"
        )
    body = (
        "<h1>Go SDK API</h1>"
        f"<p>This section is a static snapshot from pkgsite {html.escape(PKGSITE_VERSION)}, "
        "the local documentation server for pkg.go.dev-style Go package docs.</p>"
        '<div class="tiles">'
        + "\n".join(cards)
        + "</div>"
    )
    write_hovel_page(path, site_root, "Go SDK API", body, current="API Docs")


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
    path.parent.mkdir(parents=True, exist_ok=True)
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


def relative_href(from_path: Path, to_path: Path) -> str:
    return os.path.relpath(to_path, from_path.parent).replace(os.sep, "/")


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
