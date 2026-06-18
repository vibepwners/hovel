#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import html
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ApiItem:
    kind: str
    name: str
    signature: str
    doc: str
    source: str
    line: int
    children: tuple["ApiItem", ...] = ()


@dataclass(frozen=True)
class ApiPage:
    title: str
    subtitle: str
    output: Path
    items: tuple[ApiItem, ...] = ()
    intro: str = ""
    source_root: str = ""
    links: tuple[tuple[str, str], ...] = ()


EXPORT_RE = re.compile(r'^__all__\s*=\s*\[(?P<body>.*?)\]', re.S)
GO_TYPE_RE = re.compile(r"^type\s+([A-Z]\w*)\b(.*)$")
GO_FUNC_RE = re.compile(r"^func\s+(?P<receiver>\([^)]*\)\s*)?(?P<name>[A-Z]\w*)\b(?P<tail>.*)$")
GO_CONST_RE = re.compile(r"^([A-Z]\w*)\b(?:\s+[\w\[\]\*\.]+)?\s*=")
RUST_ITEM_RE = re.compile(r"^pub\s+(?:enum|struct|trait|type)\s+([A-Za-z]\w*)\b(.*)$")
RUST_FN_RE = re.compile(r"^pub\s+fn\s+([A-Za-z_]\w*)\b(.*)$")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate source-derived SDK API reference pages.")
    parser.add_argument("--output", default="_site/api/sdk", type=Path)
    parser.add_argument("--site-root", default="_site", type=Path)
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()

    repo = args.repo_root.resolve()
    site_root = args.site_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    pages = [
        python_page(repo, output),
        go_page(repo, output, "hovel", repo / "sdk/go/hovel", output / "go/hovel/index.html"),
        go_page(repo, output, "hoveltest", repo / "sdk/go/hoveltest", output / "go/hoveltest/index.html"),
        rust_page(repo, output),
    ]
    for page in pages:
        write_api_page(page, site_root)
    write_index(output / "index.html", site_root, pages)


def python_page(repo: Path, output: Path) -> ApiPage:
    package = repo / "sdk/python/hovel_sdk"
    exports = parse_python_exports(package / "__init__.py")
    items: list[ApiItem] = []
    for path in sorted(package.glob("*.py")):
        if path.name == "sdk_test.py":
            continue
        items.extend(parse_python_file(repo, path, exports))
    items.sort(key=lambda item: (item.kind, item.name))
    return ApiPage(
        title="Python SDK API",
        subtitle="hovel_sdk",
        output=output / "python/index.html",
        source_root="sdk/python/hovel_sdk",
        intro=(
            "Source-derived reference for the public Python module SDK. "
            "The prose guide explains lifecycle rules; this page keeps the callable surface visible."
        ),
        links=(("Guide", "../../../spec/module-python.html"),),
        items=tuple(items),
    )


def parse_python_exports(init_file: Path) -> set[str]:
    source = init_file.read_text()
    match = EXPORT_RE.search(source.replace("\n", " "))
    if not match:
        return set()
    return set(re.findall(r'"([^"]+)"', match.group("body")))


def parse_python_file(repo: Path, path: Path, exports: set[str]) -> list[ApiItem]:
    tree = ast.parse(path.read_text(), filename=str(path))
    module_name = "hovel_sdk" if path.stem == "__init__" else f"hovel_sdk.{path.stem}"
    items: list[ApiItem] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and is_public_python(node.name, exports):
            methods = []
            for member in node.body:
                if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef) and is_public_member(member.name):
                    methods.append(
                        ApiItem(
                            kind="method",
                            name=f"{node.name}.{member.name}",
                            signature=f"{member.name}{python_arguments(member.args)}",
                            doc=docstring(member),
                            source=rel(repo, path),
                            line=member.lineno,
                        )
                    )
            bases = ", ".join(ast.unparse(base) for base in node.bases) or "object"
            items.append(
                ApiItem(
                    kind="class",
                    name=f"{module_name}.{node.name}",
                    signature=f"class {node.name}({bases})",
                    doc=docstring(node),
                    source=rel(repo, path),
                    line=node.lineno,
                    children=tuple(methods),
                )
            )
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and is_public_python(node.name, exports):
            prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
            items.append(
                ApiItem(
                    kind="function",
                    name=f"{module_name}.{node.name}",
                    signature=f"{prefix}def {node.name}{python_arguments(node.args)}",
                    doc=docstring(node),
                    source=rel(repo, path),
                    line=node.lineno,
                )
            )
    return items


def is_public_python(name: str, exports: set[str]) -> bool:
    return name in exports


def is_public_member(name: str) -> bool:
    return not name.startswith("_")


def python_arguments(args: ast.arguments) -> str:
    names = [arg.arg for arg in [*args.posonlyargs, *args.args]]
    if args.vararg is not None:
        names.append(f"*{args.vararg.arg}")
    if args.kwonlyargs:
        if args.vararg is None:
            names.append("*")
        names.extend(arg.arg for arg in args.kwonlyargs)
    if args.kwarg is not None:
        names.append(f"**{args.kwarg.arg}")
    return f"({', '.join(names)})"


def go_page(repo: Path, output: Path, package: str, source_dir: Path, page_path: Path) -> ApiPage:
    items: list[ApiItem] = []
    for path in sorted(source_dir.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        items.extend(parse_go_file(repo, path))
    items.sort(key=lambda item: (item.kind, item.name))
    return ApiPage(
        title=f"Go SDK API: {package}",
        subtitle=f"github.com/Vibe-Pwners/hovel/sdk/go/{package}",
        output=page_path,
        source_root=rel(repo, source_dir),
        intro="Source-derived reference from exported Go declarations and doc comments.",
        links=(("Guide", "../../../../spec/module-go.html"),),
        items=tuple(items),
    )


def parse_go_file(repo: Path, path: Path) -> list[ApiItem]:
    lines = path.read_text().splitlines()
    items: list[ApiItem] = []
    comments: list[str] = []
    in_const_block = False
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            comments.append(stripped[2:].strip())
            continue
        if stripped == "":
            comments = []
            continue
        if stripped.startswith("const ("):
            in_const_block = True
            comments = []
            continue
        if in_const_block:
            if stripped == ")":
                in_const_block = False
                comments = []
                continue
            match = GO_CONST_RE.match(stripped)
            if match:
                items.append(go_item("const", match.group(1), stripped, comments, repo, path, idx))
            comments = []
            continue
        for kind, pattern in (("type", GO_TYPE_RE), ("func", GO_FUNC_RE)):
            match = pattern.match(stripped)
            if match:
                if kind == "func":
                    receiver = match.group("receiver") or ""
                    name = match.group("name")
                    receiver_type = go_receiver_type(receiver)
                    if receiver and not is_go_exported(receiver_type):
                        break
                    if receiver_type:
                        items.append(go_item("method", f"{receiver_type}.{name}", stripped, comments, repo, path, idx))
                    else:
                        items.append(go_item(kind, name, stripped, comments, repo, path, idx))
                else:
                    items.append(go_item(kind, match.group(1), stripped, comments, repo, path, idx))
                break
        comments = []
    return items


def go_receiver_type(receiver: str) -> str:
    if not receiver:
        return ""
    inner = receiver.strip()[1:-1].strip()
    if not inner:
        return ""
    type_name = inner.split()[-1].lstrip("*")
    return type_name.split(".")[-1]


def is_go_exported(name: str) -> bool:
    return bool(name and name[0].isupper())


def go_item(kind: str, name: str, signature: str, comments: list[str], repo: Path, path: Path, line: int) -> ApiItem:
    return ApiItem(
        kind=kind,
        name=name,
        signature=signature,
        doc="\n".join(comments).strip(),
        source=rel(repo, path),
        line=line,
    )


def rust_page(repo: Path, output: Path) -> ApiPage:
    source_dir = repo / "sdk/rust/hovel/src"
    items: list[ApiItem] = []
    for path in sorted(source_dir.glob("*.rs")):
        if path.name == "tests.rs":
            continue
        items.extend(parse_rust_file(repo, path))
    items.sort(key=lambda item: (item.kind, item.name))
    return ApiPage(
        title="Rust SDK API",
        subtitle="crate hovel",
        output=output / "rust/hovel/index.html",
        source_root="sdk/rust/hovel/src",
        intro="Source-derived reference from public Rust items and doc comments.",
        links=(("Guide", "../../../../spec/module-rust.html"),),
        items=tuple(items),
    )


def parse_rust_file(repo: Path, path: Path) -> list[ApiItem]:
    lines = path.read_text().splitlines()
    items: list[ApiItem] = []
    comments: list[str] = []
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("///"):
            comments.append(stripped[3:].strip())
            continue
        if stripped.startswith("//!") or stripped == "" or stripped.startswith("#["):
            continue
        match = RUST_ITEM_RE.match(stripped)
        kind = "item"
        if match is None:
            match = RUST_FN_RE.match(stripped)
            kind = "fn"
        else:
            kind = stripped.split()[1]
        if match:
            items.append(
                ApiItem(
                    kind=kind,
                    name=match.group(1),
                    signature=stripped,
                    doc="\n".join(comments).strip(),
                    source=rel(repo, path),
                    line=idx,
                )
            )
        comments = []
    return items


def write_index(path: Path, site_root: Path, pages: Iterable[ApiPage]) -> None:
    cards = []
    for page in pages:
        cards.append(
            f'<a class="tile" href="{html.escape(page_href(path, page.output))}">'
            f'<span class="tile-label">API</span>'
            f'<span class="tile-title">{html.escape(page.title)}</span>'
            f'<span class="tile-desc">{html.escape(page.subtitle)}</span>'
            "</a>"
        )
    body = (
        "<h1>SDK API Reference</h1>"
        "<p>These pages are generated from SDK source during the documentation build. "
        "Edit source doc comments and docstrings, then run <code>task docs</code>.</p>"
        '<div class="tiles">'
        + "\n".join(cards)
        + "</div>"
    )
    write_html(path, site_root, "SDK API Reference", body, current="API Docs")


def write_api_page(page: ApiPage, site_root: Path) -> None:
    parts = [f"<h1>{html.escape(page.title)}</h1>"]
    if page.intro:
        parts.append(f"<p>{html.escape(page.intro)}</p>")
    if page.links:
        links = " ".join(f'<a class="cta ghost" href="{href}">{html.escape(label)}</a>' for label, href in page.links)
        parts.append(f"<p>{links}</p>")
    parts.append(f"<p><strong>Source:</strong> <code>{html.escape(page.source_root)}</code></p>")
    current_kind = ""
    for item in page.items:
        if item.kind != current_kind:
            current_kind = item.kind
            parts.append(f"<h2>{html.escape(item.kind.title())}</h2>")
        parts.append(render_item(item))
    write_html(page.output, site_root, page.title, "\n".join(parts), current="API Docs")


def render_item(item: ApiItem) -> str:
    doc = markdownish(item.doc) if item.doc else "<p>No source documentation yet.</p>"
    children = ""
    if item.children:
        children = "<h4>Methods</h4>" + "\n".join(render_child(child) for child in item.children)
    return (
        '<section class="api-item">'
        f"<h3>{html.escape(item.name)}</h3>"
        f'<pre data-lang="{html.escape(item.kind)}"><code>{html.escape(item.signature)}</code></pre>'
        f"{doc}"
        f'<p class="api-source"><code>{html.escape(item.source)}:{item.line}</code></p>'
        f"{children}"
        "</section>"
    )


def render_child(item: ApiItem) -> str:
    doc = markdownish(item.doc) if item.doc else "<p>No source documentation yet.</p>"
    return (
        '<section class="api-member">'
        f"<h4>{html.escape(item.name)}</h4>"
        f'<pre data-lang="{html.escape(item.kind)}"><code>{html.escape(item.signature)}</code></pre>'
        f"{doc}"
        f'<p class="api-source"><code>{html.escape(item.source)}:{item.line}</code></p>'
        "</section>"
    )


def markdownish(text: str) -> str:
    paragraphs = [paragraph.strip() for paragraph in text.split("\n\n") if paragraph.strip()]
    return "".join(f"<p>{html.escape(paragraph).replace(chr(10), '<br>')}</p>" for paragraph in paragraphs)


def write_html(path: Path, site_root: Path, title: str, body: str, *, current: str) -> None:
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
    <p>Hovel SDK API · generated from source · <a href="{root}spec/module-development.html">module docs</a></p>
  </footer>
</body>
</html>
"""
    path.write_text(html_text)


def relative_prefix(path: Path, site_root: Path) -> str:
    rel = os.path.relpath(site_root, path.parent)
    if rel == ".":
        return ""
    return rel.replace(os.sep, "/").rstrip("/") + "/"


def page_href(from_path: Path, to_path: Path) -> str:
    return os.path.relpath(to_path, from_path.parent).replace(os.sep, "/")


def docstring(node: ast.AST) -> str:
    return ast.get_docstring(node) or ""


def rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


if __name__ == "__main__":
    main()
