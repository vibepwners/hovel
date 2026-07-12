#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

GO_PACKAGES = (
    (
        "Go SDK API: hovel",
        "github.com/Vibe-Pwners/hovel/sdk/go/hovel",
        "sdk/go/hovel",
        "go/hovel/index.html",
        "go/github.com/Vibe-Pwners/hovel/sdk/go/hovel/index.html",
    ),
    (
        "Go SDK API: hoveltest",
        "github.com/Vibe-Pwners/hovel/sdk/go/hoveltest",
        "sdk/go/hoveltest",
        "go/hoveltest/index.html",
        "go/github.com/Vibe-Pwners/hovel/sdk/go/hoveltest/index.html",
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate native SDK API reference pages.")
    parser.add_argument("--output", default="_site/api/sdk", type=Path)
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--sphinx-bin", required=True, type=Path)
    parser.add_argument("--go-doc-bin", required=True, type=Path)
    parser.add_argument("--rustdoc-bin", default=None, type=Path)
    args = parser.parse_args()

    main_with_paths(
        repo_root=args.repo_root.resolve(),
        output=args.output.resolve(),
        sphinx_bin=args.sphinx_bin.resolve(),
        go_doc_bin=args.go_doc_bin.resolve(),
        rustdoc_bin=args.rustdoc_bin.resolve() if args.rustdoc_bin else None,
    )


def main_with_paths(
    repo_root: Path,
    output: Path,
    *,
    sphinx_bin: Path,
    go_doc_bin: Path,
    rustdoc_bin: Path | None = None,
) -> None:
    repo = repo_root.resolve()
    output = output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    generate_python_docs(repo, output, sphinx_bin=sphinx_bin)
    generate_go_docs(repo, output, go_doc_bin=go_doc_bin)
    generate_rust_docs(repo, output, rustdoc_bin=rustdoc_bin)


def generate_python_docs(repo: Path, output: Path, *, sphinx_bin: Path) -> None:
    source = repo / "docs/tools/docs/python_api"
    with tempfile.TemporaryDirectory(prefix="hovel-sphinx-doctrees-") as doctrees:
        run(
            [
                str(sphinx_bin),
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
            env={
                "HOVEL_DOCS_REPO_ROOT": str(repo),
                "PYTHONHASHSEED": "0",
                "SOURCE_DATE_EPOCH": "0",
            },
        )


def generate_go_docs(repo: Path, output: Path, *, go_doc_bin: Path) -> None:
    go_output = output / "go"
    command = [str(go_doc_bin), "--output", str(go_output)]
    for title, import_path, source_dir, _, snapshot_href in GO_PACKAGES:
        command.extend(("--package", f"{title}|{import_path}|{repo / source_dir}|{snapshot_href.removeprefix('go/')}"))
    run(command, cwd=repo)
    for title, _, _, href, snapshot_href in GO_PACKAGES:
        write_redirect(output / href, relative_href(output / href, output / snapshot_href), title)


def generate_rust_docs(repo: Path, output: Path, *, rustdoc_bin: Path | None = None) -> None:
    rust_output = output / "rust"
    rust_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hovel-rustdoc-") as tmp:
        tmp_output = Path(tmp) / "doc"
        run(
            [
                str(rustdoc_bin or "rustdoc"),
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
    dest.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        target = dest / child.name
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=True)
        else:
            shutil.copy2(child, target)


def relative_href(from_path: Path, to_path: Path) -> str:
    return os.path.relpath(to_path, from_path.parent).replace(os.sep, "/")


def run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> None:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    subprocess.run(
        args,
        cwd=cwd,
        env=process_env,
        check=True,
        text=True,
    )


if __name__ == "__main__":
    main()
