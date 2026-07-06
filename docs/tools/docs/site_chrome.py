from __future__ import annotations

import html
import re
from pathlib import Path


SOURCE_URL = "https://github.com/Vibe-Pwners/hovel"

BOOK_NAV = [
    (
        "Book",
        [
            ("Contents", "index.html"),
            ("User Guide", "user-guide.html"),
            ("Introduction", "introduction.html"),
            ("Safety and Scope", "safety.html"),
            ("Architecture", "architecture.html"),
            ("Domain Model", "domain-model.html"),
            ("Modules and Services", "modules-services.html"),
            ("Providers, Artifacts, Logging", "providers-artifacts.html"),
            ("Operations, Chains, Throws", "chains-runs.html"),
            ("Operator Workflows", "operator-workflows.html"),
            ("Front Ends", "front-ends.html"),
            ("UI Components", "ui-components.html"),
            ("MCP and Agent Operation", "mcp-agent.html"),
            ("Configuration & Distribution", "configuration-distribution.html"),
            ("Testing Strategy", "testing-roadmap.html"),
            ("Development Guide", "development-guide.html"),
            ("Squatter Payload Provider", "squatter-payload-provider.html"),
        ],
    ),
    (
        "Reference",
        [
            ("Daemon RPC", "daemon-rpc.html"),
            ("Descriptors & Schemas", "reference/descriptors.html"),
        ],
    ),
    (
        "Module Development",
        [
            ("Overview", "module-development.html"),
            ("Wire Protocol", "module-protocol.html"),
            ("Python Modules", "module-python.html"),
            ("Go Modules", "module-go.html"),
            ("Rust Modules", "module-rust.html"),
            ("Case Study: MS17-010", "module-ms17-010.html"),
        ],
    ),
]

MODULE_ROOT_LINKS = [
    ("Overview", "index.html"),
    ("Catalogue", "catalogue.html"),
]

MODULE_SECTIONS = [
    (
        "Payload Providers",
        [
            {
                "label": "picblobs",
                "href": "picblobs/index.html",
                "prefix": "picblobs/",
                "pages": [
                    ("Overview", "picblobs/index.html"),
                    ("User Guide", "picblobs/user-guide.html"),
                    ("Building", "picblobs/building.html"),
                    ("Testing", "picblobs/testing.html"),
                    ("Reference", "picblobs/reference.html"),
                    ("Full Guide", "picblobs/guide/index.html"),
                    ("Introduction", "picblobs/guide/introduction.html"),
                    ("How It Works", "picblobs/guide/how-it-works.html"),
                    ("Getting Started", "picblobs/guide/getting-started.html"),
                    ("Building Blobs", "picblobs/guide/building.html"),
                    ("Running Blobs", "picblobs/guide/running.html"),
                    ("picblobs CLI", "picblobs/guide/picblobs-cli.html"),
                    ("Writing a Blob", "picblobs/guide/writing-blobs.html"),
                    ("Code Generation", "picblobs/guide/code-generation.html"),
                    ("Adding an Architecture", "picblobs/guide/adding-architecture.html"),
                    ("Adding a Syscall", "picblobs/guide/adding-syscall.html"),
                    ("Formatting", "picblobs/guide/formatting.html"),
                    ("Platform Support", "picblobs/guide/platform-support.html"),
                    ("Test Runners", "picblobs/guide/test-runners.html"),
                    ("Project Structure", "picblobs/guide/project-structure.html"),
                    ("Kernel Toolkit", "picblobs/guide/kernel-toolkit.html"),
                    ("Specification", "picblobs/guide/specification.html"),
                ],
            },
        ],
    ),
]


def relative_prefix(path: Path, site_root: Path) -> str:
    depth = len(path.relative_to(site_root).parents) - 1
    return "../" * depth


def section_for_path(path: Path, site_root: Path) -> str:
    rel = path.relative_to(site_root)
    if rel.parts[:1] == ("api",):
        return "API Docs"
    if rel.parts[:1] == ("modules",):
        return "Modules"
    if rel.parts[:1] == ("reports",):
        return "Reports"
    if rel.parts[:1] == ("spec",):
        return "Book"
    return "Home"


def top_nav_html(root: str, current: str) -> str:
    links = [
        ("Home", f"{root}index.html"),
        ("Book", f"{root}spec/index.html"),
        ("Modules", f"{root}modules/index.html"),
        ("API Docs", f"{root}api/sdk/index.html"),
        ("Reports", f"{root}reports/tests/latest/index.html"),
        ("Source", SOURCE_URL),
    ]
    return "\n".join(
        f'      <a href="{href}"{" aria-current=\"page\"" if label == current else ""}>{html.escape(label)}</a>'
        for label, href in links
    )


def topbar_html(root: str, current: str, brand_tag: str) -> str:
    return f"""  <header class="topbar">
    <a class="brand" href="{root}index.html">
      <img src="{root}assets/hovel.png" alt="" class="brand-mark">
      <span class="brand-name">HOVEL</span>
      <span class="brand-tag">{html.escape(brand_tag)}</span>
    </a>
    <nav class="top-nav">
{top_nav_html(root, current)}
    </nav>
  </header>"""


def book_prefix(path: Path, site_root: Path) -> str:
    rel = path.relative_to(site_root)
    if rel.parts[:1] != ("spec",):
        return ""
    nested_dirs = max(0, len(rel.parts) - 2)
    return "../" * nested_dirs


def book_sidebar_html(path: Path, site_root: Path) -> str:
    prefix = book_prefix(path, site_root)
    rel = path.relative_to(site_root)
    active = "/".join(rel.parts[1:]) if rel.parts[:1] == ("spec",) else ""
    sections = ['    <aside class="sidebar">']
    for title, links in BOOK_NAV:
        sections.append(f'      <p class="sidebar-section">{html.escape(title)}</p>')
        sections.append("      <ul>")
        for label, href in links:
            current = ' aria-current="page"' if href == active else ""
            sections.append(
                f'        <li><a href="{prefix}{href}"{current}>{html.escape(label)}</a></li>'
            )
        sections.append("      </ul>")
    sections.append("    </aside>")
    return "\n".join(sections)


def module_prefix(path: Path, site_root: Path) -> str:
    rel = path.relative_to(site_root)
    if rel.parts[:1] != ("modules",):
        return ""
    nested_dirs = max(0, len(rel.parts) - 2)
    return "../" * nested_dirs


def module_sidebar_html(path: Path, site_root: Path) -> str:
    prefix = module_prefix(path, site_root)
    rel = path.relative_to(site_root)
    active = "/".join(rel.parts[1:]) if rel.parts[:1] == ("modules",) else ""
    sections = ['    <aside class="sidebar">']
    sections.append('      <p class="sidebar-section">Modules</p>')
    sections.append("      <ul>")
    for label, href in MODULE_ROOT_LINKS:
        current = ' aria-current="page"' if href == active else ""
        sections.append(
            f'        <li><a href="{prefix}{href}"{current}>{html.escape(label)}</a></li>'
        )
    sections.append("      </ul>")
    for title, modules in MODULE_SECTIONS:
        sections.append(f'      <p class="sidebar-section">{html.escape(title)}</p>')
        sections.append("      <ul>")
        for module in modules:
            label = module["label"]
            href = module["href"]
            module_active = active.startswith(module["prefix"])
            current = ' aria-current="page"' if href == active else ""
            open_attr = " open" if module_active else ""
            sections.append("        <li>")
            sections.append(f'          <details class="module-nav"{open_attr}>')
            sections.append(
                f'            <summary><a href="{prefix}{href}"{current}>{html.escape(label)}</a></summary>'
            )
            sections.append('            <ul class="sidebar-nested">')
            for page_label, page_href in module["pages"]:
                page_current = ' aria-current="page"' if page_href == active else ""
                sections.append(
                    f'              <li><a href="{prefix}{page_href}"{page_current}>{html.escape(page_label)}</a></li>'
                )
            sections.append("            </ul>")
            sections.append("          </details>")
            sections.append("        </li>")
        sections.append("      </ul>")
    sections.append("    </aside>")
    return "\n".join(sections)


def normalize_top_navs(site_root: Path) -> None:
    for path in site_root.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        root = relative_prefix(path, site_root)
        current = section_for_path(path, site_root)
        updated = re.sub(
            r"    <nav class=\"top-nav\">\s*.*?\s*    </nav>",
            "    <nav class=\"top-nav\">\n" + top_nav_html(root, current) + "\n    </nav>",
            text,
            flags=re.DOTALL,
        )
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def normalize_book_sidebars(site_root: Path) -> None:
    for path in (site_root / "spec").rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        updated = re.sub(
            r"    <aside class=\"sidebar\">\s*.*?\s*    </aside>",
            book_sidebar_html(path, site_root),
            text,
            count=1,
            flags=re.DOTALL,
        )
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def normalize_module_sidebars(site_root: Path) -> None:
    modules_root = site_root / "modules"
    if not modules_root.is_dir():
        return
    for path in modules_root.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        updated = re.sub(
            r"    <aside class=\"sidebar\">\s*.*?\s*    </aside>",
            module_sidebar_html(path, site_root),
            text,
            count=1,
            flags=re.DOTALL,
        )
        if updated != text:
            path.write_text(updated, encoding="utf-8")
