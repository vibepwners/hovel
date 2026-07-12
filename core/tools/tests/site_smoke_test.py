#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class Link:
    href: str
    text: list[str] = field(default_factory=list)


class PageSmokeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.has_main_content = False
        self.has_topbar = False
        self.has_topnav = False
        self.has_search_dialog = False
        self.has_search_trigger = False
        self.has_demo_carousel = False
        self.has_book_toc = False
        self.has_book_chapter_header = False
        self.has_module_directory = False
        self.has_module_document_header = False
        self.has_module_switcher = False
        self.chapter_number: str | None = None
        self.module_number: str | None = None
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.links: list[Link] = []
        self.title_parts: list[str] = []
        self.h1_parts: list[str] = []
        self._active_links: list[int] = []
        self._capture_title = False
        self._capture_h1 = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        if "content" in classes and tag == "main":
            self.has_main_content = True
        if "topbar" in classes and tag == "header":
            self.has_topbar = True
        if "top-nav" in classes and tag == "nav":
            self.has_topnav = True
        if "search-dialog" in classes and tag == "dialog":
            self.has_search_dialog = True
        if "docs-search-trigger" in classes and tag == "button":
            self.has_search_trigger = True
        if tag == "demo-carousel":
            self.has_demo_carousel = True
        if "book-toc" in classes:
            self.has_book_toc = True
        if "book-chapter-header" in classes:
            self.has_book_chapter_header = True
        if "module-directory" in classes:
            self.has_module_directory = True
        if "module-document-header" in classes:
            self.has_module_document_header = True
        if "module-switcher" in classes:
            self.has_module_switcher = True
        if tag == "main" and "book-chapter" in classes:
            self.chapter_number = attributes.get("data-chapter-number")
        if tag == "main" and "module-document" in classes:
            self.module_number = attributes.get("data-module-number")
        if tag == "link" and "stylesheet" in (attributes.get("rel") or "").split():
            self.stylesheets.append(attributes.get("href") or "")
        if tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"] or "")
        if tag == "a":
            self.links.append(Link(attributes.get("href") or ""))
            self._active_links.append(len(self.links) - 1)
        if tag == "title":
            self._capture_title = True
        if tag == "h1":
            self._capture_h1 = True

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            self.title_parts.append(data)
        if self._capture_h1:
            self.h1_parts.append(data)
        for index in self._active_links:
            self.links[index].text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._active_links:
            self._active_links.pop()
        if tag == "title":
            self._capture_title = False
        if tag == "h1":
            self._capture_h1 = False


def normalized(parts: list[str]) -> str:
    return " ".join("".join(parts).split())


def link_text(link: Link) -> str:
    return normalized(link.text)


def href_path(href: str) -> str:
    return urlsplit(href).path


def check_page(path: Path) -> str | None:
    if not path.is_file():
        return f"expected file not found: {path}"

    text = path.read_text(encoding="utf-8")
    if "{{HOVEL_VERSION}}" in text or "{{HOVEL_RELEASE_TAG}}" in text:
        return f"{path} contains an unresolved version token"

    parser = PageSmokeParser()
    parser.feed(text)
    if not normalized(parser.title_parts):
        return f"{path} is missing a non-empty <title>"
    if not normalized(parser.h1_parts):
        return f"{path} is missing a non-empty <h1>"
    if not parser.has_topbar:
        return f"{path} is missing the topbar header"
    if not parser.has_topnav:
        return f"{path} is missing the top navigation"
    if not parser.has_search_trigger or not parser.has_search_dialog:
        return f"{path} is missing the docs search controls"
    if not parser.has_main_content:
        return f"{path} is missing the main content landmark"
    if not any(href_path(href).endswith("assets/site.css") for href in parser.stylesheets):
        return f"{path} is missing the shared stylesheet link"
    if not any(
        link_text(link) == "Reports"
        and href_path(link.href).endswith("reports/tests/latest/index.html")
        for link in parser.links
    ):
        return f"{path} is missing the Reports navigation link"
    if path.as_posix().endswith("reports/tests/latest/index.html"):
        if not any(href_path(href).endswith("assets/report.css") for href in parser.stylesheets):
            return f"{path} is missing the report stylesheet"
        if not any(href_path(src).endswith("assets/report.js") for src in parser.scripts):
            return f"{path} is missing the report application script"
    if path.name == "index.html" and (path.parent / "search-index.json").is_file() and not parser.has_demo_carousel:
        return f"{path} is missing the homepage demo carousel"
    if path.parent.name == "spec" and path.name == "index.html" and not parser.has_book_toc:
        return f"{path} is missing the generated book contents"
    if "spec" in path.parts and path.name != "index.html":
        if not parser.has_book_chapter_header:
            return f"{path} is missing the generated chapter header"
        if parser.chapter_number is None or len(parser.chapter_number) != 2 or not parser.chapter_number.isdigit():
            return f"{path} has an invalid generated chapter number"
    if "modules" in path.parts:
        module_index = len(path.parts) - 1 - tuple(reversed(path.parts)).index("modules")
        module_route = path.parts[module_index + 1 :]
        if module_route in (("index.html",), ("catalogue.html",)):
            if not parser.has_module_directory:
                return f"{path} is missing the generated module directory"
        else:
            if not parser.has_module_document_header:
                return f"{path} is missing the generated module document header"
            if (
                parser.module_number is None
                or len(parser.module_number) != 5
                or parser.module_number[2] != "."
                or not parser.module_number.replace(".", "").isdigit()
            ):
                return f"{path} has an invalid generated module document number"
        if not parser.has_module_switcher:
            return f"{path} is missing module-switch navigation"
    return None


def check_search_index(site: Path) -> str | None:
    path = site / "search-index.json"
    if not path.is_file():
        return f"expected search index not found: {path}"
    try:
        documents = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        return f"{path} is not valid JSON: {error}"
    if not isinstance(documents, list) or not documents:
        return f"{path} must contain a non-empty document list"
    hrefs = [document.get("href") for document in documents if isinstance(document, dict)]
    if len(hrefs) != len(documents) or any(not isinstance(href, str) or not href for href in hrefs):
        return f"{path} contains an invalid document href"
    if len(set(hrefs)) != len(hrefs):
        return f"{path} contains duplicate document hrefs"
    return None


def main() -> int:
    for raw in sys.argv[1:]:
        path = Path(raw)
        pages = sorted(path.rglob("*.html")) if path.is_dir() else [path]
        if not pages:
            print(f"site_smoke_test: no HTML pages found under {path}", file=sys.stderr)
            return 1
        if path.is_dir() and not (path / "reports/tests/latest/index.html").is_file():
            print(f"site_smoke_test: report route is missing under {path}", file=sys.stderr)
            return 1
        if path.is_dir():
            for route in ("api/sdk/index.html", "api/sdk/go/index.html"):
                if not (path / route).is_file():
                    print(f"site_smoke_test: Astro-owned API route is missing: {route}", file=sys.stderr)
                    return 1
        if path.is_dir():
            failure = check_search_index(path)
            if failure is not None:
                print(f"site_smoke_test: {failure}", file=sys.stderr)
                return 1
        for page in pages:
            failure = check_page(page)
            if failure is not None:
                print(f"site_smoke_test: {failure}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
