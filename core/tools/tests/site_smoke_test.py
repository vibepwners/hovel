#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
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
        if tag == "link" and "stylesheet" in (attributes.get("rel") or "").split():
            self.stylesheets.append(attributes.get("href") or "")
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

    parser = PageSmokeParser()
    parser.feed(path.read_text(encoding="utf-8"))
    if not normalized(parser.title_parts):
        return f"{path} is missing a non-empty <title>"
    if not normalized(parser.h1_parts):
        return f"{path} is missing a non-empty <h1>"
    if not parser.has_topbar:
        return f"{path} is missing the topbar header"
    if not parser.has_topnav:
        return f"{path} is missing the top navigation"
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
    return None


def main() -> int:
    for raw in sys.argv[1:]:
        failure = check_page(Path(raw))
        if failure is not None:
            print(f"site_smoke_test: {failure}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
