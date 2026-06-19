#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK_RE = re.compile(r'\b(?:href|src)="([^"]+)"')
EXTERNAL_SCHEMES = {"http", "https", "mailto", "tel"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check internal links in the staged docs site.")
    parser.add_argument("site_root", type=Path)
    args = parser.parse_args()

    site_root = args.site_root.resolve()
    missing: list[str] = []
    for page in sorted(site_root.rglob("*.html")):
        text = page.read_text()
        for raw in LINK_RE.findall(text):
            if "${" in raw:
                continue
            target = urlsplit(raw)
            if target.scheme in EXTERNAL_SCHEMES or raw.startswith("#"):
                continue
            if target.scheme or target.netloc:
                continue
            path = unquote(target.path)
            if not path:
                continue
            resolved = (site_root / path.lstrip("/")) if path.startswith("/") else (page.parent / path)
            if resolved.is_dir():
                resolved = resolved / "index.html"
            if not resolved.exists():
                missing.append(f"{page.relative_to(site_root)} -> {raw}")

    if missing:
        for item in missing:
            print(f"missing link: {item}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
