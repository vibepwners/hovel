#!/usr/bin/env python3
"""Serve Picblobs static docs from the workspace checkout."""

from __future__ import annotations

import http.server
import os
from pathlib import Path


def main() -> int:
    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    docs = workspace / "modules" / "picblobs" / "docs"
    os.chdir(docs)
    http.server.test(
        HandlerClass=http.server.SimpleHTTPRequestHandler,
        ServerClass=http.server.ThreadingHTTPServer,
        port=8000,
        bind="127.0.0.1",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
