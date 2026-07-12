#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve a materialized Hovel documentation site.")
    parser.add_argument("--site", default="_site", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=4322, type=int)
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    site = args.site if args.site.is_absolute() else workspace / args.site
    if not (site / "index.html").is_file():
        raise SystemExit(f"missing materialized docs site: {site}; run `task docs:build`")

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(site))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"serving {site} at http://{args.host}:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
