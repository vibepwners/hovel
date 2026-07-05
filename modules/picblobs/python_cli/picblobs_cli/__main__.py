"""Allow ``python -m picblobs_cli`` to invoke the click CLI directly."""

from __future__ import annotations

from picblobs_cli.cli import main

if __name__ == "__main__":
    main()
