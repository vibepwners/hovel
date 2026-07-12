#!/usr/bin/env python3
"""Bazel entry point for the rules_python-managed Sphinx tool."""

from __future__ import annotations

import sys

from sphinx.cmd.build import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
