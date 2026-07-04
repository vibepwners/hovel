#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$WINEPREFIX" /work
wineboot -u >/dev/null 2>&1 || true
exec wine "$SQUATTER_EXE" "$SQUATTER_PORT"
