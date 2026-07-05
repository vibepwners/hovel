#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
VENV_BIN="$ROOT/python/.venv/bin"

if [ ! -x "$VENV_BIN/python" ]; then
    echo "error: missing $VENV_BIN/python. Run: task setup" >&2
    exit 1
fi

export PATH="$VENV_BIN:$PATH"
cd "$ROOT"
exec "$@"
