#!/bin/bash
# Format check for Bazel test integration.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
WORKSPACE="${BUILD_WORKSPACE_DIRECTORY:-}"
if [ -z "$WORKSPACE" ]; then
  export PATH="$HOME/.local/share/sapling:/home/user/.local/share/sapling:$PATH"
  WORKSPACE="$(git rev-parse --show-toplevel 2>/dev/null || sl root 2>/dev/null || true)"
fi
if [ -z "$WORKSPACE" ]; then
  for candidate in "$PWD" "${TEST_SRCDIR:-}/_main"; do
    if [ -n "$candidate" ] && [ -f "$candidate/modules/picblobs/tools/fmt.py" ]; then
      WORKSPACE="$candidate"
      break
    fi
  done
fi
if [ -z "$WORKSPACE" ]; then
  echo "error: unable to locate workspace root" >&2
  exit 1
fi
PICBLOBS_ROOT="$WORKSPACE/modules/picblobs"
export PATH="$PICBLOBS_ROOT/python/.venv/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
cd "$PICBLOBS_ROOT"
exec python3 tools/fmt.py --check
