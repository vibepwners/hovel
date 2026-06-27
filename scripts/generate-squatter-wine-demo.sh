#!/usr/bin/env bash
# Materialize the Bazel-cached Docker/Wine Squatter MCP demo GIF.
set -euo pipefail

cd "$(dirname "$0")/.."

require() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required command: $name" >&2
    exit 1
  fi
}

require bash
require task

task build -- //demo:squatter_wine_gif
bash tools/demo/materialize_demo_outputs.sh squatter-wine
