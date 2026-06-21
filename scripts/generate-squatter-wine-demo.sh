#!/usr/bin/env bash
# Generate the Docker/Wine Squatter MCP demo GIF.
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
require docker
require python3
require task
require tmux
require vhs

mkdir -p demo/out demo/tmp/vhs-tmp
export TMPDIR="$PWD/demo/tmp/vhs-tmp"

task build -- //cmd/hovel //tools/demo/mcpagent:mcpagent
task modules:build

image="${HOVEL_SQUATTER_WINE_IMAGE:-hovel/squatter-wine:latest}"
docker build -t "$image" -f tools/docker/squatter-wine/Dockerfile tools/docker/squatter-wine
export HOVEL_SQUATTER_WINE_BUILD=0

tape="demo/tapes-docker/mcp-agent-02-squatter-wine.tape"
output="demo/out/mcp-agent-02-squatter-wine.gif"

vhs "$tape"

if [[ ! -s "$output" ]]; then
  echo "expected demo output was not generated: $output" >&2
  exit 1
fi

printf 'generated demo artifact:\n  %s\n' "$output"
