#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

image="${HOVEL_SQUATTER_WINE_IMAGE:-}"
if [[ -z "$image" ]]; then
  IFS= read -r image < tools/wine/image.txt
fi
host_port="${HOVEL_SQUATTER_WINE_PORT:-19100}"
exe="${HOVEL_SQUATTER_EXE:-$PWD/examples/bin/squatter.exe}"

if [[ ! -f "$exe" ]]; then
  echo "missing Squatter binary: $exe" >&2
  echo "run aspect hovel-check modules first" >&2
  exit 2
fi

docker run -d --init \
  --name "${HOVEL_SQUATTER_WINE_NAME:-hovel-squatter-wine}" \
  -p "127.0.0.1:${host_port}:9100" \
  -v "$exe:/payload/squatter.exe:ro" \
  "$image"
