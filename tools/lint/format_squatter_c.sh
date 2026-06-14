#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

export PATH="$HOME/.local/bin:$PATH"

if ! command -v clang-format >/dev/null 2>&1; then
	echo "clang-format is required for task squatter:format" >&2
	echo "Install it with: pipx install clang-format" >&2
	exit 127
fi

mapfile -t sources < <(tools/lint/squatter_sources.sh)
if ((${#sources[@]} == 0)); then
	exit 0
fi

clang-format -i "${sources[@]}"
