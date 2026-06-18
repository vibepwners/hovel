#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mapfile -t sources < <(tools/lint/squatter_sources.sh)
if ((${#sources[@]} == 0)); then
	exit 0
fi
for i in "${!sources[@]}"; do
	sources[$i]="$PWD/${sources[$i]}"
done

exec task run -- //tools/lint:clang_format -- -i "${sources[@]}"
