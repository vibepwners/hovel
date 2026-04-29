#!/usr/bin/env bash
set -euo pipefail

files=()
while IFS= read -r -d '' file; do
  files+=("$file")
done < <(find . -path './bazel-*' -prune -o -type f -name '*.go' -print0)
if ((${#files[@]} == 0)); then
  exit 0
fi

gofmt -w "${files[@]}"
