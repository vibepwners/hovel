#!/usr/bin/env bash
set -euo pipefail

mapfile -d '' files < <(find . -path './bazel-*' -prune -o -type f -name '*.go' -print0 | sort -z)
if ((${#files[@]} == 0)); then
  exit 0
fi

gofmt -w "${files[@]}"
