#!/usr/bin/env bash
set -euo pipefail

mapfile -d '' files < <(find . -path './bazel-*' -prune -o -type f -name '*.go' -print0 | sort -z)
if ((${#files[@]} == 0)); then
  exit 0
fi

unformatted="$(gofmt -l "${files[@]}")"
if [[ -n "$unformatted" ]]; then
  printf 'gofmt found files that need formatting:\n%s\n' "$unformatted" >&2
  printf 'Run gofmt -w on the files above before committing.\n' >&2
  exit 1
fi
