#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <source.c> <mingw-include-marker> <project-include-dir>" >&2
  exit 2
fi

source_file="$1"
mingw_marker="$2"
project_include="$3"

if resolved_marker="$(readlink -f "$mingw_marker" 2>/dev/null)"; then
  mingw_marker="$resolved_marker"
fi

mingw_include="$(dirname "$mingw_marker")"

if ! command -v clang-tidy >/dev/null 2>&1; then
  echo "clang-tidy is required for task squatter:clang-tidy" >&2
  exit 127
fi

exec clang-tidy \
  --quiet \
  --checks='clang-analyzer-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling' \
  --warnings-as-errors='*' \
  "$source_file" \
  -- \
  -x c \
  -std=c11 \
  -D_WIN32_WINNT=0x0501 \
  -DUNICODE \
  -D_UNICODE \
  -DDECLSPEC_IMPORT= \
  -target i686-w64-windows-gnu \
  -isystem "$mingw_include" \
  -I"$project_include"
