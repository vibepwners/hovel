#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

if ! command -v cppcheck >/dev/null 2>&1; then
  echo "cppcheck is required for task squatter:cppcheck" >&2
  exit 127
fi

mapfile -t sources < <(find payloads/squatter/windows/src -type f -name '*.c' | sort)

exec cppcheck \
  --quiet \
  --enable=warning,performance,portability \
  --error-exitcode=1 \
  --force \
  --inline-suppr \
  --std=c11 \
  --suppress=missingIncludeSystem \
  -D_WIN32_WINNT=0x0501 \
  -DUNICODE \
  -D_UNICODE \
  -DDECLSPEC_IMPORT= \
  -Ipayloads/squatter/windows/src \
  "${sources[@]}"
