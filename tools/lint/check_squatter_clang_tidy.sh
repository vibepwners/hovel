#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

if ! command -v clang-tidy >/dev/null 2>&1; then
  echo "clang-tidy is required for task squatter:clang-tidy" >&2
  exit 127
fi

mapfile -t sources < <(find payloads/squatter/windows/src -type f -name '*.c' | sort)

bazel_bin="$(readlink -f bazel-bin 2>/dev/null || true)"
if [[ -z "$bazel_bin" || "$bazel_bin" != */execroot/* ]]; then
  echo "bazel-bin symlink is missing; run task build first so clang-tidy can find MinGW headers" >&2
  exit 1
fi
output_base="${bazel_bin%%/execroot/*}"
mingw_root="$output_base/external/+mingw_toolchain_repo+mingw_i686"
mingw_include="$mingw_root/i686-w64-mingw32/include"

if [[ ! -f "$mingw_include/winsock2.h" ]]; then
  echo "MinGW headers not found under $mingw_root; run task build first" >&2
  exit 1
fi

for src in "${sources[@]}"; do
  clang-tidy \
    --quiet \
    --checks='clang-analyzer-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling' \
    --warnings-as-errors='*' \
    "$src" \
    -- \
    -x c \
    -std=c11 \
    -D_WIN32_WINNT=0x0501 \
    -DUNICODE \
    -D_UNICODE \
    -DDECLSPEC_IMPORT= \
    -target i686-w64-windows-gnu \
    -isystem "$mingw_include" \
    -Ipayloads/squatter/windows/src
done
