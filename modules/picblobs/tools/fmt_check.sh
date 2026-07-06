#!/bin/bash
# Format check for Bazel test integration.
set -euo pipefail

resolve_runfile() {
  if [ -x "$1" ] || [ -f "$1" ]; then
    realpath "$1"
    return 0
  fi
  for root in "${TEST_SRCDIR:-}" "${TEST_SRCDIR:-}/_main" "${TEST_SRCDIR:-}/hovel"; do
    if [ -n "$root" ] && { [ -x "$root/$1" ] || [ -f "$root/$1" ]; }; then
      realpath "$root/$1"
      return 0
    fi
  done
  echo "error: unable to locate runfile $1" >&2
  exit 1
}

select_buildifier() {
  case "$(uname -m)" in
    aarch64|arm64) resolve_runfile "$5" ;;
    *) resolve_runfile "$4" ;;
  esac
}

if [ "$#" -ge 5 ]; then
  export PICBLOBS_CLANG_FORMAT="$(resolve_runfile "$1")"
  export PICBLOBS_RUFF="$(resolve_runfile "$2")"
  export PICBLOBS_LIZARD="$(resolve_runfile "$3")"
  export PICBLOBS_BUILDIFIER="$(select_buildifier "$@")"
fi

WORKSPACE=""
if [ -n "${TEST_SRCDIR:-}" ]; then
  for candidate in "${TEST_SRCDIR:-}/_main" "${TEST_SRCDIR:-}/hovel" "${TEST_SRCDIR:-}"; do
    if [ -n "$candidate" ] && [ -f "$candidate/modules/picblobs/tools/fmt.py" ]; then
      WORKSPACE="$candidate"
      break
    fi
  done
fi
if [ -z "$WORKSPACE" ] && [ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]; then
  WORKSPACE="$BUILD_WORKSPACE_DIRECTORY"
fi
if [ -z "$WORKSPACE" ]; then
  export PATH="$HOME/.local/share/sapling:/home/user/.local/share/sapling:$PATH"
  WORKSPACE="$(git rev-parse --show-toplevel 2>/dev/null || sl root 2>/dev/null || true)"
fi
if [ -z "$WORKSPACE" ]; then
  for candidate in "$PWD"; do
    if [ -n "$candidate" ] && [ -f "$candidate/modules/picblobs/tools/fmt.py" ]; then
      WORKSPACE="$candidate"
      break
    fi
  done
fi
if [ -z "$WORKSPACE" ]; then
  echo "error: unable to locate workspace root" >&2
  exit 1
fi
PICBLOBS_ROOT="$WORKSPACE/modules/picblobs"
cd "$PICBLOBS_ROOT"
exec python3 tools/fmt.py --check
