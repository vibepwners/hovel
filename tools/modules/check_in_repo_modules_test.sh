#!/usr/bin/env bash
set -euo pipefail

resolve_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    printf '%s/%s\n' "$(cd "$(dirname "$path")" && pwd)" "$(basename "$path")"
    return
  fi
  if [[ -e "$PWD/$path" ]]; then
    printf '%s\n' "$PWD/$path"
    return
  fi
  echo "missing runfile: $path" >&2
  exit 1
}

find_runfile() {
  local rel="$1"
  for candidate in \
    "$PWD/$rel" \
    "${TEST_SRCDIR:-}/_main/$rel" \
    "${TEST_SRCDIR:-}/hovel/$rel"; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "missing runfile: $rel" >&2
  exit 1
}

hovel_bin="$(resolve_path "${1:?missing hovel binary}")"
shift

tmp="$(mktemp -d "/tmp/hovel-module-check.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

python_root="$(find_runfile examples/python)"
sdk_root="$(find_runfile sdk/python)"
config="$tmp/hovel-modules.json"

cat >"$config" <<JSON
{
  "modules": [
    {"id": "etro-survey", "runtime": "jsonrpc-stdio", "project_dir": "$python_root/etro_survey", "module": "hovel_etro_survey"},
    {"id": "etro-exploit", "runtime": "jsonrpc-stdio", "project_dir": "$python_root/etro_exploit", "module": "hovel_etro_exploit"},
    {"id": "mock-survey", "runtime": "jsonrpc-stdio", "project_dir": "$python_root/mock_survey", "module": "hovel_example_survey"},
    {"id": "mock-exploit", "runtime": "jsonrpc-stdio", "project_dir": "$python_root/mock_exploit", "module": "hovel_example_exploit"},
    {"id": "mock-exploit-session", "runtime": "jsonrpc-stdio", "project_dir": "$python_root/mock_exploit_session", "module": "hovel_example_exploit_session"},
    {"id": "mock-survey-go", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$1")"]},
    {"id": "mock-exploit-go", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$2")"]},
    {"id": "mock-exploit-session-go", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$3")"]},
    {"id": "mock-survey-rust", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$4")"]},
    {"id": "mock-exploit-rust", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$5")"]},
    {"id": "mock-exploit-session-rust", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$6")"]},
    {"id": "squatter", "runtime": "jsonrpc-stdio", "command": ["$(resolve_path "$7")"]}
  ]
}
JSON

export HOVEL_MODULE_CONFIG="$config"
export HOVEL_PYTHON_SDK_ROOT="$sdk_root"

out="$("$hovel_bin" module check --all)"
printf '%s\n' "$out"
grep -q "MODULE CHECKS" <<<"$out"
grep -q "12 passed" <<<"$out"
grep -q "squatter@v0.1.0" <<<"$out"
grep -q "✅ PASS" <<<"$out"

run_out="$("$hovel_bin" run --workspace "$tmp/workspace" -- module check mock-survey)"
printf '%s\n' "$run_out"
grep -q "MODULE CHECK mock-survey" <<<"$run_out"
grep -q "status  ✅ PASS" <<<"$run_out"
grep -q "config schema" <<<"$run_out"
grep -q "step contracts" <<<"$run_out"
