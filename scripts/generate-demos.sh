#!/usr/bin/env bash
# Generate reproducible terminal demo artifacts from VHS tapes.
set -euo pipefail

cd "$(dirname "$0")/.."

require() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required command: $name" >&2
    exit 1
  fi
}

require python3
require task
require vhs

demo_daemon_pids=()
cleanup_demo_daemons() {
  local pid
  for pid in "${demo_daemon_pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup_demo_daemons EXIT

start_demo_daemon() {
  local workspace="$1"
  local hovel_bin="$2"

  "$hovel_bin" daemon serve --workspace "$workspace" >"$workspace/daemon.log" 2>&1 &
  demo_daemon_pids+=("$!")
  until "$hovel_bin" daemon status --workspace "$workspace" >/dev/null 2>&1; do
    sleep 0.1
  done
}

mapfile -t tapes < <(find demo/tapes -type f -name '*.tape' -print | sort)
if [[ "${#tapes[@]}" -eq 0 ]]; then
  echo "no VHS tapes found under demo/tapes" >&2
  exit 1
fi

rm -rf demo/out demo/tmp
mkdir -p demo/out demo/tmp

task build -- //cmd/hovel
task modules:build

hovel_bin="$PWD/bazel-bin/cmd/hovel/hovel_/hovel"
if [[ ! -x "$hovel_bin" ]]; then
  echo "expected built hovel binary at $hovel_bin" >&2
  exit 1
fi

workspace="$PWD/demo/tmp/mock-survey-exploit-verify"
rm -rf "$workspace"
mkdir -p "$workspace"

export HOVEL_MODULE_CONFIG="$PWD/examples/hovel-modules.json"

verify_mock_throw_json() {
  local json="$1"
  local chain="$2"
  HOVEL_DEMO_JSON="$json" HOVEL_DEMO_CHAIN="$chain" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["HOVEL_DEMO_JSON"])
assert payload["chain"] == os.environ["HOVEL_DEMO_CHAIN"], payload
assert payload["targets"] == ["mock://router-01"], payload
results = payload["results"]
assert [r["moduleId"] for r in results] == [
    "mock-survey-go@v0.0.0-example",
    "mock-exploit-session-go@v0.0.0-example",
], results
assert all(r["state"] == "succeeded" for r in results), results
assert results[0]["summary"] == "example survey reached router-01:443", results[0]
assert results[1]["summary"] == "mock exploit opened an interactive shell session", results[1]
assert results[1]["findings"], results[1]
assert len(results[1]["sessions"]) == 1, results[1]
session = results[1]["sessions"][0]
assert session["name"] == "mock shell on mock://router-01", session
assert session["kind"] == "shell", session
assert session["state"] == "active", session
PY
}

start_demo_daemon "$workspace" "$hovel_bin"
json="$("$hovel_bin" throw demo/chains/mock-survey-exploit.chain.yaml --workspace "$workspace" --now --json)"
verify_mock_throw_json "$json" "mock-survey-exploit-demo"
"$hovel_bin" session send latest whoami --workspace "$workspace"
session_output="$("$hovel_bin" session read latest --workspace "$workspace")"
if [[ "$session_output" != *"mock-operator"* ]]; then
  echo "saved-chain demo session interaction failed" >&2
  exit 1
fi

constructed_workspace="$PWD/demo/tmp/mock-survey-exploit-commands-verify"
constructed_chain="mock-survey-exploit-commands-verify"
rm -rf "$constructed_workspace"
mkdir -p "$constructed_workspace"
start_demo_daemon "$constructed_workspace" "$hovel_bin"

"$hovel_bin" run --workspace "$constructed_workspace" --op demo -- chain create "$constructed_chain"
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- chain add mock-survey-go
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- chain add mock-exploit-session-go
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- target add mock://router-01
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- target config set mock://router-01 target.host router-01
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- target config set mock://router-01 target.port 443
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- chain config set operator.confirmed_lab true
json="$("$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- throw --now --json)"
verify_mock_throw_json "$json" "$constructed_chain"
"$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- session send latest whoami
session_output="$("$hovel_bin" run --workspace "$constructed_workspace" --op demo --chain "$constructed_chain" -- session read latest)"
if [[ "$session_output" != *"mock-operator"* ]]; then
  echo "constructed demo session interaction failed" >&2
  exit 1
fi

for tape in "${tapes[@]}"; do
  vhs "$tape"
done

mapfile -t outputs < <(awk '$1 == "Output" { print $2 }' "${tapes[@]}" | sort -u)
if [[ "${#outputs[@]}" -eq 0 ]]; then
  echo "no Output directives found in demo tapes" >&2
  exit 1
fi

for output in "${outputs[@]}"; do
  if [[ ! -s "$output" ]]; then
    echo "expected demo output was not generated: $output" >&2
    exit 1
  fi
done

printf 'generated demo artifacts:\n'
printf '  %s\n' "${outputs[@]}"
