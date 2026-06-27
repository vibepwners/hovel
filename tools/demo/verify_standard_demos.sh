#!/usr/bin/env bash
# Cacheable Bazel verification for behavior exercised by the standard VHS demos.
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

daemon_socket_ready() {
  local socket_path="$1"

  python3 - "$socket_path" >/dev/null 2>&1 <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_UNIX)
sock.settimeout(0.2)
try:
    sock.connect(sys.argv[1])
finally:
    sock.close()
PY
}

demo_daemon_pids=()
cleanup_demo_daemons() {
  local pid
  for pid in "${demo_daemon_pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
  rm -rf "${tmp:-}"
}
trap cleanup_demo_daemons EXIT

start_demo_daemon() {
  local workspace="$1"
  local hovel_bin="$2"

  "$hovel_bin" daemon serve --workspace "$workspace" >"$workspace/daemon.log" 2>&1 &
  local daemon_pid="$!"
  demo_daemon_pids+=("$daemon_pid")

  local socket_path="$workspace/hoveld.sock"
  local attempts=0
  until daemon_socket_ready "$socket_path"; do
    if ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
      echo "demo verification daemon exited before becoming ready" >&2
      sed -n '1,120p' "$workspace/daemon.log" >&2 || true
      exit 1
    fi
    attempts=$((attempts + 1))
    if [[ "$attempts" -ge 100 ]]; then
      echo "timed out waiting for demo verification daemon at $socket_path" >&2
      sed -n '1,120p' "$workspace/daemon.log" >&2 || true
      exit 1
    fi
    sleep 0.1
  done
}

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

hovel_bin="$(resolve_path "${1:?missing hovel binary}")"
agent_bin="$(resolve_path "${2:?missing mock agent binary}")"
mock_survey_go="$(resolve_path "${3:?missing mock survey binary}")"
mock_exploit_session_go="$(resolve_path "${4:?missing mock exploit session binary}")"
chain_file="$(resolve_path "${5:?missing demo chain file}")"

tmp="$(mktemp -d "/tmp/hovel-demo-verify.XXXXXX")"
config="$tmp/hovel-modules.json"
cat >"$config" <<JSON
{
  "modules": [
    {"id": "mock-survey-go", "runtime": "jsonrpc-stdio", "command": ["$mock_survey_go"]},
    {"id": "mock-exploit-session-go", "runtime": "jsonrpc-stdio", "command": ["$mock_exploit_session_go"]}
  ]
}
JSON
export HOVEL_MODULE_CONFIG="$config"

workspace="$tmp/w-verify-saved"
mkdir -p "$workspace"
start_demo_daemon "$workspace" "$hovel_bin"
json="$("$hovel_bin" throw "$chain_file" --workspace "$workspace" --now --json)"
verify_mock_throw_json "$json" "mock-survey-exploit-demo"
"$hovel_bin" session send latest whoami --workspace "$workspace"
session_output="$("$hovel_bin" session read latest --workspace "$workspace")"
if [[ "$session_output" != *"mock-operator"* ]]; then
  echo "saved-chain demo session interaction failed" >&2
  exit 1
fi

constructed_workspace="$tmp/w-verify-built"
constructed_chain="mock-survey-exploit-commands-verify"
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

agent_workspace="$tmp/w-verify-mcp-agent"
agent_chain="mock-survey-exploit-agent-verify"
mkdir -p "$agent_workspace"
start_demo_daemon "$agent_workspace" "$hovel_bin"

"$hovel_bin" run --workspace "$agent_workspace" --op demo -- chain create "$agent_chain"
"$hovel_bin" run --workspace "$agent_workspace" --op demo --chain "$agent_chain" -- chain add mock-survey-go
"$hovel_bin" run --workspace "$agent_workspace" --op demo --chain "$agent_chain" -- chain add mock-exploit-session-go
"$hovel_bin" run --workspace "$agent_workspace" --op demo --chain "$agent_chain" -- target add mock://router-01
"$hovel_bin" run --workspace "$agent_workspace" --op demo --chain "$agent_chain" -- target config set mock://router-01 target.host router-01
"$hovel_bin" run --workspace "$agent_workspace" --op demo --chain "$agent_chain" -- target config set mock://router-01 target.port 443
"$hovel_bin" run --workspace "$agent_workspace" --op demo --chain "$agent_chain" -- chain config set operator.confirmed_lab true

agent_output="$("$agent_bin" --hovel "$hovel_bin" --workspace "$agent_workspace" --op demo --chain "$agent_chain" --no-color --delay 0)"
for expected in "tool: hovel_workspace_snapshot" "tool: hovel_throw_start" "mock://router-01" "mock-survey-go@v0.0.0-example" "mock exploit opened an interactive shell session" "Hovel throw completed"; do
  if [[ "$agent_output" != *"$expected"* ]]; then
    echo "mock agent MCP verification did not include expected text: $expected" >&2
    printf '%s\n' "$agent_output" >&2
    exit 1
  fi
done
