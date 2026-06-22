#!/usr/bin/env bash
# Shared setup for VHS demo steps. Source this from a tape, then call
# hovel_demo_setup <step-name> <state> [chain-name].

hovel_demo_teardown() {
  if [[ -n "${HOVEL_SQUATTER_CONTAINER_ID:-}" ]]; then
    docker rm -f "$HOVEL_SQUATTER_CONTAINER_ID" >/dev/null 2>&1 || true
    unset HOVEL_SQUATTER_CONTAINER_ID
  fi
  if [[ -n "${HOVEL_DAEMON_PID:-}" ]]; then
    kill "$HOVEL_DAEMON_PID" >/dev/null 2>&1 || true
    wait "$HOVEL_DAEMON_PID" >/dev/null 2>&1 || true
    unset HOVEL_DAEMON_PID
  fi
  trap - EXIT
}

hovel_demo_create_chain() {
  local chain="$1"

  hovel run --workspace "$HOVEL_WORKSPACE" --op demo -- chain create "$chain" >/dev/null
  hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- chain add mock-survey-go >/dev/null
  hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- chain add mock-exploit-session-go >/dev/null
  hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- target add mock://router-01 >/dev/null
}

hovel_demo_configure_chain() {
  local chain="$1"

  hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- target config set mock://router-01 target.host router-01 >/dev/null
  hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- target config set mock://router-01 target.port 443 >/dev/null
  hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- chain config set operator.confirmed_lab true >/dev/null
}

hovel_demo_create_link_package() {
  export HOVEL_DEMO_PACKAGE="$HOVEL_WORKSPACE/packages/linked-demo"
  mkdir -p "$HOVEL_DEMO_PACKAGE/bin"
  cat >"$HOVEL_DEMO_PACKAGE/hovel-module.yaml" <<'YAML'
apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: linked-demo
  version: 0.1.0
  moduleType: survey
  summary: Linked demo module package
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/linked-demo"]
YAML
  printf '#!/bin/sh\n' >"$HOVEL_DEMO_PACKAGE/bin/linked-demo"
  chmod +x "$HOVEL_DEMO_PACKAGE/bin/linked-demo"
}

hovel_demo_daemon_ready() {
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

hovel_demo_tcp_ready() {
  local host="$1"
  local port="$2"

  python3 - "$host" "$port" >/dev/null 2>&1 <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET)
sock.settimeout(0.5)
try:
    sock.connect((sys.argv[1], int(sys.argv[2])))
finally:
    sock.close()
PY
}

hovel_demo_squatter_listening() {
  local container="$1"
  local port="$2"
  local port_hex

  printf -v port_hex "%04X" "$port"
  docker exec "$container" awk -v port="$port_hex" '
    $2 ~ ":" port "$" && $4 == "0A" { found = 1 }
    END { exit found ? 0 : 1 }
  ' /proc/net/tcp /proc/net/tcp6 >/dev/null 2>&1
}

hovel_demo_start_squatter_wine() {
  local repo_root="$1"
  local step_id="$2"

  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for the Squatter Wine demo" >&2
    return 1
  fi
  local port=$((19000 + (step_id % 1000)))
  export HOVEL_DEMO_PAYLOAD="p1"
  export HOVEL_DEMO_SQUATTER_HOST="127.0.0.1"
  export HOVEL_DEMO_SQUATTER_PORT="$port"
  export HOVEL_SQUATTER_WINE_PORT="$port"
  export HOVEL_SQUATTER_WINE_NAME="hovel-squatter-wine-$step_id"
  export HOVEL_SQUATTER_EXE="$repo_root/examples/bin/squatter.exe"

  HOVEL_SQUATTER_CONTAINER_ID="$("$repo_root/tools/docker/squatter-wine/run.sh")"
  export HOVEL_SQUATTER_CONTAINER_ID

  local attempts=0
  until hovel_demo_squatter_listening "$HOVEL_SQUATTER_CONTAINER_ID" 9100; do
    attempts=$((attempts + 1))
    if [[ "$attempts" -ge 120 ]]; then
      echo "timed out waiting for Squatter Wine container on $HOVEL_DEMO_SQUATTER_HOST:$HOVEL_DEMO_SQUATTER_PORT" >&2
      docker logs "$HOVEL_SQUATTER_CONTAINER_ID" >&2 || true
      return 1
    fi
    sleep 0.5
  done
}

hovel_demo_setup() {
  local step="$1"
  local state="${2:-empty}"
  local chain="${3:-mock-survey-exploit-demo}"
  local repo_root="${HOVEL_REPO_ROOT:-$PWD}"
  local step_id
  step_id="$(printf '%s' "$step" | cksum | awk '{print $1}')"
  local bin_dir="$repo_root/demo/tmp/b-$step_id"

  export HOVEL_MODULE_CONFIG="$repo_root/examples/hovel-modules.json"
  export HOVEL_WORKSPACE="$repo_root/demo/tmp/w-$step_id"
  export HOVEL_DEMO_CHAIN="$chain"
  export HOVEL_CLI_NO_WELCOME=1

  rm -rf "$HOVEL_WORKSPACE" "$bin_dir"
  mkdir -p "$HOVEL_WORKSPACE" "$bin_dir"
  ln -sf "$repo_root/bazel-bin/cmd/hovel/hovel_/hovel" "$bin_dir/hovel"
  if [[ -x "$repo_root/bazel-bin/tools/demo/mcpagent/mcpagent_/mcpagent" ]]; then
    ln -sf "$repo_root/bazel-bin/tools/demo/mcpagent/mcpagent_/mcpagent" "$bin_dir/hovel-mock-agent"
  fi
  export PATH="$bin_dir:$PATH"

  if [[ "$state" == "squatter-wine" ]]; then
    hovel_demo_start_squatter_wine "$repo_root" "$step_id"
  fi

  hovel daemon serve --workspace "$HOVEL_WORKSPACE" >"$HOVEL_WORKSPACE/daemon.log" 2>&1 &
  HOVEL_DAEMON_PID=$!
  export HOVEL_DAEMON_PID
  trap hovel_demo_teardown EXIT

  local socket_path="$HOVEL_WORKSPACE/hoveld.sock"
  local attempts=0
  until hovel_demo_daemon_ready "$socket_path"; do
    if ! kill -0 "$HOVEL_DAEMON_PID" >/dev/null 2>&1; then
      echo "hovel demo daemon exited before becoming ready" >&2
      sed -n '1,120p' "$HOVEL_WORKSPACE/daemon.log" >&2 || true
      return 1
    fi
    attempts=$((attempts + 1))
    if [[ "$attempts" -ge 100 ]]; then
      echo "timed out waiting for hovel demo daemon at $socket_path" >&2
      sed -n '1,120p' "$HOVEL_WORKSPACE/daemon.log" >&2 || true
      return 1
    fi
    sleep 0.1
  done

  case "$state" in
    empty)
      ;;
    chain)
      hovel_demo_create_chain "$chain"
      ;;
    configured)
      hovel_demo_create_chain "$chain"
      hovel_demo_configure_chain "$chain"
      ;;
    session)
      hovel throw "$repo_root/demo/chains/mock-survey-exploit.chain.yaml" --workspace "$HOVEL_WORKSPACE" --now --json >/dev/null
      ;;
    configured-session)
      hovel_demo_create_chain "$chain"
      hovel_demo_configure_chain "$chain"
      hovel run --workspace "$HOVEL_WORKSPACE" --op demo --chain "$chain" -- throw --now --json >/dev/null
      ;;
    squatter-wine)
      hovel run --workspace "$HOVEL_WORKSPACE" --op demo -- payloads register-squatter "$HOVEL_DEMO_SQUATTER_HOST" --host "$HOVEL_DEMO_SQUATTER_HOST" --port "$HOVEL_DEMO_SQUATTER_PORT" --workspace "$HOVEL_WORKSPACE" >/dev/null
      ;;
    *)
      echo "unknown demo setup state: $state" >&2
      return 2
      ;;
  esac

  echo "HOVEL_DEMO_READY $step"
}
