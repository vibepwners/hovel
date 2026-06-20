#!/usr/bin/env bash
# Shared setup for VHS demo steps. Source this from a tape, then call
# hovel_demo_setup <step-name> <state> [chain-name].

hovel_demo_teardown() {
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

hovel_demo_setup() {
  local step="$1"
  local state="${2:-empty}"
  local chain="${3:-mock-survey-exploit-demo}"
  local repo_root="${HOVEL_REPO_ROOT:-$PWD}"
  local bin_dir="$repo_root/demo/tmp/${step}-bin"

  export HOVEL_MODULE_CONFIG="$repo_root/examples/hovel-modules.json"
  export HOVEL_WORKSPACE="$repo_root/demo/tmp/${step}-workspace"
  export HOVEL_DEMO_CHAIN="$chain"

  rm -rf "$HOVEL_WORKSPACE" "$bin_dir"
  mkdir -p "$HOVEL_WORKSPACE" "$bin_dir"
  ln -sf "$repo_root/bazel-bin/cmd/hovel/hovel_/hovel" "$bin_dir/hovel"
  export PATH="$bin_dir:$PATH"

  hovel daemon serve --workspace "$HOVEL_WORKSPACE" >"$HOVEL_WORKSPACE/daemon.log" 2>&1 &
  HOVEL_DAEMON_PID=$!
  export HOVEL_DAEMON_PID
  trap hovel_demo_teardown EXIT

  until hovel daemon status --workspace "$HOVEL_WORKSPACE" >/dev/null 2>&1; do
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
    *)
      echo "unknown demo setup state: $state" >&2
      return 2
      ;;
  esac
}
