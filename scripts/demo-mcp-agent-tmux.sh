#!/usr/bin/env bash
# Render the MCP agent demo as a real three-pane tmux session for VHS.
set -euo pipefail

: "${HOVEL_WORKSPACE:?HOVEL_WORKSPACE is required}"
: "${HOVEL_DEMO_CHAIN:?HOVEL_DEMO_CHAIN is required}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required for the MCP agent demo" >&2
  exit 1
fi
if ! command -v hovel >/dev/null 2>&1; then
  echo "hovel must be on PATH" >&2
  exit 1
fi
if ! command -v hovel-mock-agent >/dev/null 2>&1; then
  echo "hovel-mock-agent must be on PATH" >&2
  exit 1
fi

operation="${HOVEL_DEMO_OPERATION:-demo}"
width="${HOVEL_DEMO_TMUX_WIDTH:-$(tput cols 2>/dev/null || true)}"
height="${HOVEL_DEMO_TMUX_HEIGHT:-$(tput lines 2>/dev/null || true)}"
agent_delay="${HOVEL_DEMO_AGENT_DELAY:-160ms}"
agent_token_delay="${HOVEL_DEMO_AGENT_TOKEN_DELAY:-14ms}"
if ! [[ "$width" =~ ^[0-9]+$ ]] || [[ "$width" -lt 100 ]]; then
  width=170
fi
if ! [[ "$height" =~ ^[0-9]+$ ]] || [[ "$height" -lt 28 ]]; then
  height=44
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/hovel-mcp-tmux.XXXXXX")"
client_to_server="$tmpdir/client-to-server.fifo"
server_to_client="$tmpdir/server-to-client.fifo"
agent_status="$tmpdir/agent.status"
agent_start="$tmpdir/agent.start"
cli_ready="$tmpdir/cli.ready"
log_replay="$tmpdir/log.replay"
mcp_script="$tmpdir/mcp-pane.sh"
cli_script="$tmpdir/cli-pane.sh"
agent_script="$tmpdir/agent-pane.sh"
session="hovel-mcp-demo-$$"

cleanup() {
  tmux has-session -t "$session" >/dev/null 2>&1 && tmux kill-session -t "$session" >/dev/null 2>&1 || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT

mkfifo "$client_to_server" "$server_to_client"

cat >"$mcp_script" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '\033[H\033[2J'
printf 'hovel mcp\n'
printf 'workspace: %s\n' "$HOVEL_WORKSPACE"
printf 'operation: %s\n' "$HOVEL_DEMO_OPERATION"
printf 'chain: %s\n\n' "$HOVEL_DEMO_CHAIN"
printf 'stdio JSON-RPC bridged over named pipes\n'
printf 'operator entity: demo-mcp-pane\n\n'
set +e
hovel mcp \
  --workspace "$HOVEL_WORKSPACE" \
  --op "$HOVEL_DEMO_OPERATION" \
  --chain "$HOVEL_DEMO_CHAIN" \
  --entity-id demo-mcp-pane \
  --display-name "Hovel MCP pane" \
  <"$HOVEL_MCP_CLIENT_TO_SERVER" \
  >"$HOVEL_MCP_SERVER_TO_CLIENT"
status=$?
set -e
printf '\nhovel mcp exited with status %s\n' "$status"
sleep 600
SH

cat >"$cli_script" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
export HOVEL_CLI_NO_WELCOME=1
printf '\033[H\033[2J'
printf 'hovel cli\n'
printf 'workspace: %s\n\n' "$HOVEL_WORKSPACE"
printf '\033[35mh0v3l\033[0m> op use %s\n' "$HOVEL_DEMO_OPERATION"
printf 'Operation selected: %s\n' "$HOVEL_DEMO_OPERATION"
printf '\033[35mh0v3l\033[0m [%s]> chain use %s\n' "$HOVEL_DEMO_OPERATION" "$HOVEL_DEMO_CHAIN"
printf 'Chain selected: %s\n' "$HOVEL_DEMO_CHAIN"
printf '\033[35mh0v3l\033[0m [%s/%s] > \n' "$HOVEL_DEMO_OPERATION" "$HOVEL_DEMO_CHAIN"
touch "$HOVEL_DEMO_CLI_READY"
while [[ ! -f "$HOVEL_DEMO_LOG_REPLAY" ]]; do
  sleep 0.1
done
printf '\033[35mh0v3l\033[0m [%s/%s] > chain logs\n' "$HOVEL_DEMO_OPERATION" "$HOVEL_DEMO_CHAIN"
printf 'waiting for throw logs...\n'
while true; do
  logs="$(hovel run \
    --workspace "$HOVEL_WORKSPACE" \
    --op "$HOVEL_DEMO_OPERATION" \
    --chain "$HOVEL_DEMO_CHAIN" \
    -- chain logs --no-color 2>&1 || true)"
  if [[ "$logs" == *"HOVEL//THROW"* ]]; then
    printf '%s\n' "$logs"
    break
  fi
  sleep 0.4
done
sleep 600
SH

cat >"$agent_script" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '\033[H\033[2J'
printf 'mock agent\n'
printf 'model: mock-codex\n'
printf 'transport: MCP named pipes\n'
printf 'waiting for hovel cli to select the demo operation and chain...\n'
while [[ ! -f "$HOVEL_DEMO_AGENT_START" ]]; do
  sleep 0.1
done
printf '\033[H\033[2J'
set +e
hovel-mock-agent \
  --workspace "$HOVEL_WORKSPACE" \
  --op "$HOVEL_DEMO_OPERATION" \
  --chain "$HOVEL_DEMO_CHAIN" \
  --mcp-read "$HOVEL_MCP_SERVER_TO_CLIENT" \
  --mcp-write "$HOVEL_MCP_CLIENT_TO_SERVER" \
  --delay "$HOVEL_DEMO_AGENT_DELAY" \
  --token-delay "$HOVEL_DEMO_AGENT_TOKEN_DELAY" \
  --prompt "Throw the configured mock exploit through Hovel MCP"
status=$?
set -e
printf '%s' "$status" >"$HOVEL_DEMO_AGENT_STATUS"
sleep 600
SH

chmod +x "$mcp_script" "$cli_script" "$agent_script"

pane_env=(
  "HOVEL_WORKSPACE=$HOVEL_WORKSPACE"
  "HOVEL_DEMO_OPERATION=$operation"
  "HOVEL_DEMO_CHAIN=$HOVEL_DEMO_CHAIN"
  "HOVEL_MCP_CLIENT_TO_SERVER=$client_to_server"
  "HOVEL_MCP_SERVER_TO_CLIENT=$server_to_client"
  "HOVEL_DEMO_AGENT_DELAY=$agent_delay"
  "HOVEL_DEMO_AGENT_TOKEN_DELAY=$agent_token_delay"
  "HOVEL_DEMO_AGENT_STATUS=$agent_status"
  "HOVEL_DEMO_AGENT_START=$agent_start"
  "HOVEL_DEMO_CLI_READY=$cli_ready"
  "HOVEL_DEMO_LOG_REPLAY=$log_replay"
  "HOVEL_MODULE_CONFIG=${HOVEL_MODULE_CONFIG:-}"
  "HOVEL_CLI_NO_WELCOME=${HOVEL_CLI_NO_WELCOME:-1}"
)

tmux new-session -d -s "$session" -x "$width" -y "$height" "env ${pane_env[*]} '$mcp_script'"
mcp_pane="$(tmux display-message -p -t "$session:0.0" '#{pane_id}')"
agent_pane="$(tmux split-window -h -p 50 -t "$mcp_pane" -P -F '#{pane_id}' "env ${pane_env[*]} '$agent_script'")"
cli_pane="$(tmux split-window -v -p 50 -t "$mcp_pane" -P -F '#{pane_id}' "env ${pane_env[*]} '$cli_script'")"

tmux set-option -t "$session" -g pane-border-status top >/dev/null
tmux select-pane -t "$mcp_pane" -T "hovel mcp"
tmux select-pane -t "$cli_pane" -T "hovel cli"
tmux select-pane -t "$agent_pane" -T "mock agent"
tmux select-pane -t "$agent_pane"

wait_for_pane_text() {
  local pane="$1"
  local text="$2"
  local attempts="${3:-80}"
  for _ in $(seq 1 "$attempts"); do
    if tmux capture-pane -p -t "$pane" | grep -Fq "$text"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

(
  for _ in $(seq 1 80); do
    [[ -f "$cli_ready" ]] && break
    sleep 0.1
  done
  touch "$agent_start"
  sleep 0.8
  touch "$log_replay"
  wait_for_pane_text "$cli_pane" "HOVEL//THROW" || sleep 1
  for _ in $(seq 1 80); do
    [[ -s "$agent_status" ]] && break
    sleep 0.2
  done
  sleep 1.2
  tmux kill-session -t "$session" >/dev/null 2>&1 || true
) &
driver_pid=$!

tmux attach-session -t "$session" || true
wait "$driver_pid" >/dev/null 2>&1 || true

status="$(cat "$agent_status" 2>/dev/null || printf '1')"
if [[ "$status" != "0" ]]; then
  exit "$status"
fi
