#!/usr/bin/env bash
set -euo pipefail

hovel_bin="$1"
tmp_base="/private/tmp"
if [[ ! -d "$tmp_base" ]]; then
  tmp_base="/tmp"
fi
workspace="$(mktemp -d "$tmp_base/hovel-binary-e2e.XXXXXX")"
daemon_pid=""

cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$workspace"
}
trap cleanup EXIT

find_runfile() {
  local rel="$1"
  local candidate
  for candidate in \
    "$PWD/$rel" \
    "${TEST_SRCDIR:-}/_main/$rel" \
    "${TEST_SRCDIR:-}/hovel/$rel"; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

export HOVEL_MODULE_CONFIG="$(find_runfile examples/python/hovel-modules.json)"
export HOVEL_PYTHON_SDK_ROOT="$(find_runfile sdk/python)"

"$hovel_bin" daemon serve --workspace "$workspace" >"$workspace/daemon.out" 2>"$workspace/daemon.err" &
daemon_pid="$!"

for _ in $(seq 1 200); do
  if [[ -S "$workspace/hoveld.sock" && -f "$workspace/daemon.json" ]]; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon exited before it was ready" >&2
    cat "$workspace/daemon.out" >&2 || true
    cat "$workspace/daemon.err" >&2 || true
    exit 1
  fi
  sleep 0.05
done

if [[ ! -S "$workspace/hoveld.sock" ]]; then
  echo "daemon socket was not created" >&2
  cat "$workspace/daemon.out" >&2 || true
  cat "$workspace/daemon.err" >&2 || true
  exit 1
fi

output="$("$hovel_bin" command throw --chain mock-exploit --target mock://target --workspace "$workspace" --json)"

python3 - "$workspace" "$output" <<'PY'
import json
import pathlib
import sqlite3
import sys

workspace = pathlib.Path(sys.argv[1])
payload = json.loads(sys.argv[2])
assert payload["chain"] == "mock-exploit", payload
assert payload["targets"] == ["mock://target"], payload
assert len(payload["results"]) == 1, payload
result = payload["results"][0]
assert result["state"] == "succeeded", result
assert result["moduleId"] == "mock-exploit@v0.0.0-example", result
assert result["findings"], result
assert result["artifacts"], result
plan = payload["plan"]
db_path = workspace / "workspace.db"
with sqlite3.connect(db_path) as db:
    row = db.execute("select plan_json from throw_plans where id = ?", (plan["id"],)).fetchone()
    versions = [row[0] for row in db.execute("select version from schema_migrations order by version")]
assert row, payload
record = json.loads(row[0])
assert record["id"] == plan["id"], record
assert record["confirmationId"] == plan["confirmationId"], record
assert record["workspace"] == str(workspace), record
assert versions == [1], versions
PY
