#!/usr/bin/env bash
# Render one VHS tape as a Bazel action with a declared GIF output.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: render_vhs_demo.sh --tape PATH --tape-rel PATH --output PATH
                          --hovel-bin PATH --agent-bin PATH
                          --mock-survey-go PATH --mock-exploit-session-go PATH
                          [--vhs-version-file PATH]
                          [--squatter-provider PATH --squatter-exe PATH --wine]
EOF
  exit 2
}

abs_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    printf '%s/%s\n' "$(cd "$(dirname "$path")" && pwd)" "$(basename "$path")"
    return
  fi
  echo "missing path: $path" >&2
  exit 1
}

require() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required command: $name" >&2
    exit 1
  fi
}

find_command() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return
  fi
  local gopath=""
  if command -v go >/dev/null 2>&1; then
    gopath="$(go env GOPATH 2>/dev/null || true)"
  fi
  local candidates=()
  [[ -n "${HOME:-}" ]] && candidates+=("$HOME/go/bin/$name")
  [[ -n "${GOPATH:-}" ]] && candidates+=("$GOPATH/bin/$name")
  [[ -n "$gopath" ]] && candidates+=("$gopath/bin/$name")
  candidates+=(
    "/home/runner/go/bin/$name"
    "/home/user/go/bin/$name"
  )
  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "missing required command: $name" >&2
  exit 1
}

tape=""
tape_rel=""
output=""
hovel_bin=""
agent_bin=""
mock_survey_go=""
mock_exploit_session_go=""
vhs_version_file=""
squatter_provider=""
squatter_exe=""
wine=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --tape)
      tape="${2:-}"; shift 2 ;;
    --tape-rel)
      tape_rel="${2:-}"; shift 2 ;;
    --output)
      output="${2:-}"; shift 2 ;;
    --hovel-bin)
      hovel_bin="${2:-}"; shift 2 ;;
    --agent-bin)
      agent_bin="${2:-}"; shift 2 ;;
    --mock-survey-go)
      mock_survey_go="${2:-}"; shift 2 ;;
    --mock-exploit-session-go)
      mock_exploit_session_go="${2:-}"; shift 2 ;;
    --vhs-version-file)
      vhs_version_file="${2:-}"; shift 2 ;;
    --squatter-provider)
      squatter_provider="${2:-}"; shift 2 ;;
    --squatter-exe)
      squatter_exe="${2:-}"; shift 2 ;;
    --wine)
      wine=1; shift ;;
    *)
      usage ;;
  esac
done

[[ -n "$tape" && -n "$tape_rel" && -n "$output" ]] || usage
[[ -n "$hovel_bin" && -n "$agent_bin" ]] || usage
[[ -n "$mock_survey_go" && -n "$mock_exploit_session_go" ]] || usage
if [[ "$wine" == "1" ]]; then
  [[ -n "$squatter_provider" && -n "$squatter_exe" ]] || usage
fi

require bash
require python3
require tmux
vhs_bin="$(find_command vhs)"
if [[ -n "$vhs_version_file" ]]; then
  vhs_version_file="$(abs_path "$vhs_version_file")"
  expected_vhs_version="$(tr -d '[:space:]' <"$vhs_version_file")"
  actual_vhs_version="$("$vhs_bin" --version 2>/dev/null || true)"
  if [[ "$actual_vhs_version" != *"$expected_vhs_version"* ]]; then
    echo "expected VHS $expected_vhs_version, got: $actual_vhs_version" >&2
    exit 1
  fi
fi
if [[ "$wine" == "1" ]]; then
  require docker
fi

tape="$(abs_path "$tape")"
hovel_bin="$(abs_path "$hovel_bin")"
agent_bin="$(abs_path "$agent_bin")"
mock_survey_go="$(abs_path "$mock_survey_go")"
mock_exploit_session_go="$(abs_path "$mock_exploit_session_go")"
if [[ "$wine" == "1" ]]; then
  squatter_provider="$(abs_path "$squatter_provider")"
  squatter_exe="$(abs_path "$squatter_exe")"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/hovel-vhs.XXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

repo="$work/repo"
mkdir -p \
  "$repo/$(dirname "$tape_rel")" \
  "$repo/demo/chains" \
  "$repo/demo/out" \
  "$repo/demo/tmp/cache" \
  "$repo/demo/tmp/home" \
  "$repo/demo/tmp/vhs-tmp" \
  "$repo/examples/bin" \
  "$repo/scripts" \
  "$repo/tools/demo" \
  "$repo/tools/docker/squatter-wine"

install -m 0644 "$tape" "$repo/$tape_rel"
install -m 0644 "demo/chains/mock-survey-exploit.chain.yaml" "$repo/demo/chains/mock-survey-exploit.chain.yaml"
install -m 0755 "scripts/demo-step-setup.sh" "$repo/scripts/demo-step-setup.sh"
install -m 0755 "scripts/demo-mcp-agent-tmux.sh" "$repo/scripts/demo-mcp-agent-tmux.sh"
install -m 0755 "tools/demo/check_gif_duration.py" "$repo/tools/demo/check_gif_duration.py"
install -m 0755 "$hovel_bin" "$repo/demo/tmp/hovel"
install -m 0755 "$agent_bin" "$repo/demo/tmp/hovel-mock-agent"
install -m 0755 "$mock_survey_go" "$repo/examples/bin/mock-survey-go"
install -m 0755 "$mock_exploit_session_go" "$repo/examples/bin/mock-exploit-session-go"

cat >"$repo/examples/hovel-modules.json" <<'JSON'
{
  "modules": [
    {"id": "mock-survey-go", "runtime": "jsonrpc-stdio", "command": ["bin/mock-survey-go"]},
    {"id": "mock-exploit-session-go", "runtime": "jsonrpc-stdio", "command": ["bin/mock-exploit-session-go"]}
  ]
}
JSON

if [[ "$wine" == "1" ]]; then
  install -m 0755 "$squatter_provider" "$repo/examples/bin/squatter-provider"
  install -m 0755 "$squatter_exe" "$repo/examples/bin/squatter.exe"
  install -m 0644 "tools/docker/squatter-wine/Dockerfile" "$repo/tools/docker/squatter-wine/Dockerfile"
  install -m 0755 "tools/docker/squatter-wine/entrypoint.sh" "$repo/tools/docker/squatter-wine/entrypoint.sh"
  install -m 0755 "tools/docker/squatter-wine/run.sh" "$repo/tools/docker/squatter-wine/run.sh"
  cat >"$repo/examples/hovel-modules.json" <<'JSON'
{
  "modules": [
    {"id": "squatter", "runtime": "jsonrpc-stdio", "command": ["bin/squatter-provider"]}
  ]
}
JSON
  image="${HOVEL_SQUATTER_WINE_IMAGE:-hovel/squatter-wine:latest}"
  docker build -t "$image" -f "$repo/tools/docker/squatter-wine/Dockerfile" "$repo/tools/docker/squatter-wine"
  export HOVEL_SQUATTER_WINE_BUILD=0
fi

export TMPDIR="$repo/demo/tmp/vhs-tmp"
export HOME="$repo/demo/tmp/home"
export XDG_CACHE_HOME="$repo/demo/tmp/cache"
export HOVEL_REPO_ROOT="$repo"
export HOVEL_DEMO_HOVEL_BIN="$repo/demo/tmp/hovel"
export HOVEL_DEMO_AGENT_BIN="$repo/demo/tmp/hovel-mock-agent"

(
  cd "$repo"
  "$vhs_bin" "$tape_rel"
)

rendered="$repo/$(awk '$1 == "Output" { print $2; exit }' "$repo/$tape_rel")"
if [[ ! -s "$rendered" ]]; then
  echo "expected demo output was not generated: $rendered" >&2
  exit 1
fi
python3 "$repo/tools/demo/check_gif_duration.py" "$rendered"
cp "$rendered" "$output"
