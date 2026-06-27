#!/usr/bin/env bash
# Copy Bazel-cached demo GIF outputs back into demo/out/ for docs staging.
set -euo pipefail

cd "$(dirname "$0")/../.."

mode="${1:-}"
case "$mode" in
  standard)
    outputs=(
      "module-package-install-01-link.gif"
      "mcp-agent-01-throw.gif"
      "mock-survey-exploit-01-inspect.gif"
      "mock-survey-exploit-02-throw.gif"
      "mock-survey-exploit-03-session-io.gif"
      "mock-survey-exploit-04-session-connect.gif"
      "mock-survey-exploit-cli-02-session-io.gif"
      "mock-survey-exploit-cli-03-session-connect.gif"
      "mock-survey-exploit-cli-commands-01-create.gif"
      "mock-survey-exploit-cli-commands-02-config-before.gif"
      "mock-survey-exploit-cli-commands-03-config-apply.gif"
      "mock-survey-exploit-cli-commands-04-save.gif"
      "mock-survey-exploit-commands-01-create.gif"
      "mock-survey-exploit-commands-02-config-before.gif"
      "mock-survey-exploit-commands-03-config-apply.gif"
      "mock-survey-exploit-commands-04-save.gif"
    )
    ;;
  squatter-wine)
    outputs=("mcp-agent-02-squatter-wine.gif")
    ;;
  *)
    echo "usage: $0 standard|squatter-wine" >&2
    exit 2
    ;;
esac

mkdir -p demo/out

stamp="demo/out/.${mode}.sha256"
fingerprint="$(
  {
    printf '%s\n' "$mode"
    sha256sum tools/demo/check_gif_duration.py
    for output in "${outputs[@]}"; do
      src="bazel-bin/demo/out/${output}"
      if [[ ! -s "$src" ]]; then
        echo "missing Bazel demo output: $src" >&2
        exit 1
      fi
      sha256sum "$src"
    done
  } | sha256sum | awk '{print $1}'
)"

current=true
if [[ ! -f "$stamp" ]] || [[ "$(tr -d '[:space:]' < "$stamp")" != "$fingerprint" ]]; then
  current=false
else
  for output in "${outputs[@]}"; do
    src="bazel-bin/demo/out/${output}"
    dest="demo/out/${output}"
    if [[ ! -s "$dest" ]] || ! cmp -s "$src" "$dest"; then
      current=false
      break
    fi
  done
fi

if [[ "$current" == true ]]; then
  printf 'demo artifacts are current:\n'
  printf '  demo/out/%s\n' "${outputs[@]}"
  exit 0
fi

copied=()
for output in "${outputs[@]}"; do
  src="bazel-bin/demo/out/${output}"
  dest="demo/out/${output}"
  if [[ ! -s "$src" ]]; then
    echo "missing Bazel demo output: $src" >&2
    exit 1
  fi
  cp "$src" "$dest"
  copied+=("$dest")
done

python3 tools/demo/check_gif_duration.py "${copied[@]}"
printf '%s\n' "$fingerprint" > "$stamp"

printf 'generated demo artifacts:\n'
printf '  %s\n' "${copied[@]}"
