#!/usr/bin/env bash
# Build the compiled (Go and Rust) example modules and stage their binaries to
# examples/bin/ under stable names. The example module config
# (examples/hovel-modules.json) launches these binaries via "command" entries, so
# they must exist before the daemon builds its catalog. Python examples need no
# staging — they are launched through the interpreter from source.
#
# Invoked through `task modules:build`; do not call directly.
set -euo pipefail

cd "$(dirname "$0")/../.."

dest="examples/bin"
mkdir -p "$dest"

# target -> staged binary name
targets=(
  "//examples/go/mock_survey:mock_survey"
  "//examples/go/mock_exploit:mock_exploit"
  "//examples/go/mock_exploit_session:mock_exploit_session"
  "//examples/rust/mock_survey:mock-survey-rust"
  "//examples/rust/mock_exploit:mock-exploit-rust"
  "//examples/rust/mock_exploit_session:mock-exploit-session-rust"
)
names=(
  "mock-survey-go"
  "mock-exploit-go"
  "mock-exploit-session-go"
  "mock-survey-rust"
  "mock-exploit-rust"
  "mock-exploit-session-rust"
)

bazel build "${targets[@]}"

for i in "${!targets[@]}"; do
  src="$(bazel cquery --output=files "${targets[$i]}" 2>/dev/null | head -n1)"
  if [[ -z "$src" || ! -e "$src" ]]; then
    echo "stage_examples: could not locate output for ${targets[$i]}" >&2
    exit 1
  fi
  install -m 0755 "$src" "$dest/${names[$i]}"
done

echo "staged ${#names[@]} example module binaries to $dest"
