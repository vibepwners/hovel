#!/usr/bin/env bash
# Materialize Bazel-cached terminal demo artifacts from VHS tapes.
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

task test -- //demo:standard_verification_test
task build -- --jobs=1 //demo:standard_gifs
bash tools/demo/materialize_demo_outputs.sh standard
