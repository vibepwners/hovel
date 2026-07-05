#!/usr/bin/env sh
set -eu

PICBLOBS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PICBLOBS_ROOT/../.."
export PICBLOBS_REQUIRE_LINT_TOOLS=1
exec bazel build --config=picblobs_lint //modules/picblobs/src/... //modules/picblobs/tests/...
