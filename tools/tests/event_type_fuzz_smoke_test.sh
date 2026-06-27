#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <event_test_binary>" >&2
  exit 2
fi

event_test="$1"
fuzz_cache="${TEST_TMPDIR:-/tmp}/event-type-fuzz-cache"
mkdir -p "$fuzz_cache"

exec "$event_test" \
  -test.fuzz=FuzzNewTypeNeverAcceptsUntrimmedOrSingleSegmentValues \
  -test.fuzztime=5s \
  -test.fuzzcachedir="$fuzz_cache"
