#!/usr/bin/env bash
set -euo pipefail

find payloads/squatter/windows/src \
  -path 'payloads/squatter/windows/src/nocrt/chkstk.S' -prune -o \
  -type f \( -name '*.c' -o -name '*.h' \) \
  -print | sort
