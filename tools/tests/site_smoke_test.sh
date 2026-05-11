#!/usr/bin/env bash
set -euo pipefail

# Verifies the static spec site is present and shaped how the rest of the
# project expects. Each argument is a path to a generated HTML file that must
# exist and contain the shared site stylesheet link.

for path in "$@"; do
  if [[ ! -f "${path}" ]]; then
    echo "site_smoke_test: expected file not found: ${path}" >&2
    exit 1
  fi
  if ! grep -q 'assets/site.css' "${path}"; then
    echo "site_smoke_test: ${path} is missing the shared stylesheet link" >&2
    exit 1
  fi
done
