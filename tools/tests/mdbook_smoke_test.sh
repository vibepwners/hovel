#!/usr/bin/env bash
set -euo pipefail

book_dir="$1"

test -f "${book_dir}/index.html"
test -f "${book_dir}/introduction.html"
test -f "${book_dir}/reference/descriptors.html"
