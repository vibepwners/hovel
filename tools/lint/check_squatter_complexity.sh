#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

export PATH="$HOME/.local/bin:$PATH"

if command -v lizard >/dev/null 2>&1; then
	exec lizard -w -C 10 $(tools/lint/squatter_sources.sh)
fi

if python3 -m lizard --version >/dev/null 2>&1; then
	exec python3 -m lizard -w -C 10 $(tools/lint/squatter_sources.sh)
fi

cat >&2 <<'EOF'
lizard is required for task squatter:complexity.
Install it as a stable Python tool, then rerun:

  pipx install lizard
  # or: python3 -m pip install --user lizard
EOF
exit 127
