#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

fingerprint="$(
  python3 - <<'PY'
from __future__ import annotations

import hashlib
from pathlib import Path

paths: set[Path] = {
    Path("LICENSE"),
    Path("VERSION"),
    Path("go.mod"),
    Path("go.sum"),
    Path("index.html"),
    Path("sdk/python/pyproject.toml"),
    Path("sdk/python/uv.lock"),
    Path("tools/docs/check_site_links.py"),
    Path("tools/docs/generate_sdk_api_docs.py"),
    Path("tools/docs/stage_site.sh"),
}

for pattern in (
    "assets/**/*",
    "demo/out/*.gif",
    "sdk/go/**/*.go",
    "sdk/python/hovel_sdk/**/*.py",
    "sdk/rust/hovel/src/**/*.rs",
    "spec/**/*.html",
    "tools/docs/python_api/**/*",
):
    paths.update(Path(".").glob(pattern))

digest = hashlib.sha256()
for path in sorted(path for path in paths if path.is_file()):
    digest.update(path.as_posix().encode())
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")
print(digest.hexdigest())
PY
)"

stamp="_site/.hovel_docs_inputs.sha256"
if [[ -f "$stamp" ]] && [[ -f _site/.nojekyll ]] && [[ "$(tr -d '[:space:]' < "$stamp")" == "$fingerprint" ]]; then
  echo "docs site is current: _site"
  exit 0
fi

task build -- //spec:site

rm -rf _site
mkdir -p _site
cp index.html _site/
cp LICENSE _site/
cp -r assets _site/
cp -r spec _site/
find _site -name BUILD.bazel -delete

version="$(tr -d '[:space:]' < VERSION)"
python3 - "${version}" <<'PY'
import sys
from pathlib import Path

version = sys.argv[1]
replacements = {
    "{{HOVEL_VERSION}}": version,
    "{{HOVEL_RELEASE_TAG}}": "v" + version,
}
for path in Path("_site").rglob("*.html"):
    text = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
PY

demo_outputs=(
  "module-package-install-01-link.gif"
  "mcp-agent-01-throw.gif"
  "mcp-agent-02-squatter-wine.gif"
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
mkdir -p _site/assets/demos
for output in "${demo_outputs[@]}"; do
  if [[ ! -s "demo/out/${output}" ]]; then
    echo "missing generated demo artifact: demo/out/${output}" >&2
    echo "run task docs before staging docs, or run task demos and task demo:squatter-wine" >&2
    exit 1
  fi
  cp "demo/out/${output}" "_site/assets/demos/${output}"
done

python3 tools/docs/generate_sdk_api_docs.py \
  --repo-root "${repo_root}" \
  --site-root "${repo_root}/_site" \
  --output "${repo_root}/_site/api/sdk"

python3 tools/docs/check_site_links.py "${repo_root}/_site"

# Pages serves _site/ as the document root. Nothing here needs Jekyll.
touch _site/.nojekyll
printf '%s\n' "$fingerprint" > "$stamp"
