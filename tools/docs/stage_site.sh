#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

bazel build //spec:site

rm -rf _site
mkdir -p _site
cp index.html _site/
cp LICENSE _site/
cp -r assets _site/
cp -r spec _site/
find _site -name BUILD.bazel -delete

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
