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
  "mock-survey-exploit.gif"
  "mock-survey-exploit.mp4"
  "mock-survey-exploit-cli.gif"
  "mock-survey-exploit-cli.mp4"
  "mock-survey-exploit-commands.gif"
  "mock-survey-exploit-commands.mp4"
  "mock-survey-exploit-cli-commands.gif"
  "mock-survey-exploit-cli-commands.mp4"
)
mkdir -p _site/assets/demos
for output in "${demo_outputs[@]}"; do
  if [[ ! -s "demo/out/${output}" ]]; then
    echo "missing generated demo artifact: demo/out/${output}" >&2
    echo "run task demos before staging docs" >&2
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
