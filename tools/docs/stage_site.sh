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

python3 tools/docs/generate_sdk_api_docs.py \
  --repo-root "${repo_root}" \
  --site-root "${repo_root}/_site" \
  --output "${repo_root}/_site/api/sdk"

python3 tools/docs/check_site_links.py "${repo_root}/_site"

# Pages serves _site/ as the document root. Nothing here needs Jekyll.
touch _site/.nojekyll
