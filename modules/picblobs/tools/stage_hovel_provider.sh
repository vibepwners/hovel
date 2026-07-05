#!/usr/bin/env sh
set -eu

repo="${BUILD_WORKSPACE_DIRECTORY:-}"
if [ -z "$repo" ]; then
  repo="$(cd "$(dirname "$0")/../../.." && pwd)"
fi

cd "$repo"
bazel build //modules/picblobs/provider:picblobs-provider

src="bazel-bin/modules/picblobs/provider/picblobs-provider_/picblobs-provider"
if [ ! -x "$src" ]; then
  src="bazel-bin/modules/picblobs/provider/picblobs-provider"
fi
if [ ! -x "$src" ]; then
  echo "could not locate built picblobs-provider under bazel-bin/modules/picblobs/provider" >&2
  exit 1
fi

mkdir -p modules/picblobs/bin
cp "$src" modules/picblobs/bin/picblobs-provider
chmod 0755 modules/picblobs/bin/picblobs-provider
echo "staged modules/picblobs/bin/picblobs-provider"
