#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

uv run --project sdk/python --group dev ruff check sdk/python examples/python
uv run --project sdk/python --group dev mypy --strict --config-file sdk/python/pyproject.toml \
  sdk/python/hovel_sdk examples/python
uv run --project sdk/python --group dev pydoclint --config sdk/python/pyproject.toml \
  sdk/python/hovel_sdk examples/python
