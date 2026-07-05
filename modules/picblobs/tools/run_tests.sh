#!/usr/bin/env bash
set -euo pipefail

# Full picblobs test suite: unit tests + payload execution tests, across both
# the picblobs and picblobs-cli packages.
#
# This is the implementation behind `task test` / `task test:unit` /
# `task test:payload` — prefer those entry points. Direct flags:
#   --os <os> --arch <arch> --type <type>   filter payload tests
#   --payload-only | --unit-only            select a subset
#   anything else                           passed through to pytest

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="$ROOT/python/tests"

# Activate the dev venv if not already active.
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    VENV="$ROOT/python/.venv"
    if [[ -d "$VENV" ]]; then
        # shellcheck disable=SC1091
        source "$VENV/bin/activate"
    else
        echo "error: no virtualenv found. Run: task setup" >&2
        exit 1
    fi
fi

# Parse arguments: extract our flags, pass the rest to pytest.
PYTEST_ARGS=()
PICBLOBS_FILTER_OS=""
PICBLOBS_FILTER_ARCH=""
PICBLOBS_FILTER_TYPE=""
PAYLOAD_ONLY=0
UNIT_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --os)
            PICBLOBS_FILTER_OS="$2"
            shift 2
            ;;
        --arch)
            PICBLOBS_FILTER_ARCH="$2"
            shift 2
            ;;
        --type)
            PICBLOBS_FILTER_TYPE="$2"
            shift 2
            ;;
        --payload-only)
            PAYLOAD_ONLY=1
            shift
            ;;
        --unit-only)
            UNIT_ONLY=1
            shift
            ;;
        *)
            PYTEST_ARGS+=("$1")
            shift
            ;;
    esac
done

# Export filters as env vars for conftest.py.
[[ -n "$PICBLOBS_FILTER_OS" ]] && export PICBLOBS_TEST_OS="$PICBLOBS_FILTER_OS"
[[ -n "$PICBLOBS_FILTER_ARCH" ]] && export PICBLOBS_TEST_ARCH="$PICBLOBS_FILTER_ARCH"
[[ -n "$PICBLOBS_FILTER_TYPE" ]] && export PICBLOBS_TEST_TYPE="$PICBLOBS_FILTER_TYPE"

# Build the test file list.
TEST_FILES=()
if [[ "$PAYLOAD_ONLY" -eq 1 ]]; then
    TEST_FILES=("$TEST_DIR"/test_payload_*.py)
elif [[ "$UNIT_ONLY" -eq 1 ]]; then
    for f in "$TEST_DIR"/test_*.py; do
        case "$(basename "$f")" in
            test_payload_*) ;;  # skip payload tests
            *) TEST_FILES+=("$f") ;;
        esac
    done
else
    TEST_FILES=("$TEST_DIR"/test_*.py)
fi

echo "==> Running picblobs test suite"
echo "    test files: ${#TEST_FILES[@]}"
[[ -n "$PICBLOBS_FILTER_OS" ]] && echo "    filter os: $PICBLOBS_FILTER_OS"
[[ -n "$PICBLOBS_FILTER_ARCH" ]] && echo "    filter arch: $PICBLOBS_FILTER_ARCH"
[[ -n "$PICBLOBS_FILTER_TYPE" ]] && echo "    filter type: $PICBLOBS_FILTER_TYPE"
echo ""

# pytest must run from python/ for testpaths/conftest to resolve.
cd "$ROOT/python"
python -m pytest "${TEST_FILES[@]}" "${PYTEST_ARGS[@]}"
PICBLOBS_STATUS=$?

# Also run the picblobs-cli suite (separate rootdir — click testing +
# runner-discovery checks that depend on picblobs_cli being installed). These
# are unit tests, not payload execution tests, so they run for the full and
# --unit-only subsets; only --payload-only suppresses them.
if [[ "$PAYLOAD_ONLY" -eq 0 ]]; then
    echo ""
    echo "==> Running picblobs-cli test suite"
    cd "$ROOT/python_cli"
    python -m pytest tests/ "${PYTEST_ARGS[@]}"
    CLI_STATUS=$?
else
    CLI_STATUS=0
fi

exit $(( PICBLOBS_STATUS + CLI_STATUS ))
