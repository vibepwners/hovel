#!/usr/bin/env bash
# Bazel test wrapper for kernel VM tests.
# Args: <test_name> <distro> <timeout>
#
# This script:
# 1. Finds the kernel/ directory (via runfiles or BUILD_WORKSPACE_DIRECTORY)
# 2. Runs vm_harness.py with the specified test
# 3. Exits with the test result

set -euo pipefail

TEST_NAME="${1:?Usage: run_vm_test.sh <test> <distro> <timeout>}"
DISTRO="${2:-ubuntu}"
TIMEOUT="${3:-600}"

# Find the kernel directory — handles bazel runfiles, direct invocation, etc.
if [ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]; then
    if [ -d "$BUILD_WORKSPACE_DIRECTORY/modules/picblobs/kernel" ]; then
        PROJECT_ROOT="$BUILD_WORKSPACE_DIRECTORY/modules/picblobs"
    else
        PROJECT_ROOT="$BUILD_WORKSPACE_DIRECTORY"
    fi
    KERNEL_DIR="$PROJECT_ROOT/kernel"
elif [ -n "${RUNFILES_DIR:-}" ]; then
    # Bazel test mode — find kernel/ in runfiles
    for candidate in \
        "$RUNFILES_DIR/_main/modules/picblobs/kernel" \
        "$RUNFILES_DIR/_main/kernel" \
        "$RUNFILES_DIR/picblobs/kernel"; do
        if [ -d "$candidate" ]; then
            KERNEL_DIR="$candidate"
            PROJECT_ROOT="$(dirname "$KERNEL_DIR")"
            break
        fi
    done
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    KERNEL_DIR="$SCRIPT_DIR"
    PROJECT_ROOT="$(dirname "$KERNEL_DIR")"
fi

if [ -z "${KERNEL_DIR:-}" ] || [ ! -d "$KERNEL_DIR" ]; then
    echo "ERROR: Cannot find kernel/ directory"
    exit 1
fi

# Verify prerequisites
for tool in qemu-system-x86_64 qemu-img python3; do
    if ! command -v "$tool" &>/dev/null; then
        echo "SKIP: $tool not found"
        exit 0  # return 0 so bazel doesn't count it as a failure
    fi
done

# Check for ISO creation tool
if ! command -v genisoimage &>/dev/null && \
   ! command -v mkisofs &>/dev/null && \
   ! command -v xorrisofs &>/dev/null; then
    echo "SKIP: no ISO creation tool (genisoimage/mkisofs/xorrisofs)"
    exit 0
fi

echo "=== Kernel VM Test: $TEST_NAME ($DISTRO, timeout=${TIMEOUT}s) ==="
echo "=== Kernel dir: $KERNEL_DIR ==="

cd "$PROJECT_ROOT"
export PYTHONUNBUFFERED=1
exec python3 -u kernel/vm/vm_harness.py test \
    -t "$TEST_NAME" \
    --distro "$DISTRO" \
    --timeout "$TIMEOUT"
