#!/usr/bin/env bash
# Drop into the picblobs dev container with the source tree mounted.
#
# Usage:
#   ci/dev.sh              # interactive shell
#   ci/dev.sh make test    # run a command and exit
#
# The container runs as your host UID/GID so files it creates are
# owned by you, not root.  Always targets linux/amd64 (runs under
# Rosetta on Apple Silicon).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="picblobs-dev"
PLATFORM="linux/amd64"

HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# Pick whichever container runtime is available.
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    RUNTIME=docker
elif command -v podman &>/dev/null; then
    RUNTIME=podman
else
    echo "error: neither docker nor podman found" >&2
    exit 1
fi

# Build the image with the host user's UID/GID baked in.
# Rebuild if the image doesn't exist or the UID/GID changed.
_needs_build=0
if ! $RUNTIME image exists "$IMAGE" 2>/dev/null; then
    _needs_build=1
else
    # Check if the baked-in UID still matches.
    _img_uid=$($RUNTIME inspect --format '{{.Config.User}}' "$IMAGE" 2>/dev/null || echo "")
    if [ "$_img_uid" != "$HOST_UID:$HOST_GID" ]; then
        _needs_build=1
    fi
fi

if [ "$_needs_build" -eq 1 ]; then
    echo "Building $IMAGE (uid=$HOST_UID gid=$HOST_GID platform=$PLATFORM) ..."
    $RUNTIME build \
        --platform "$PLATFORM" \
        --build-arg "UID=$HOST_UID" \
        --build-arg "GID=$HOST_GID" \
        -t "$IMAGE" \
        -f "$SCRIPT_DIR/Dockerfile" \
        "$PROJECT_ROOT"
fi

# Mount flags: :Z for SELinux relabelling (harmless on non-SELinux hosts).
MOUNT=(-v "$PROJECT_ROOT:/workspace:Z")

if [ $# -eq 0 ]; then
    exec $RUNTIME run --platform "$PLATFORM" --rm -it "${MOUNT[@]}" "$IMAGE"
else
    exec $RUNTIME run --platform "$PLATFORM" --rm "${MOUNT[@]}" "$IMAGE" bash -c "cd /workspace && $*"
fi
