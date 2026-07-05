#!/bin/bash
# End-to-end NaCl encrypted handshake test.
#
# Runs server and client PIC blobs under QEMU, validates:
#   1. Both processes exit 0
#   2. Server decrypted the correct plaintext (SHA256 match)
#   3. Server completed the secure channel
#
# Usage: nacl_e2e.sh <qemu> <runner> <server.bin> <client.bin>

set -euo pipefail

QEMU="$1"; RUNNER="$2"; SERVER="$3"; CLIENT="$4"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

EXPECTED_MSG="Hello from NaCl PIC blob!"

echo "=== NaCl E2E test ==="

# Start server in background, capture stdout.
"$QEMU" "$RUNNER" "$SERVER" > "$TMPDIR/server.out" 2>&1 &
SERVER_PID=$!

# The client has a built-in retry loop (50 attempts with busy-wait),
# but give the server a moment to bind.
sleep 1

# Run client, capture stdout.
CLIENT_EXIT=0
"$QEMU" "$RUNNER" "$CLIENT" > "$TMPDIR/client.out" 2>&1 || CLIENT_EXIT=$?

# Wait for server to finish.
SERVER_EXIT=0
wait "$SERVER_PID" || SERVER_EXIT=$?

echo "--- Server output ---"
cat "$TMPDIR/server.out"
echo "--- Client output ---"
cat "$TMPDIR/client.out"

# Check 1: exit codes.
FAIL=0
if [ "$SERVER_EXIT" -ne 0 ]; then
    echo "FAIL: server exited $SERVER_EXIT"
    FAIL=1
fi
if [ "$CLIENT_EXIT" -ne 0 ]; then
    echo "FAIL: client exited $CLIENT_EXIT"
    FAIL=1
fi

# Check 2: server decrypted the expected plaintext.
# Server prints: "[server] decrypted: Hello from NaCl PIC blob!"
EXPECTED_HASH="$(printf '%s' "$EXPECTED_MSG" | sha256sum)"
EXPECTED_HASH="${EXPECTED_HASH%% *}"

# Extract what the server actually decrypted.
ACTUAL_MSG=""
while IFS= read -r line; do
    case "$line" in
        *"decrypted: "*)
            ACTUAL_MSG="${line#*decrypted: }"
            ;;
    esac
done < "$TMPDIR/server.out"

if [ -z "$ACTUAL_MSG" ]; then
    echo "FAIL: server did not print decrypted message"
    FAIL=1
else
    ACTUAL_HASH="$(printf '%s' "$ACTUAL_MSG" | sha256sum)"
    ACTUAL_HASH="${ACTUAL_HASH%% *}"
    if [ "$EXPECTED_HASH" = "$ACTUAL_HASH" ]; then
        echo "OK: payload SHA256 match ($EXPECTED_HASH)"
    else
        echo "FAIL: payload SHA256 mismatch"
        echo "  expected: $EXPECTED_HASH ($EXPECTED_MSG)"
        echo "  actual:   $ACTUAL_HASH ($ACTUAL_MSG)"
        FAIL=1
    fi
fi

# Check 3: server confirmed secure channel.
CHANNEL_OK=0
while IFS= read -r line; do
    case "$line" in
        *"secure channel OK"*) CHANNEL_OK=1 ;;
    esac
done < "$TMPDIR/server.out"

if [ "$CHANNEL_OK" -eq 1 ]; then
    echo "OK: secure channel confirmed"
else
    echo "FAIL: server did not confirm secure channel"
    FAIL=1
fi

echo ""
if [ "$FAIL" -ne 0 ]; then
    echo "=== FAIL ==="
    exit 1
fi
echo "=== PASS ==="
