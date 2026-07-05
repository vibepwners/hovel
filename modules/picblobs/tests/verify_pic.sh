#!/bin/bash
# Verify that PIC blob .so files have the correct ELF properties:
#   1. No dynamic relocations (key PIC invariant)
#   2. __blob_start and __blob_end symbols present
#   3. Entry point at address 0
#   4. Blob size under 100KB
#   5. Valid ARM ELF
#
# Pure bash — no grep, awk, or other host tools. Only uses the
# Bootlin readelf passed as the first argument.
#
# Usage: verify_pic.sh <readelf> <blob.so> [<blob.so> ...]

set -euo pipefail

READELF="$1"; shift

FAIL=0

fail() {
    echo "FAIL: $1"
    FAIL=1
}

# Extract a symbol's hex address from readelf -s output.
# Parses lines like: "    42: 00000a90     0 NOTYPE  GLOBAL DEFAULT    5 __blob_end"
sym_addr() {
    local symtab="$1" name="$2"
    local line
    while IFS= read -r line; do
        case "$line" in
            *"$name"*)
                # Fields: Num Value Size Type Bind Vis Ndx Name
                # Strip leading whitespace then split on whitespace.
                local trimmed="${line#"${line%%[![:space:]]*}"}"
                local i=0 addr=""
                for field in $trimmed; do
                    if [ "$i" -eq 1 ]; then
                        addr="$field"
                        break
                    fi
                    i=$((i + 1))
                done
                echo "$addr"
                return 0
                ;;
        esac
    done <<< "$symtab"
    return 1
}

check_blob() {
    local so="$1"
    local name="${so##*/}"

    echo "--- Checking $name ---"

    if [ ! -f "$so" ]; then
        fail "$name: file not found: $so"
        return
    fi

    # 1. No relocation sections (should all be discarded by blob.ld).
    local sections reloc_count=0
    sections="$("$READELF" -S "$so" 2>/dev/null)"
    while IFS= read -r line; do
        case "$line" in
            *.rel.*|*.rela.*) reloc_count=$((reloc_count + 1)) ;;
        esac
    done <<< "$sections"
    if [ "$reloc_count" -ne 0 ]; then
        fail "$name: found $reloc_count relocation section(s) — blob is not fully PIC"
    else
        echo "  OK: no relocation sections"
    fi

    # 2. __blob_start and __blob_end symbols exist.
    local symtab
    symtab="$("$READELF" -s "$so" 2>/dev/null)"

    local start_addr="" end_addr=""
    start_addr="$(sym_addr "$symtab" __blob_start)" || true
    end_addr="$(sym_addr "$symtab" __blob_end)" || true

    if [ -n "$start_addr" ]; then
        echo "  OK: __blob_start found"
    else
        fail "$name: missing __blob_start symbol"
    fi

    if [ -n "$end_addr" ]; then
        echo "  OK: __blob_end found"
    else
        fail "$name: missing __blob_end symbol"
    fi

    # 3. __blob_start is at address 0 (entry point at blob offset 0).
    if [ "$start_addr" = "00000000" ] || [ "$start_addr" = "0000000000000000" ]; then
        echo "  OK: __blob_start at address 0"
    else
        fail "$name: __blob_start at ${start_addr:-?} (expected 0)"
    fi

    # 4. Blob size under 100KB.
    if [ -n "$end_addr" ]; then
        local blob_size=$((16#$end_addr))
        if [ "$blob_size" -le 102400 ]; then
            echo "  OK: blob size ${blob_size} bytes ($((blob_size / 1024))KB < 100KB)"
        else
            fail "$name: blob size ${blob_size} bytes exceeds 100KB limit"
        fi
    fi

    # 5. Valid ARM ELF.
    local header
    header="$("$READELF" -h "$so" 2>/dev/null)"
    local machine=""
    while IFS= read -r line; do
        case "$line" in
            *Machine:*)
                # "  Machine:                           ARM"
                machine="${line#*Machine:}"
                # Trim leading whitespace.
                machine="${machine#"${machine%%[![:space:]]*}"}"
                # Take first word.
                machine="${machine%% *}"
                break
                ;;
        esac
    done <<< "$header"
    if [ "$machine" = "ARM" ]; then
        echo "  OK: ARM ELF"
    else
        fail "$name: expected ARM ELF, got machine=$machine"
    fi
}

if [ $# -eq 0 ]; then
    echo "Usage: $0 <readelf> <blob.so> [<blob.so> ...]" >&2
    exit 1
fi

for so in "$@"; do
    check_blob "$so"
    echo ""
done

if [ "$FAIL" -ne 0 ]; then
    echo "=== SOME CHECKS FAILED ==="
    exit 1
fi

echo "=== ALL CHECKS PASSED ==="
