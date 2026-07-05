#!/usr/bin/env bash
set -euo pipefail

# Build all mbed (eBPF + kernel module) lab components.
#
# Usage:
#   ./kernel/build.sh              # build everything
#   ./kernel/build.sh --examples   # kernel blob examples only
#   ./kernel/build.sh --kmod       # kernel module only
#   ./kernel/build.sh --check      # verify prerequisites

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors (if terminal supports them)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[*]${NC} $1"; }
fail() { echo -e "  ${RED}[!]${NC} $1"; }

check_prereqs() {
    echo ""
    echo "═══ Checking prerequisites ═══"
    echo ""

    local all_ok=true

    # GNU assembler
    if command -v as &>/dev/null; then
        ok "as (GNU assembler): $(as --version | head -1)"
    else
        fail "as not found — apt install binutils"
        all_ok=false
    fi

    # Linker
    if command -v ld &>/dev/null; then
        ok "ld (GNU linker): $(ld --version | head -1)"
    else
        fail "ld not found — apt install binutils"
        all_ok=false
    fi

    # Kernel headers
    if [ -d "/lib/modules/$(uname -r)/build" ]; then
        ok "kernel headers: /lib/modules/$(uname -r)/build"
    else
        warn "kernel headers not installed — pic_kmod.ko build will be skipped"
        warn "install with: apt install linux-headers-$(uname -r)"
    fi

    # BCC
    if python3 -c "import bcc" 2>/dev/null; then
        ok "python3-bpfcc: installed"
    else
        warn "python3-bpfcc not installed — eBPF tools need it"
        warn "install with: apt install bpfcc-tools python3-bpfcc"
    fi

    # QEMU
    if command -v qemu-x86_64-static &>/dev/null; then
        ok "qemu-user-static: installed"
    else
        warn "qemu-user-static not installed — blob execution needs it"
        warn "install with: apt install qemu-user-static"
    fi

    # picblobs
    if python3 -c "import picblobs" 2>/dev/null; then
        ok "picblobs: installed"
    else
        warn "picblobs not installed"
        warn "install with: cd $PROJECT_ROOT && pip install -e '.[dev]'"
    fi

    echo ""
    if $all_ok; then
        ok "All required prerequisites met"
    fi
}

build_examples() {
    echo ""
    echo "═══ Building kernel blob examples ═══"
    echo ""
    python3 "$SCRIPT_DIR/kmod_loader/build_examples.py" --no-kmod
}

build_kmod() {
    echo ""
    echo "═══ Building kernel module ═══"
    echo ""
    if [ -d "/lib/modules/$(uname -r)/build" ]; then
        make -C "$SCRIPT_DIR/kmod_loader"
        if [ -f "$SCRIPT_DIR/kmod_loader/pic_kmod.ko" ]; then
            ok "pic_kmod.ko built ($(stat -c%s "$SCRIPT_DIR/kmod_loader/pic_kmod.ko") bytes)"
        fi
    else
        warn "Skipping — kernel headers not installed"
    fi
}

build_all() {
    echo ""
    echo "══════════════════════════════════════════"
    echo "  mbed lab builder"
    echo "══════════════════════════════════════════"

    check_prereqs
    build_examples
    build_kmod

    echo ""
    echo "═══ Build summary ═══"
    echo ""

    # List what was built
    if [ -d "$SCRIPT_DIR/kmod_loader/build" ]; then
        for f in "$SCRIPT_DIR/kmod_loader/build"/*.bin; do
            [ -f "$f" ] && ok "example: $(basename "$f") ($(stat -c%s "$f") bytes)"
        done
    fi

    [ -f "$SCRIPT_DIR/kmod_loader/pic_kmod.ko" ] && \
        ok "module: pic_kmod.ko"

    echo ""
    echo "eBPF tools (no build needed — pure Python + BCC):"
    for f in "$SCRIPT_DIR"/ebpf_*.py; do
        [ -f "$f" ] && ok "$(basename "$f")"
    done

    echo ""
    echo "Run examples:"
    echo "  sudo python3 kernel/kmod/build_examples.py --run nop_sled"
    echo "  sudo python3 kernel/kmod/build_examples.py --run hello_ring0"
    echo "  sudo python3 kernel/ebpf_kernel_mem.py kaslr"
    echo ""
    echo "VM testing (hermetic, safe for kernel modules):"
    echo "  python3 kernel/vm/vm_harness.py test       # run all tests in VM"
    echo "  python3 kernel/vm/vm_harness.py shell      # interactive VM"
    echo ""
    echo "Full lab guide: kernel/ebpf_loader_lab.md"
}

fetch_vm() {
    echo ""
    echo "═══ Fetching VM image ═══"
    echo ""
    python3 "$SCRIPT_DIR/vm_test/vm_harness.py" fetch
}

run_vm_tests() {
    echo ""
    echo "═══ Running kernel tests in VM ═══"
    echo ""
    python3 "$SCRIPT_DIR/vm_test/vm_harness.py" test "$@"
}

# Parse args
case "${1:-}" in
    --check)      check_prereqs ;;
    --examples)   build_examples ;;
    --kmod)       build_kmod ;;
    --fetch-vm)   fetch_vm ;;
    --vm-test)    shift; run_vm_tests "$@" ;;
    --vm-shell)   python3 "$SCRIPT_DIR/vm_test/vm_harness.py" shell ;;
    *)            build_all ;;
esac
