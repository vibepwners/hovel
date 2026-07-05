#!/usr/bin/env python3
"""
eBPF Custom Kernel Program Framework — Educational Red Team Lab Demo

Lets students write and load custom eBPF programs that run in kernel
context. Provides a set of ready-made templates and a framework for
writing new ones.

eBPF programs run INSIDE THE KERNEL — they execute in ring 0, on the
kernel's stack, with access to kernel data structures. The BPF verifier
ensures safety (bounded loops, valid memory access, no arbitrary writes)
but within those constraints you have full kernel visibility.

Templates provided:

  1. SYSCALL MONITOR   — Log all syscalls from a target process with
                         arguments and return values.

  2. FILE SNOOP        — Monitor all file opens/reads/writes from kernel
                         context. See what files a process touches.

  3. NET INSPECT       — XDP program that inspects packets at the NIC
                         level, before the kernel network stack.

  4. KEYLOG DETECT     — Hook keyboard input path to understand how
                         keyloggers intercept input, and detect them.

  5. CRED MONITOR      — Alert when any process's credentials change
                         (privilege escalation detection).

  6. CUSTOM            — Load your own BPF C program from a file.

Usage:
  # Run a built-in template
  sudo python3 mbed/ebpf_kernel_prog.py syscall-monitor --pid 1234
  sudo python3 mbed/ebpf_kernel_prog.py file-snoop --pid 1234
  sudo python3 mbed/ebpf_kernel_prog.py net-inspect --iface eth0
  sudo python3 mbed/ebpf_kernel_prog.py keylog-detect
  sudo python3 mbed/ebpf_kernel_prog.py cred-monitor

  # Load a custom program
  sudo python3 mbed/ebpf_kernel_prog.py custom --program my_prog.c

  # List available templates
  sudo python3 mbed/ebpf_kernel_prog.py list
"""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import os
import sys
import time
from pathlib import Path

# ===========================================================================
# Template 1: Syscall monitor
# ===========================================================================

BPF_SYSCALL_MONITOR = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TARGET_PID __TARGET_PID__

struct syscall_event_t {
    u64 ts_ns;          // timestamp
    u32 pid;
    u32 tid;
    u64 syscall_nr;
    u64 arg0, arg1, arg2, arg3;
    u64 ret;
    u8  is_exit;        // 0 = entry, 1 = exit
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

// Syscall name table (populated by userspace for display)
// We capture the raw number; Python translates it.

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID)
        return 0;

    struct syscall_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->syscall_nr = args->id;
    e->arg0 = args->args[0];
    e->arg1 = args->args[1];
    e->arg2 = args->args[2];
    e->arg3 = args->args[3];
    e->is_exit = 0;
    e->ret = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID)
        return 0;

    struct syscall_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->syscall_nr = args->id;
    e->ret = args->ret;
    e->is_exit = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
    return 0;
}
"""

# x86_64 syscall number → name (common ones)
SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    28: "madvise",
    32: "dup",
    33: "dup2",
    35: "nanosleep",
    39: "getpid",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    49: "bind",
    50: "listen",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    62: "kill",
    72: "fcntl",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    82: "rename",
    83: "mkdir",
    87: "unlink",
    89: "readlink",
    90: "chmod",
    92: "chown",
    102: "getuid",
    104: "getgid",
    110: "getppid",
    157: "prctl",
    186: "gettid",
    200: "tkill",
    217: "getdents64",
    231: "exit_group",
    257: "openat",
    262: "newfstatat",
    281: "epoll_pwait",
    290: "eventfd2",
    302: "prlimit64",
    318: "getrandom",
    332: "statx",
    435: "clone3",
}


def mode_syscall_monitor(args):
    """Template 1: Kernel-context syscall monitor."""
    from bcc import BPF

    pid = args.pid or 0
    src = BPF_SYSCALL_MONITOR.replace("__TARGET_PID__", str(pid))

    target_str = f"PID {pid}" if pid else "ALL processes"
    print("\n[*] ══════ KERNEL SYSCALL MONITOR ══════")
    print(f"[*] Target: {target_str}")
    print("[*] Tracing: raw_syscalls:sys_enter + sys_exit")
    print("[*] All events captured in kernel context")
    print("[*] Ctrl+C to stop\n")

    b = BPF(text=src)

    start_ts = [0]

    print(f"{'TIME':>12}  {'PID':>7}  {'COMM':<16}  {'SYSCALL':<16}  {'ARGS / RETURN'}")
    print(f"{'─' * 12}  {'─' * 7}  {'─' * 16}  {'─' * 16}  {'─' * 40}")

    def handle_event(ctx, data, size):
        event = b["events"].event(data)

        if not start_ts[0]:
            start_ts[0] = event.ts_ns

        ts = (event.ts_ns - start_ts[0]) / 1e9
        comm = event.comm.decode("utf-8", errors="replace")
        name = SYSCALL_NAMES.get(event.syscall_nr, f"syscall_{event.syscall_nr}")

        if event.is_exit:
            ret = event.ret
            if ret > 0xFFFFFFFF00000000:
                ret = -(0x10000000000000000 - ret)  # sign-extend
            print(
                f"{ts:>12.6f}  {event.pid:>7}  {comm:<16}  {'← ' + name:<16}  ret={ret}"
            )
        else:
            print(
                f"{ts:>12.6f}  {event.pid:>7}  {comm:<16}  "
                f"{'→ ' + name:<16}  "
                f"({event.arg0:#x}, {event.arg1:#x}, {event.arg2:#x})"
            )

    b["events"].open_ring_buffer(handle_event)

    try:
        while True:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Stopped")

    return 0


# ===========================================================================
# Template 2: File snoop
# ===========================================================================

BPF_FILE_SNOOP = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define TARGET_PID __TARGET_PID__

struct file_event_t {
    u64 ts_ns;
    u32 pid;
    u32 fd;
    u64 bytes;          // bytes read/written
    u8  op;             // 0=open, 1=read, 2=write, 3=close
    u32 flags;          // open flags
    int ret;            // return value
    char comm[16];
    char fname[128];    // filename
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

// --- openat ---
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;

    struct file_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->op = 0;
    e->flags = args->flags;
    e->fd = 0;
    e->bytes = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), args->filename);

    events.ringbuf_submit(e, 0);
    return 0;
}

// --- read ---
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;

    long ret = args->ret;
    if (ret <= 0) return 0;

    struct file_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->op = 1;
    e->bytes = (u64)ret;
    e->ret = ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->fname[0] = 0;

    events.ringbuf_submit(e, 0);
    return 0;
}

// --- write ---
TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;

    long ret = args->ret;
    if (ret <= 0) return 0;

    struct file_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->op = 2;
    e->bytes = (u64)ret;
    e->ret = ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->fname[0] = 0;

    events.ringbuf_submit(e, 0);
    return 0;
}
"""


def mode_file_snoop(args):
    """Template 2: Monitor file operations from kernel context."""
    from bcc import BPF

    pid = args.pid or 0
    src = BPF_FILE_SNOOP.replace("__TARGET_PID__", str(pid))

    target_str = f"PID {pid}" if pid else "ALL processes"
    print("\n[*] ══════ KERNEL FILE SNOOP ══════")
    print(f"[*] Target: {target_str}")
    print("[*] Tracing: openat, read, write")
    print("[*] Ctrl+C to stop\n")

    b = BPF(text=src)
    start_ts = [0]
    OP_NAMES = {0: "OPEN", 1: "READ", 2: "WRITE", 3: "CLOSE"}

    print(f"{'TIME':>10}  {'PID':>7}  {'COMM':<16}  {'OP':<6}  {'BYTES':>8}  {'FILE'}")
    print(f"{'─' * 10}  {'─' * 7}  {'─' * 16}  {'─' * 6}  {'─' * 8}  {'─' * 40}")

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        if not start_ts[0]:
            start_ts[0] = event.ts_ns
        ts = (event.ts_ns - start_ts[0]) / 1e9
        comm = event.comm.decode("utf-8", errors="replace")
        op = OP_NAMES.get(event.op, "?")
        fname = event.fname.decode("utf-8", errors="replace").rstrip("\x00")
        bytes_str = str(event.bytes) if event.bytes else ""
        print(
            f"{ts:>10.4f}  {event.pid:>7}  {comm:<16}  {op:<6}  {bytes_str:>8}  {fname}"
        )

    b["events"].open_ring_buffer(handle_event)

    try:
        while True:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    return 0


# ===========================================================================
# Template 3: Network packet inspector (XDP)
# ===========================================================================

BPF_NET_INSPECT = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

struct pkt_event_t {
    u64 ts_ns;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;       // IPPROTO_TCP, IPPROTO_UDP, etc.
    u32 pkt_len;
    u8  tcp_flags;      // SYN, ACK, FIN, RST, etc.
    u8  direction;      // 0=ingress
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

// XDP program — runs at the NIC level, BEFORE the kernel network stack.
// This is the earliest point you can inspect a packet in Linux.
int xdp_inspect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct pkt_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return XDP_PASS;

    e->ts_ns = bpf_ktime_get_ns();
    e->src_ip = ip->saddr;
    e->dst_ip = ip->daddr;
    e->protocol = ip->protocol;
    e->pkt_len = data_end - data;
    e->direction = 0;
    e->src_port = 0;
    e->dst_port = 0;
    e->tcp_flags = 0;

    // Parse transport header
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            e->src_port = __constant_ntohs(tcp->source);
            e->dst_port = __constant_ntohs(tcp->dest);
            e->tcp_flags = ((u8 *)tcp)[13]; // flags byte
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            e->src_port = __constant_ntohs(udp->source);
            e->dst_port = __constant_ntohs(udp->dest);
        }
    }

    events.ringbuf_submit(e, 0);
    return XDP_PASS;  // pass all packets through
}
"""


def ip_to_str(ip_int):
    """Convert network-byte-order u32 to dotted quad."""
    import socket
    import struct

    return socket.inet_ntoa(struct.pack("!I", ip_int))


def tcp_flags_str(flags):
    """Decode TCP flags byte."""
    names = []
    if flags & 0x02:
        names.append("SYN")
    if flags & 0x10:
        names.append("ACK")
    if flags & 0x01:
        names.append("FIN")
    if flags & 0x04:
        names.append("RST")
    if flags & 0x08:
        names.append("PSH")
    if flags & 0x20:
        names.append("URG")
    return "|".join(names) if names else ""


def mode_net_inspect(args):
    """Template 3: XDP packet inspector."""
    from bcc import BPF

    iface = args.iface or "eth0"

    print("\n[*] ══════ XDP NETWORK INSPECTOR ══════")
    print(f"[*] Interface: {iface}")
    print("[*] Attachment point: XDP (pre-stack, NIC level)")
    print("[*] This runs in kernel context before any packet processing")
    print("[*] Ctrl+C to stop\n")

    b = BPF(text=BPF_NET_INSPECT)
    fn = b.load_func("xdp_inspect", BPF.XDP)
    b.attach_xdp(iface, fn, 0)  # flags=0 = generic XDP

    start_ts = [0]
    PROTO = {6: "TCP", 17: "UDP", 1: "ICMP"}

    print(
        f"{'TIME':>10}  {'PROTO':<5}  {'SOURCE':<21}  {'DEST':<21}  "
        f"{'LEN':>5}  {'FLAGS'}"
    )
    print(f"{'─' * 10}  {'─' * 5}  {'─' * 21}  {'─' * 21}  {'─' * 5}  {'─' * 15}")

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        if not start_ts[0]:
            start_ts[0] = event.ts_ns
        ts = (event.ts_ns - start_ts[0]) / 1e9

        proto = PROTO.get(event.protocol, str(event.protocol))
        src = ip_to_str(event.src_ip)
        dst = ip_to_str(event.dst_ip)
        if event.src_port:
            src = f"{src}:{event.src_port}"
            dst = f"{dst}:{event.dst_port}"
        flags = tcp_flags_str(event.tcp_flags)

        print(
            f"{ts:>10.4f}  {proto:<5}  {src:<21}  {dst:<21}  "
            f"{event.pkt_len:>5}  {flags}"
        )

    b["events"].open_ring_buffer(handle_event)

    try:
        while True:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass
    finally:
        b.remove_xdp(iface, 0)
        print(f"\n[*] XDP program detached from {iface}")
    return 0


# ===========================================================================
# Template 4: Keylog detector
# ===========================================================================

BPF_KEYLOG_DETECT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/input.h>

struct key_event_t {
    u64 ts_ns;
    u32 pid;
    u16 type;     // EV_KEY, EV_REL, etc.
    u16 code;     // KEY_A, KEY_B, etc.
    s32 value;    // 0=release, 1=press, 2=repeat
    char comm[16];
    char dev[64]; // device name from kprobe arg
};

BPF_RINGBUF_OUTPUT(events, 1 << 16);
BPF_HASH(readers, u32, u64, 256);  // PIDs reading from input devices

// Hook input_event — called when ANY input event is delivered to handlers.
// This is the kernel function that dispatches keyboard/mouse events.
// A keylogger must either:
//   1. Read from /dev/input/eventN (we detect via openat hook)
//   2. Hook input_event itself (we detect by being here first)
//   3. Use a kernel module (detected by module enumeration)
int trace_input_event(struct pt_regs *ctx) {
    struct input_dev *dev = (struct input_dev *)PT_REGS_PARM1(ctx);
    unsigned int type = (unsigned int)PT_REGS_PARM2(ctx);
    unsigned int code = (unsigned int)PT_REGS_PARM3(ctx);
    int value = (int)PT_REGS_PARM4(ctx);

    // Only keyboard events
    if (type != EV_KEY)
        return 0;

    // Only key press (not release or repeat)
    if (value != 1)
        return 0;

    struct key_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = type;
    e->code = code;
    e->value = value;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read device name
    if (dev) {
        const char *name;
        bpf_probe_read_kernel(&name, sizeof(name), &dev->name);
        if (name)
            bpf_probe_read_kernel_str(e->dev, sizeof(e->dev), name);
    }

    events.ringbuf_submit(e, 0);
    return 0;
}

// Detect processes opening /dev/input/* — potential keyloggers
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char fname[32] = {};
    bpf_probe_read_user_str(fname, sizeof(fname), args->filename);

    // Check if opening an input device
    // "/dev/input/" prefix check
    if (fname[0] == '/' && fname[1] == 'd' && fname[2] == 'e' &&
        fname[3] == 'v' && fname[4] == '/' && fname[5] == 'i' &&
        fname[6] == 'n' && fname[7] == 'p') {

        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 ts = bpf_ktime_get_ns();
        readers.update(&pid, &ts);

        // Emit alert
        struct key_event_t *e = events.ringbuf_reserve(sizeof(*e));
        if (e) {
            e->ts_ns = ts;
            e->pid = pid;
            e->type = 0xFFFF;  // sentinel: input device opened
            e->code = 0;
            e->value = 0;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_probe_read_user_str(e->dev, sizeof(e->dev), args->filename);
            events.ringbuf_submit(e, 0);
        }
    }

    return 0;
}
"""

KEY_NAMES = {
    1: "ESC",
    2: "1",
    3: "2",
    4: "3",
    5: "4",
    6: "5",
    7: "6",
    8: "7",
    9: "8",
    10: "9",
    11: "0",
    14: "BACKSPACE",
    15: "TAB",
    16: "Q",
    17: "W",
    18: "E",
    19: "R",
    20: "T",
    21: "Y",
    22: "U",
    23: "I",
    24: "O",
    25: "P",
    28: "ENTER",
    29: "L_CTRL",
    30: "A",
    31: "S",
    32: "D",
    33: "F",
    34: "G",
    35: "H",
    36: "J",
    37: "K",
    38: "L",
    42: "L_SHIFT",
    44: "Z",
    45: "X",
    46: "C",
    47: "V",
    48: "B",
    49: "N",
    50: "M",
    54: "R_SHIFT",
    56: "L_ALT",
    57: "SPACE",
    58: "CAPSLOCK",
    97: "R_CTRL",
    100: "R_ALT",
    125: "L_META",
}


def mode_keylog_detect(args):
    """Template 4: Keyboard input monitor and keylogger detector."""
    from bcc import BPF

    print("\n[*] ══════ KERNEL KEYBOARD MONITOR ══════")
    print("[*] Hooking: input_event (kernel input subsystem)")
    print("[*] Also watching: openat for /dev/input/* access")
    print("[*] This shows how keyloggers intercept input")
    print("[*] and how to detect processes reading input devices")
    print("[*] Ctrl+C to stop\n")

    b = BPF(text=BPF_KEYLOG_DETECT)
    b.attach_kprobe(event="input_event", fn_name="trace_input_event")

    start_ts = [0]
    suspicious_pids = set()

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        if not start_ts[0]:
            start_ts[0] = event.ts_ns
        ts = (event.ts_ns - start_ts[0]) / 1e9
        comm = event.comm.decode("utf-8", errors="replace")
        dev = event.dev.decode("utf-8", errors="replace").rstrip("\x00")

        if event.type == 0xFFFF:
            # Input device opened — potential keylogger alert
            suspicious_pids.add(event.pid)
            print(f"\n[!] ALERT: PID {event.pid} ({comm}) opened {dev}")
            print("[!] This process may be a keylogger!\n")
        else:
            key = KEY_NAMES.get(event.code, f"KEY_{event.code}")
            marker = " [!]" if event.pid in suspicious_pids else ""
            print(
                f"{ts:>10.4f}  {event.pid:>7}  {comm:<16}  "
                f"KEY: {key:<12}  dev: {dev}{marker}"
            )

    b["events"].open_ring_buffer(handle_event)

    try:
        while True:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass

    if suspicious_pids:
        print(
            f"\n[!] Suspicious PIDs that opened /dev/input/*: {sorted(suspicious_pids)}"
        )
    print("[*] Stopped")
    return 0


# ===========================================================================
# Template 5: Credential change monitor (privilege escalation detection)
# ===========================================================================

BPF_CRED_MONITOR = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>

struct cred_change_t {
    u64 ts_ns;
    u32 pid;
    u32 old_uid, new_uid;
    u32 old_euid, new_euid;
    u64 old_cap_eff, new_cap_eff;
    u64 caller_ip;        // who called commit_creds
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 1 << 16);

// Hook commit_creds — THE kernel function that changes a process's
// credentials. Every setuid(), setgid(), capset(), and privilege
// escalation exploit ultimately calls this function.
//
// By hooking it, we see EVERY credential change on the system.
int trace_commit_creds(struct pt_regs *ctx) {
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct cred_change_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->caller_ip = PT_REGS_IP(ctx);

    // Read OLD credentials (current task's real_cred)
    const struct cred *old_cred;
    bpf_probe_read_kernel(&old_cred, sizeof(old_cred), &task->real_cred);
    if (old_cred) {
        bpf_probe_read_kernel(&e->old_uid, sizeof(u32), &old_cred->uid);
        bpf_probe_read_kernel(&e->old_euid, sizeof(u32), &old_cred->euid);
        kernel_cap_t cap;
        bpf_probe_read_kernel(&cap, sizeof(cap), &old_cred->cap_effective);
        e->old_cap_eff = *(u64 *)&cap;
    }

    // Read NEW credentials (the cred being committed)
    if (new_cred) {
        bpf_probe_read_kernel(&e->new_uid, sizeof(u32), &new_cred->uid);
        bpf_probe_read_kernel(&e->new_euid, sizeof(u32), &new_cred->euid);
        kernel_cap_t cap;
        bpf_probe_read_kernel(&cap, sizeof(cap), &new_cred->cap_effective);
        e->new_cap_eff = *(u64 *)&cap;
    }

    events.ringbuf_submit(e, 0);
    return 0;
}
"""


def mode_cred_monitor(args):
    """Template 5: Monitor all credential changes system-wide."""
    from bcc import BPF

    print("\n[*] ══════ KERNEL CREDENTIAL CHANGE MONITOR ══════")
    print("[*] Hooking: commit_creds (kernel credential update path)")
    print("[*] Every setuid, capset, and privesc goes through this function")
    print("[*] Ctrl+C to stop\n")

    b = BPF(text=BPF_CRED_MONITOR)
    b.attach_kprobe(event="commit_creds", fn_name="trace_commit_creds")

    start_ts = [0]

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        if not start_ts[0]:
            start_ts[0] = event.ts_ns
        ts = (event.ts_ns - start_ts[0]) / 1e9
        comm = event.comm.decode("utf-8", errors="replace")

        uid_changed = event.old_uid != event.new_uid
        euid_changed = event.old_euid != event.new_euid
        cap_changed = event.old_cap_eff != event.new_cap_eff
        privesc = event.old_euid != 0 and event.new_euid == 0

        if privesc:
            print(f"\n{'!' * 72}")
            print("[!!!] PRIVILEGE ESCALATION DETECTED")
            print(
                f"[!!!] PID {event.pid} ({comm}) went from "
                f"euid={event.old_euid} → euid=0 (ROOT)"
            )
            print(f"[!!!] Caller: {event.caller_ip:#018x}")
            print(f"{'!' * 72}\n")
        elif uid_changed or euid_changed:
            print(
                f"{ts:>10.4f}  PID {event.pid:>7}  {comm:<16}  "
                f"uid: {event.old_uid}→{event.new_uid}  "
                f"euid: {event.old_euid}→{event.new_euid}"
            )
        elif cap_changed:
            print(
                f"{ts:>10.4f}  PID {event.pid:>7}  {comm:<16}  "
                f"caps: {event.old_cap_eff:#x}→{event.new_cap_eff:#x}"
            )

    b["events"].open_ring_buffer(handle_event)

    try:
        while True:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass

    print("\n[*] Stopped")
    return 0


# ===========================================================================
# Template 6: Custom program loader
# ===========================================================================


def mode_custom(args):
    """Load and run a custom BPF C program from a file."""
    from bcc import BPF

    prog_path = Path(args.program)
    if not prog_path.exists():
        print(f"[!] Program file not found: {prog_path}")
        return 1

    src = prog_path.read_text()

    print("\n[*] ══════ CUSTOM eBPF PROGRAM ══════")
    print(f"[*] Loading: {prog_path}")
    print(f"[*] Size: {len(src)} bytes")
    print()

    # Replace common placeholders
    if args.pid:
        src = src.replace("__TARGET_PID__", str(args.pid))

    try:
        b = BPF(text=src)
    except Exception as e:
        print("[!] BPF compilation/verification failed:")
        print(f"    {e}")
        print("\n[*] Common issues:")
        print("    - BPF verifier rejected the program (too complex, unbounded loops)")
        print("    - Missing kernel headers for struct definitions")
        print("    - Invalid memory access (forgot bpf_probe_read_kernel)")
        return 1

    print("[+] Program loaded and verified successfully!")
    print("[*] The BPF verifier accepted your program — it's now in kernel")
    print("[*] Press Ctrl+C to unload\n")

    # If the program has a ring buffer named 'events', print events
    try:

        def handle_event(ctx, data, size):
            raw = ctypes.string_at(data, size)
            print(f"[event] {size} bytes: {raw[:64].hex()}")

        b["events"].open_ring_buffer(handle_event)
        has_events = True
    except KeyError:
        has_events = False
        print("[*] No 'events' ring buffer found — program runs silently")

    try:
        while True:
            if has_events:
                b.ring_buffer_poll(timeout=100)
            else:
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    print("\n[*] Program unloaded from kernel")
    return 0


# ===========================================================================
# List templates
# ===========================================================================


def mode_list(args):
    """List available templates with descriptions."""
    print("\n[*] ══════ AVAILABLE KERNEL PROGRAM TEMPLATES ══════\n")

    templates = [
        (
            "syscall-monitor",
            "Log all syscalls with args/return values",
            "sudo python3 mbed/ebpf_kernel_prog.py syscall-monitor --pid 1234",
        ),
        (
            "file-snoop",
            "Monitor file open/read/write from kernel",
            "sudo python3 mbed/ebpf_kernel_prog.py file-snoop --pid 1234",
        ),
        (
            "net-inspect",
            "XDP packet inspector (NIC level, pre-stack)",
            "sudo python3 mbed/ebpf_kernel_prog.py net-inspect --iface eth0",
        ),
        (
            "keylog-detect",
            "Keyboard input monitor + keylogger detection",
            "sudo python3 mbed/ebpf_kernel_prog.py keylog-detect",
        ),
        (
            "cred-monitor",
            "Privilege escalation detector (hooks commit_creds)",
            "sudo python3 mbed/ebpf_kernel_prog.py cred-monitor",
        ),
        (
            "custom",
            "Load your own BPF C program from a file",
            "sudo python3 mbed/ebpf_kernel_prog.py custom --program my.c",
        ),
    ]

    for name, desc, example in templates:
        print(f"  {name:<20}  {desc}")
        print(f"  {'':20}  $ {example}\n")

    print("Writing custom programs:")
    print("  Create a .c file with BPF C code. You can use:")
    print("    - bpf_probe_read_kernel()     read kernel memory")
    print("    - bpf_probe_write_user()      write to userspace memory")
    print("    - bpf_get_current_task()      get current task_struct")
    print("    - bpf_get_current_pid_tgid()  get PID/TID")
    print("    - bpf_get_current_comm()      get process name")
    print("    - bpf_ktime_get_ns()          nanosecond timestamp")
    print("    - BPF_RINGBUF_OUTPUT()        ring buffer for events")
    print("    - BPF_HASH / BPF_ARRAY        maps for state")
    print()
    print("  The BPF verifier will reject unsafe programs.")
    print("  Use __TARGET_PID__ as a placeholder — replaced by --pid.\n")

    return 0


# ===========================================================================
# Main
# ===========================================================================


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Custom Kernel Program Framework — Red Team Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Templates run eBPF programs in KERNEL CONTEXT (ring 0).
They can read kernel memory, hook syscalls, inspect packets,
and monitor credential changes — all from inside the kernel.

Examples:
  sudo python3 mbed/ebpf_kernel_prog.py syscall-monitor --pid 1234
  sudo python3 mbed/ebpf_kernel_prog.py cred-monitor
  sudo python3 mbed/ebpf_kernel_prog.py net-inspect --iface eth0
  sudo python3 mbed/ebpf_kernel_prog.py custom --program my_prog.c
  sudo python3 mbed/ebpf_kernel_prog.py list
        """,
    )

    subs = parser.add_subparsers(dest="template", required=True)

    p1 = subs.add_parser("syscall-monitor", help="Trace syscalls from kernel")
    p1.add_argument("--pid", type=int, default=0)

    p2 = subs.add_parser("file-snoop", help="Monitor file I/O from kernel")
    p2.add_argument("--pid", type=int, default=0)

    p3 = subs.add_parser("net-inspect", help="XDP packet inspector")
    p3.add_argument("--iface", default="eth0")

    subs.add_parser("keylog-detect", help="Keyboard monitor + detection")

    subs.add_parser("cred-monitor", help="Privilege escalation detector")

    p6 = subs.add_parser("custom", help="Load custom BPF program")
    p6.add_argument("--program", required=True, help="Path to BPF C source")
    p6.add_argument("--pid", type=int, default=0)

    subs.add_parser("list", help="List available templates")

    args = parser.parse_args()

    if args.template != "list" and os.geteuid() != 0:
        print("[!] Requires root for eBPF program loading")
        return 1

    if args.template != "list" and importlib.util.find_spec("bcc") is None:
        print("ERROR: BCC not installed.")
        print("Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    handlers = {
        "syscall-monitor": mode_syscall_monitor,
        "file-snoop": mode_file_snoop,
        "net-inspect": mode_net_inspect,
        "keylog-detect": mode_keylog_detect,
        "cred-monitor": mode_cred_monitor,
        "custom": mode_custom,
        "list": mode_list,
    }

    return handlers[args.template](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
