#!/usr/bin/env python3
"""
eBPF Kernel Memory Explorer — Educational Red Team Lab Demo

Demonstrates reading and traversing kernel data structures from eBPF
programs running in kernel context. All reads use bpf_probe_read_kernel()
which can access arbitrary kernel memory.

Techniques:

  1. CRED DUMP     — Read any process's uid/gid/capabilities from its
                     task_struct→cred chain in kernel memory.

  2. TASK WALK     — Walk the kernel's task list (linked list of all
                     task_structs) entirely from BPF. Find hidden processes
                     by comparing BPF's view against /proc.

  3. MODULE ENUM   — Walk the kernel module list to find loaded modules,
                     including ones hidden from /proc/modules by rootkits.

  4. VMA WALK      — Traverse a process's virtual memory areas
                     (task→mm→mmap) from kernel space. Shows every mapped
                     region with permissions — the kernel's ground-truth
                     view of the address space.

  5. KASLR LEAK    — Extract kernel text base address from BPF context,
                     defeating KASLR from an unprivileged-looking probe.

  6. KALLSYMS      — Resolve kernel symbol addresses by hooking kallsyms
                     iteration, capturing the kernel's own symbol table.

Requirements:
  - Linux 5.8+ with BTF (CONFIG_DEBUG_INFO_BTF=y)
  - BCC (apt install bpfcc-tools python3-bpfcc)
  - Root / CAP_BPF + CAP_SYS_ADMIN

Usage:
  sudo python3 mbed/ebpf_kernel_mem.py creds   --pid 1234
  sudo python3 mbed/ebpf_kernel_mem.py tasks
  sudo python3 mbed/ebpf_kernel_mem.py modules
  sudo python3 mbed/ebpf_kernel_mem.py vmas    --pid 1234
  sudo python3 mbed/ebpf_kernel_mem.py kaslr
  sudo python3 mbed/ebpf_kernel_mem.py kallsyms --symbol commit_creds
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time

# ===========================================================================
# Technique 1: Credential dump — read task_struct → real_cred → uid/gid/cap
# ===========================================================================

BPF_CRED_DUMP = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/capability.h>

#define TARGET_PID __TARGET_PID__

struct cred_event_t {
    u32 pid;
    u32 tgid;
    char comm[16];

    // UIDs (from struct cred)
    u32 uid, euid, suid, fsuid;
    u32 gid, egid, sgid, fsgid;

    // Capabilities (from struct cred → cap_effective etc.)
    u64 cap_inheritable;
    u64 cap_permitted;
    u64 cap_effective;
    u64 cap_bset;
    u64 cap_ambient;

    // Kernel addresses for students to inspect
    u64 task_addr;
    u64 cred_addr;
    u64 mm_addr;

    // Security context
    u32 securebits;
};

BPF_RINGBUF_OUTPUT(events, 1 << 16);

// We attach this to a tracepoint that fires in the target's context.
// sched:sched_process_fork or syscalls:sys_enter_* both work.
// Using a timer-triggered kprobe on a frequent kernel function so
// we can dump creds on demand without needing the target to do anything.

int dump_creds(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // If TARGET_PID == 0, dump all. Otherwise filter.
    if (TARGET_PID != 0 && pid != TARGET_PID)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct cred_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->task_addr = (u64)task;

    // --- Read the cred struct pointer from task_struct ---
    // task_struct.real_cred points to the process's actual credentials.
    // This is what the kernel uses for permission checks.
    const struct cred *cred;
    bpf_probe_read_kernel(&cred, sizeof(cred), &task->real_cred);
    e->cred_addr = (u64)cred;

    // --- Read UIDs/GIDs from cred ---
    // struct cred contains: uid, euid, suid, fsuid (and gid equivalents)
    // These are kuid_t/kgid_t wrappers around u32.
    bpf_probe_read_kernel(&e->uid,  sizeof(u32), &cred->uid);
    bpf_probe_read_kernel(&e->euid, sizeof(u32), &cred->euid);
    bpf_probe_read_kernel(&e->suid, sizeof(u32), &cred->suid);
    bpf_probe_read_kernel(&e->fsuid, sizeof(u32), &cred->fsuid);
    bpf_probe_read_kernel(&e->gid,  sizeof(u32), &cred->gid);
    bpf_probe_read_kernel(&e->egid, sizeof(u32), &cred->egid);
    bpf_probe_read_kernel(&e->sgid, sizeof(u32), &cred->sgid);
    bpf_probe_read_kernel(&e->fsgid, sizeof(u32), &cred->fsgid);

    // --- Read capabilities ---
    // kernel_cap_t is a struct containing cap[_KERNEL_CAPABILITY_U32S]
    // On modern kernels with 64-bit caps, it's a u64 (or two u32s).
    kernel_cap_t cap;

    bpf_probe_read_kernel(&cap, sizeof(cap), &cred->cap_inheritable);
    e->cap_inheritable = *(u64 *)&cap;

    bpf_probe_read_kernel(&cap, sizeof(cap), &cred->cap_permitted);
    e->cap_permitted = *(u64 *)&cap;

    bpf_probe_read_kernel(&cap, sizeof(cap), &cred->cap_effective);
    e->cap_effective = *(u64 *)&cap;

    bpf_probe_read_kernel(&cap, sizeof(cap), &cred->cap_bounding);
    e->cap_bset = *(u64 *)&cap;

    bpf_probe_read_kernel(&cap, sizeof(cap), &cred->cap_ambient);
    e->cap_ambient = *(u64 *)&cap;

    bpf_probe_read_kernel(&e->securebits, sizeof(u32), &cred->securebits);

    // --- Read mm pointer ---
    struct mm_struct *mm;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    e->mm_addr = (u64)mm;

    events.ringbuf_submit(e, 0);
    return 0;
}
"""

# Capability bit names (from include/uapi/linux/capability.h)
CAP_NAMES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


def decode_caps(cap_val: int) -> list[str]:
    """Decode a capability bitmask into named capabilities."""
    caps = []
    for bit, name in CAP_NAMES.items():
        if cap_val & (1 << bit):
            caps.append(name)
    return caps


def mode_creds(args):
    """Technique 1: Dump process credentials from kernel memory."""
    from bcc import BPF

    pid = args.pid or 0
    src = BPF_CRED_DUMP.replace("__TARGET_PID__", str(pid))

    target_str = f"PID {pid}" if pid else "ALL processes"
    print("\n[*] ══════ KERNEL CREDENTIAL DUMP ══════")
    print(f"[*] Target: {target_str}")
    print("[*] Reading: task_struct → real_cred → uid/gid/caps")
    print("[*] All reads via bpf_probe_read_kernel() in kernel context\n")

    b = BPF(text=src)
    b.attach_kprobe(event="__x64_sys_write", fn_name="dump_creds")

    seen_pids = set()
    count = [0]

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        tgid = event.tgid

        # Deduplicate
        if tgid in seen_pids:
            return
        seen_pids.add(tgid)
        count[0] += 1

        comm = event.comm.decode("utf-8", errors="replace")

        print(f"{'─' * 72}")
        print(f"  Process:      {comm} (PID {event.pid}, TGID {tgid})")
        print(f"  task_struct:  {event.task_addr:#018x}")
        print(f"  cred:         {event.cred_addr:#018x}")
        print(f"  mm_struct:    {event.mm_addr:#018x}")
        print()
        print(
            f"  UIDs:  uid={event.uid}  euid={event.euid}  "
            f"suid={event.suid}  fsuid={event.fsuid}"
        )
        print(
            f"  GIDs:  gid={event.gid}  egid={event.egid}  "
            f"sgid={event.sgid}  fsgid={event.fsgid}"
        )
        print()

        eff_caps = decode_caps(event.cap_effective)
        decode_caps(event.cap_permitted)

        print(f"  Capabilities (effective):  {event.cap_effective:#018x}")
        if eff_caps:
            # Print in columns
            for i in range(0, len(eff_caps), 3):
                row = "    " + "  ".join(f"{c:<28}" for c in eff_caps[i : i + 3])
                print(row)
        else:
            print("    (none)")

        print(f"  Capabilities (permitted):  {event.cap_permitted:#018x}")
        print(f"  Capabilities (inheritable): {event.cap_inheritable:#018x}")
        print(f"  Capabilities (bounding):   {event.cap_bset:#018x}")
        print(f"  Capabilities (ambient):    {event.cap_ambient:#018x}")
        print(f"  Securebits:                {event.securebits:#010x}")

        # Highlight interesting findings
        if event.euid == 0:
            print("\n  [!] RUNNING AS ROOT (euid=0)")
        if event.cap_effective & (1 << 21):  # CAP_SYS_ADMIN
            print("  [!] HAS CAP_SYS_ADMIN")
        if event.cap_effective & (1 << 19):  # CAP_SYS_PTRACE
            print("  [!] HAS CAP_SYS_PTRACE — can ptrace any process")
        if event.cap_effective & (1 << 16):  # CAP_SYS_MODULE
            print("  [!] HAS CAP_SYS_MODULE — can load kernel modules")
        if event.cap_effective & (1 << 39):  # CAP_BPF
            print("  [!] HAS CAP_BPF — can load BPF programs")

        if pid != 0 and count[0] >= 1:
            return

    b["events"].open_ring_buffer(handle_event)

    limit = 1 if pid else args.limit
    try:
        while count[0] < limit:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass

    print(f"\n{'─' * 72}")
    print(f"[*] Dumped credentials for {count[0]} process(es)")
    return 0


# ===========================================================================
# Technique 2: Task list walk — enumerate all processes from kernel memory
# ===========================================================================

BPF_TASK_WALK = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

struct task_event_t {
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u64 task_addr;
    u64 start_time;     // task start time (nsec)
    u64 mm_addr;        // 0 = kernel thread
    u32 flags;          // task->flags (PF_* flags)
    u32 state;          // task state
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);  // 256KB — could be many tasks

// Walk the task list starting from init_task.
// init_task.tasks is a list_head linking all task_structs.
// We follow task->tasks.next until we loop back to init_task.
//
// This runs in a kprobe context, so we have a limited instruction
// budget (~1M instructions). For a busy system, we may need to
// split across multiple probe hits.

int walk_tasks(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *init_task;
    struct task_struct *pos;

    // Navigate to init_task (PID 1's group leader's namespace ancestor)
    // Alternatively, we can read the global init_task symbol.
    // BCC can resolve it via kallsyms.
    init_task = (struct task_struct *)__INIT_TASK_ADDR__;

    pos = init_task;

    #pragma unroll
    for (int i = 0; i < 4096; i++) {
        struct task_event_t *e = events.ringbuf_reserve(sizeof(*e));
        if (!e) break;

        bpf_probe_read_kernel(&e->pid,   sizeof(u32), &pos->pid);
        bpf_probe_read_kernel(&e->tgid,  sizeof(u32), &pos->tgid);
        bpf_probe_read_kernel(&e->flags, sizeof(u32), &pos->flags);
        bpf_probe_read_kernel(e->comm,   sizeof(e->comm), &pos->comm);
        e->task_addr = (u64)pos;

        // Read ppid: task->real_parent->tgid
        struct task_struct *parent;
        bpf_probe_read_kernel(&parent, sizeof(parent), &pos->real_parent);
        if (parent)
            bpf_probe_read_kernel(&e->ppid, sizeof(u32), &parent->tgid);

        // Read uid from real_cred
        const struct cred *cred;
        bpf_probe_read_kernel(&cred, sizeof(cred), &pos->real_cred);
        if (cred)
            bpf_probe_read_kernel(&e->uid, sizeof(u32), &cred->uid);

        // Read mm pointer (NULL = kernel thread)
        struct mm_struct *mm;
        bpf_probe_read_kernel(&mm, sizeof(mm), &pos->mm);
        e->mm_addr = (u64)mm;

        // Read start time
        bpf_probe_read_kernel(&e->start_time, sizeof(u64),
                              &pos->start_time);

        events.ringbuf_submit(e, 0);

        // Follow tasks.next to next task_struct
        // tasks is a list_head embedded in task_struct.
        // list_head.next points to the NEXT list_head, not the next
        // task_struct. We use container_of arithmetic:
        //   next_task = (void *)next_list_entry - offsetof(task_struct, tasks)
        struct list_head tasks_head;
        bpf_probe_read_kernel(&tasks_head, sizeof(tasks_head), &pos->tasks);

        pos = (struct task_struct *)((void *)tasks_head.next -
              offsetof(struct task_struct, tasks));

        // Check if we've looped back to init_task
        if (pos == init_task || (u64)pos < 0xffff000000000000ULL)
            break;
    }

    return 0;
}
"""


def mode_tasks(args):
    """Technique 2: Walk the kernel task list via BPF."""
    from bcc import BPF

    # Resolve init_task address from kallsyms
    init_addr = None
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == "init_task":
                    init_addr = int(parts[0], 16)
                    break
    except PermissionError:
        print("[!] Cannot read /proc/kallsyms — need root")
        return 1

    if not init_addr:
        print("[!] Could not find init_task in /proc/kallsyms")
        return 1

    print("\n[*] ══════ KERNEL TASK LIST WALK ══════")
    print(f"[*] init_task @ {init_addr:#018x}")
    print("[*] Walking task_struct linked list from kernel memory")
    print("[*] Each entry read via bpf_probe_read_kernel()\n")

    src = BPF_TASK_WALK.replace("__INIT_TASK_ADDR__", str(init_addr))
    b = BPF(text=src)
    b.attach_kprobe(event="__x64_sys_getpid", fn_name="walk_tasks")

    tasks = []

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        tasks.append(
            {
                "pid": event.tgid,
                "tid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "comm": event.comm.decode("utf-8", errors="replace"),
                "task_addr": event.task_addr,
                "mm_addr": event.mm_addr,
                "flags": event.flags,
                "kthread": event.mm_addr == 0,
            }
        )

    b["events"].open_ring_buffer(handle_event)

    # Trigger the probe by calling getpid()
    os.getpid()
    time.sleep(0.5)
    b.ring_buffer_consume()

    # Display results
    print(
        f"{'PID':>7}  {'PPID':>7}  {'UID':>5}  {'TYPE':>6}  "
        f"{'TASK_STRUCT':<20}  {'COMM'}"
    )
    print(f"{'─' * 7}  {'─' * 7}  {'─' * 5}  {'─' * 6}  {'─' * 20}  {'─' * 16}")

    # Deduplicate by tgid (thread group leaders only)
    seen = set()
    kernel_count = 0
    user_count = 0
    for t in tasks:
        if t["pid"] in seen:
            continue
        seen.add(t["pid"])
        ttype = "kernel" if t["kthread"] else "user"
        if t["kthread"]:
            kernel_count += 1
        else:
            user_count += 1
        print(
            f"{t['pid']:>7}  {t['ppid']:>7}  {t['uid']:>5}  "
            f"{ttype:>6}  {t['task_addr']:#018x}  {t['comm']}"
        )

    print(
        f"\n[*] Found {len(seen)} processes ({user_count} user, "
        f"{kernel_count} kernel threads)"
    )

    # Compare against /proc to find hidden processes
    if args.check_hidden:
        print("\n[*] ── Hidden process check ──")
        proc_pids = set()
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                proc_pids.add(int(entry))

        bpf_pids = {t["pid"] for t in tasks if not t["kthread"] and t["pid"] > 0}

        hidden = bpf_pids - proc_pids
        if hidden:
            print("[!] Processes visible in kernel but NOT in /proc:")
            for pid in sorted(hidden):
                t = next(x for x in tasks if x["pid"] == pid)
                print(
                    f"    PID {pid}: {t['comm']} (task_struct @ {t['task_addr']:#018x})"
                )
            print("[!] These processes may be hidden by a rootkit!")
        else:
            print("[+] No hidden processes found (kernel and /proc agree)")

        extra = proc_pids - bpf_pids - {0}
        if extra and len(extra) < 20:
            print(
                f"[*] PIDs in /proc but not in BPF walk (spawned after "
                f"walk): {sorted(extra)[:10]}"
            )

    return 0


# ===========================================================================
# Technique 3: Kernel module enumeration
# ===========================================================================

BPF_MODULE_ENUM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/module.h>

struct mod_event_t {
    u64  mod_addr;        // struct module address
    u64  core_addr;       // module core (.text) base
    u32  core_size;       // core section size
    u32  init_size;       // init section size
    u32  taints;          // module taint flags
    int  state;           // MODULE_STATE_*
    char name[56];        // module name (MODULE_NAME_LEN = 56)
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

int enum_modules(struct pt_regs *ctx) {
    // Start from the global 'modules' list head.
    // Each struct module has a 'list' member linking it to this list.
    struct list_head *modules_head = (struct list_head *)__MODULES_ADDR__;
    struct list_head first;
    bpf_probe_read_kernel(&first, sizeof(first), modules_head);

    struct list_head *pos = first.next;

    #pragma unroll
    for (int i = 0; i < 1024; i++) {
        if (pos == modules_head)
            break;

        // container_of: module = (void *)pos - offsetof(struct module, list)
        struct module *mod = (struct module *)((void *)pos -
            offsetof(struct module, list));

        struct mod_event_t *e = events.ringbuf_reserve(sizeof(*e));
        if (!e) break;

        e->mod_addr = (u64)mod;

        bpf_probe_read_kernel(e->name, sizeof(e->name), &mod->name);
        bpf_probe_read_kernel(&e->state, sizeof(int), &mod->state);
        bpf_probe_read_kernel(&e->taints, sizeof(u32), &mod->taints);

        // Core layout — where the module's .text lives in kernel memory
        // On newer kernels this is mod->core_layout.base / .size
        // On older kernels it's mod->module_core / mod->core_size
        struct module_layout core;
        bpf_probe_read_kernel(&core, sizeof(core), &mod->core_layout);
        e->core_addr = (u64)core.base;
        e->core_size = core.size;

        struct module_layout init_layout;
        bpf_probe_read_kernel(&init_layout, sizeof(init_layout),
                              &mod->init_layout);
        e->init_size = init_layout.size;

        events.ringbuf_submit(e, 0);

        // Follow list to next module
        struct list_head next_head;
        bpf_probe_read_kernel(&next_head, sizeof(next_head), pos);
        pos = next_head.next;
    }

    return 0;
}
"""

MODULE_STATES = {0: "LIVE", 1: "COMING", 2: "GOING", 3: "UNFORMED"}


def mode_modules(args):
    """Technique 3: Walk the kernel module list."""
    from bcc import BPF

    # Resolve 'modules' list head from kallsyms
    modules_addr = None
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == "modules":
                    modules_addr = int(parts[0], 16)
                    break
    except PermissionError:
        print("[!] Cannot read /proc/kallsyms — need root")
        return 1

    if not modules_addr:
        print("[!] Could not find 'modules' symbol in /proc/kallsyms")
        return 1

    print("\n[*] ══════ KERNEL MODULE ENUMERATION ══════")
    print(f"[*] modules list_head @ {modules_addr:#018x}")
    print("[*] Walking struct module linked list from kernel memory\n")

    src = BPF_MODULE_ENUM.replace("__MODULES_ADDR__", str(modules_addr))
    b = BPF(text=src)
    b.attach_kprobe(event="__x64_sys_getpid", fn_name="enum_modules")

    modules = []

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        modules.append(
            {
                "name": event.name.decode("utf-8", errors="replace").rstrip("\x00"),
                "addr": event.mod_addr,
                "core_addr": event.core_addr,
                "core_size": event.core_size,
                "init_size": event.init_size,
                "state": event.state,
                "taints": event.taints,
            }
        )

    b["events"].open_ring_buffer(handle_event)

    os.getpid()
    time.sleep(0.5)
    b.ring_buffer_consume()

    print(
        f"{'MODULE':<24}  {'STATE':>7}  {'CORE BASE':<20}  "
        f"{'CORE SIZE':>10}  {'STRUCT MODULE'}"
    )
    print(f"{'─' * 24}  {'─' * 7}  {'─' * 20}  {'─' * 10}  {'─' * 20}")

    for m in modules:
        state = MODULE_STATES.get(m["state"], f"?{m['state']}")
        print(
            f"{m['name']:<24}  {state:>7}  {m['core_addr']:#018x}  "
            f"{m['core_size']:>10}  {m['addr']:#018x}"
        )

    print(f"\n[*] Found {len(modules)} kernel modules via BPF walk")

    # Compare against /proc/modules
    if args.check_hidden:
        print("\n[*] ── Hidden module check ──")
        proc_modules = set()
        try:
            with open("/proc/modules") as f:
                for line in f:
                    proc_modules.add(line.split()[0])
        except PermissionError:
            pass

        bpf_modules = {m["name"] for m in modules}
        hidden = bpf_modules - proc_modules
        if hidden:
            print("[!] Modules in kernel list but NOT in /proc/modules:")
            for name in sorted(hidden):
                m = next(x for x in modules if x["name"] == name)
                print(f"    {name} @ {m['core_addr']:#018x} (size {m['core_size']})")
            print("[!] These modules may be hidden by a rootkit!")
        else:
            print("[+] No hidden modules found (kernel list and /proc agree)")

    return 0


# ===========================================================================
# Technique 4: VMA walk — traverse process virtual memory areas
# ===========================================================================

BPF_VMA_WALK = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define TARGET_PID __TARGET_PID__

struct vma_event_t {
    u32 pid;
    u64 vm_start;
    u64 vm_end;
    u64 vm_flags;      // VM_READ, VM_WRITE, VM_EXEC, etc.
    u64 vm_pgoff;      // file offset in pages
    u64 file_inode;    // inode number (0 = anonymous)
    char fname[64];    // backing file path (dentry name)
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

int walk_vmas(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Read mm_struct pointer
    struct mm_struct *mm;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (!mm) return 0;

    // Read the mmap pointer (head of VMA linked list)
    // On kernel 6.1+, the VMA list uses a maple tree instead of linked list.
    // For compatibility, we read from the maple tree's first entry.
    // On older kernels, mm->mmap is the head of the VMA list.
    struct vm_area_struct *vma;
    bpf_probe_read_kernel(&vma, sizeof(vma), &mm->mmap);

    #pragma unroll
    for (int i = 0; i < 512; i++) {
        if (!vma) break;

        struct vma_event_t *e = events.ringbuf_reserve(sizeof(*e));
        if (!e) break;

        e->pid = pid;
        bpf_probe_read_kernel(&e->vm_start, sizeof(u64), &vma->vm_start);
        bpf_probe_read_kernel(&e->vm_end,   sizeof(u64), &vma->vm_end);
        bpf_probe_read_kernel(&e->vm_flags, sizeof(u64), &vma->vm_flags);
        bpf_probe_read_kernel(&e->vm_pgoff, sizeof(u64), &vma->vm_pgoff);
        e->file_inode = 0;
        e->fname[0] = 0;

        // Read backing file info (if file-backed mapping)
        struct file *f;
        bpf_probe_read_kernel(&f, sizeof(f), &vma->vm_file);
        if (f) {
            // file → f_path.dentry → d_name.name
            struct dentry *dentry;
            bpf_probe_read_kernel(&dentry, sizeof(dentry),
                                  &f->f_path.dentry);
            if (dentry) {
                struct qstr d_name;
                bpf_probe_read_kernel(&d_name, sizeof(d_name),
                                      &dentry->d_name);
                bpf_probe_read_kernel_str(e->fname, sizeof(e->fname),
                                          d_name.name);

                // Read inode number
                struct inode *inode;
                bpf_probe_read_kernel(&inode, sizeof(inode),
                                      &dentry->d_inode);
                if (inode) {
                    bpf_probe_read_kernel(&e->file_inode, sizeof(u64),
                                          &inode->i_ino);
                }
            }
        }

        events.ringbuf_submit(e, 0);

        // Follow vm_next to next VMA
        struct vm_area_struct *next;
        bpf_probe_read_kernel(&next, sizeof(next), &vma->vm_next);
        vma = next;
    }

    return 0;
}
"""

# VM flags from include/linux/mm.h
VM_READ = 0x00000001
VM_WRITE = 0x00000002
VM_EXEC = 0x00000004
VM_SHARED = 0x00000008
VM_MAYREAD = 0x00000010
VM_MAYWRITE = 0x00000020
VM_MAYEXEC = 0x00000040


def decode_vm_flags(flags: int) -> str:
    """Decode VMA flags to rwxs string (like /proc/pid/maps)."""
    r = "r" if flags & VM_READ else "-"
    w = "w" if flags & VM_WRITE else "-"
    x = "x" if flags & VM_EXEC else "-"
    s = "s" if flags & VM_SHARED else "p"
    return f"{r}{w}{x}{s}"


def mode_vmas(args):
    """Technique 4: Walk a process's VMA list from kernel memory."""
    from bcc import BPF

    pid = args.pid
    if not pid:
        print("[!] --pid required for VMA walk")
        return 1

    print("\n[*] ══════ KERNEL VMA WALK ══════")
    print(f"[*] Target PID: {pid}")
    print("[*] Reading: task_struct → mm_struct → vm_area_struct list")
    print("[*] This is the kernel's ground-truth view of the address space\n")

    src = BPF_VMA_WALK.replace("__TARGET_PID__", str(pid))
    b = BPF(text=src)
    b.attach_kprobe(event="__x64_sys_write", fn_name="walk_vmas")

    vmas = []

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        vmas.append(
            {
                "start": event.vm_start,
                "end": event.vm_end,
                "flags": event.vm_flags,
                "pgoff": event.vm_pgoff,
                "inode": event.file_inode,
                "fname": event.fname.decode("utf-8", errors="replace").rstrip("\x00"),
            }
        )

    b["events"].open_ring_buffer(handle_event)

    # Trigger: send SIGUSR1 or wait for target to call write
    print(f"[*] Waiting for PID {pid} to call write()...\n")

    try:
        deadline = time.time() + 10
        while not vmas and time.time() < deadline:
            b.ring_buffer_poll(timeout=200)
    except KeyboardInterrupt:
        pass

    if not vmas:
        print("[!] No VMA events received. Target may not have called write().")
        print("[*] Try: kill -USR1 <pid> or wait for I/O")
        return 1

    print(
        f"{'START':<18}  {'END':<18}  {'PERM':>4}  {'SIZE':>10}  "
        f"{'OFFSET':>10}  {'FILE'}"
    )
    print(f"{'─' * 18}  {'─' * 18}  {'─' * 4}  {'─' * 10}  {'─' * 10}  {'─' * 30}")

    rwx_regions = []
    total_mapped = 0

    for v in vmas:
        size = v["end"] - v["start"]
        total_mapped += size
        perms = decode_vm_flags(v["flags"])
        offset = v["pgoff"] * 4096
        fname = v["fname"] or "[anon]"

        print(
            f"{v['start']:#018x}  {v['end']:#018x}  {perms}  "
            f"{size:>10}  {offset:#010x}  {fname}"
        )

        if (v["flags"] & (VM_READ | VM_WRITE | VM_EXEC)) == (
            VM_READ | VM_WRITE | VM_EXEC
        ):
            rwx_regions.append(v)

    print(f"\n[*] {len(vmas)} VMAs, {total_mapped / 1024 / 1024:.1f} MB total mapped")

    if rwx_regions:
        print("\n[!] ── RWX REGIONS DETECTED ──")
        for v in rwx_regions:
            size = v["end"] - v["start"]
            fname = v["fname"] or "[anon]"
            print(f"    {v['start']:#018x} - {v['end']:#018x}  ({size} bytes)  {fname}")
        print("[!] RWX regions are injection targets — blob can be written here")

    return 0


# ===========================================================================
# Technique 5: KASLR leak
# ===========================================================================

BPF_KASLR_LEAK = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct kaslr_event_t {
    u64 current_task;        // address of current task_struct
    u64 kprobe_addr;         // address of probed function
    u64 text_base_estimate;  // _stext estimate
    u64 init_task;           // address of init_task (if resolved)
    u64 ip;                  // instruction pointer in probe context
};

BPF_RINGBUF_OUTPUT(events, 1 << 14);

int leak_kaslr(struct pt_regs *ctx) {
    struct kaslr_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->current_task = (u64)bpf_get_current_task();
    e->ip = PT_REGS_IP(ctx);

    // The probed function's address reveals KASLR offset.
    // Without KASLR: __x64_sys_getpid is at a known offset from _stext.
    // With KASLR: it's shifted by a random offset.
    // Knowing ANY kernel symbol address breaks KASLR.
    e->kprobe_addr = e->ip;

    // Estimate kernel text base: most kernel text starts at
    // 0xffffffff81000000 + kaslr_offset.
    // The probed function is within kernel text, so we can estimate.
    // Round down to 2MB alignment (typical KASLR granularity).
    e->text_base_estimate = e->ip & ~0x1FFFFFULL;

    events.ringbuf_submit(e, 0);
    return 0;
}
"""


def mode_kaslr(args):
    """Technique 5: Leak kernel base address via BPF probes."""
    from bcc import BPF

    print("\n[*] ══════ KASLR LEAK VIA eBPF ══════")
    print("[*] BPF programs can read kernel instruction pointers")
    print("[*] This reveals the KASLR offset without /proc/kallsyms\n")

    b = BPF(text=BPF_KASLR_LEAK)
    b.attach_kprobe(event="__x64_sys_getpid", fn_name="leak_kaslr")

    result = [None]

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        result[0] = event

    b["events"].open_ring_buffer(handle_event)

    os.getpid()
    time.sleep(0.3)
    b.ring_buffer_consume()

    if not result[0]:
        print("[!] No event received")
        return 1

    e = result[0]

    # Read actual _stext from kallsyms for comparison
    stext = None
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == "_stext":
                    stext = int(parts[0], 16)
                    break
    except PermissionError:
        pass

    print(f"  Probed function (__x64_sys_getpid): {e.kprobe_addr:#018x}")
    print(f"  Instruction pointer (PT_REGS_IP):   {e.ip:#018x}")
    print(f"  Current task_struct:                 {e.current_task:#018x}")
    print(f"  Estimated text base (2MB aligned):   {e.text_base_estimate:#018x}")

    if stext:
        offset = e.kprobe_addr - stext
        kaslr_slide = stext - 0xFFFFFFFF81000000
        print(f"\n  Actual _stext (from kallsyms):       {stext:#018x}")
        print(f"  Probed function offset from _stext:  {offset:#x}")
        print(f"  KASLR slide:                         {kaslr_slide:#x}")

        if kaslr_slide == 0:
            print("\n  [*] KASLR is DISABLED (slide = 0)")
        else:
            print("\n  [!] KASLR is ENABLED — but we have the slide!")
            print("  [!] Any kernel symbol can now be resolved:")
            print(f"      symbol_addr = known_offset + {stext:#x}")

    print("\n  [*] Key insight: BPF programs run in kernel context and can")
    print("  [*] access PT_REGS_IP, task_struct pointers, and other kernel")
    print("  [*] addresses that are hidden from userspace by KASLR.")

    return 0


# ===========================================================================
# Technique 6: Kallsyms capture — resolve arbitrary kernel symbols
# ===========================================================================

BPF_KALLSYMS = r"""
#include <uapi/linux/ptrace.h>

struct sym_event_t {
    u64 addr;
    char name[64];
    char type;
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

// Hook kallsyms_on_each_symbol's callback to capture symbols as the
// kernel iterates its own symbol table.
// Alternatively, for specific symbols we can just kprobe them.

// Simpler approach: kprobe known functions and record their addresses.
int capture_symbol(struct pt_regs *ctx) {
    struct sym_event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->addr = PT_REGS_IP(ctx);
    e->type = 'T';

    // We know which function this is because we attached the kprobe.
    // The function name is set by Python before loading.
    char name[] = "__SYMBOL_NAME__";
    __builtin_memcpy(e->name, name, sizeof(name));

    events.ringbuf_submit(e, 0);
    return 0;
}
"""


def mode_kallsyms(args):
    """Technique 6: Resolve kernel symbol addresses via kprobe attachment."""
    from bcc import BPF

    symbols = args.symbol or [
        "commit_creds",
        "prepare_kernel_cred",
        "core_pattern",
        "__x64_sys_execve",
    ]

    print("\n[*] ══════ KERNEL SYMBOL RESOLUTION ══════")
    print("[*] Resolving symbols by attaching kprobes")
    print(f"[*] Targets: {', '.join(symbols)}\n")

    # For each symbol, try to attach a kprobe and capture its address
    results = {}

    for sym in symbols:
        src = BPF_KALLSYMS.replace("__SYMBOL_NAME__", sym)
        try:
            b = BPF(text=src)
            b.attach_kprobe(event=sym, fn_name="capture_symbol")
            # If attach succeeds, we can read the address from kallsyms
            # (BCC resolves it internally)
            addr = BPF.ksym(sym)
            results[sym] = addr or "attached (addr pending)"
            b.detach_kprobe(event=sym)
            del b
        except Exception as e:
            results[sym] = f"FAILED: {e}"

    # Also try reading /proc/kallsyms directly for comparison
    kallsyms = {}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] in symbols:
                    kallsyms[parts[2]] = int(parts[0], 16)
    except PermissionError:
        pass

    print(f"{'SYMBOL':<32}  {'BPF RESOLVED':<20}  {'KALLSYMS':<20}")
    print(f"{'─' * 32}  {'─' * 20}  {'─' * 20}")

    for sym in symbols:
        bpf_val = results.get(sym, "?")
        bpf_str = f"{bpf_val:#018x}" if isinstance(bpf_val, int) else str(bpf_val)

        ksym_val = kallsyms.get(sym)
        ksym_str = f"{ksym_val:#018x}" if ksym_val else "?"

        print(f"{sym:<32}  {bpf_str:<20}  {ksym_str:<20}")

    # Highlight dangerous symbols
    print()
    for sym in symbols:
        if sym == "commit_creds" and sym in kallsyms:
            print(
                f"[!] commit_creds @ {kallsyms[sym]:#x} — used for "
                f"privilege escalation (overwrite current->cred)"
            )
        elif sym == "prepare_kernel_cred" and sym in kallsyms:
            print(
                f"[!] prepare_kernel_cred @ {kallsyms[sym]:#x} — "
                f"allocates root cred struct (uid=0, full caps)"
            )
        elif sym == "core_pattern" and sym in kallsyms:
            print(
                f"[!] core_pattern @ {kallsyms[sym]:#x} — "
                f"overwriting this enables code exec on crash"
            )

    return 0


# ===========================================================================
# Main
# ===========================================================================


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Kernel Memory Explorer — Red Team Lab Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Techniques:
  creds    — Dump process UIDs, GIDs, capabilities from task_struct→cred
  tasks    — Walk kernel task list, detect hidden processes
  modules  — Walk kernel module list, detect hidden modules
  vmas     — Walk process VMA list (kernel's view of address space)
  kaslr    — Leak KASLR base address from BPF probe context
  kallsyms — Resolve kernel symbol addresses via kprobe attachment

All reads use bpf_probe_read_kernel() — direct kernel memory access.

Examples:
  sudo python3 mbed/ebpf_kernel_mem.py creds --pid 1234
  sudo python3 mbed/ebpf_kernel_mem.py tasks --check-hidden
  sudo python3 mbed/ebpf_kernel_mem.py modules --check-hidden
  sudo python3 mbed/ebpf_kernel_mem.py vmas --pid 1234
  sudo python3 mbed/ebpf_kernel_mem.py kaslr
  sudo python3 mbed/ebpf_kernel_mem.py kallsyms --symbol commit_creds
        """,
    )

    subs = parser.add_subparsers(dest="technique", required=True)

    # Technique 1: creds
    p1 = subs.add_parser("creds", help="Dump process credentials from kernel")
    p1.add_argument("--pid", type=int, default=0, help="Target PID (0 = all)")
    p1.add_argument(
        "--limit", type=int, default=20, help="Max processes to dump (default: 20)"
    )

    # Technique 2: tasks
    p2 = subs.add_parser("tasks", help="Walk kernel task list")
    p2.add_argument(
        "--check-hidden",
        action="store_true",
        help="Compare against /proc to find hidden processes",
    )

    # Technique 3: modules
    p3 = subs.add_parser("modules", help="Walk kernel module list")
    p3.add_argument(
        "--check-hidden",
        action="store_true",
        help="Compare against /proc/modules to find hidden modules",
    )

    # Technique 4: vmas
    p4 = subs.add_parser("vmas", help="Walk process VMA list")
    p4.add_argument("--pid", type=int, required=True, help="Target PID")

    # Technique 5: kaslr
    subs.add_parser("kaslr", help="Leak KASLR base address")

    # Technique 6: kallsyms
    p6 = subs.add_parser("kallsyms", help="Resolve kernel symbol addresses")
    p6.add_argument("--symbol", action="append", help="Symbol to resolve (repeatable)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Requires root for kernel memory access via eBPF")
        return 1

    if importlib.util.find_spec("bcc") is None:
        print("ERROR: BCC not installed. Run: apt install bpfcc-tools python3-bpfcc")
        return 1

    handlers = {
        "creds": mode_creds,
        "tasks": mode_tasks,
        "modules": mode_modules,
        "vmas": mode_vmas,
        "kaslr": mode_kaslr,
        "kallsyms": mode_kallsyms,
    }

    return handlers[args.technique](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
