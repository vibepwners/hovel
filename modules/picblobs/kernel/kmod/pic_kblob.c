/*
 * pic_kblob.c — Example PIC blob designed for KERNEL context (ring 0)
 *
 * Unlike the userspace blobs (which make syscalls), this blob calls
 * kernel functions directly. It demonstrates what "ring 0 PIC code"
 * looks like — no syscalls, just direct kernel API calls.
 *
 * IMPORTANT: Userspace PIC blobs (hello.c, ul_exec.c) will NOT work
 * in kernel context because they use the `syscall` instruction, which
 * traps into the kernel from userspace. If you're already IN the kernel,
 * you call kernel functions directly — no trap needed.
 *
 * This blob is compiled as a flat binary (like userspace blobs) but
 * uses kernel function pointers passed via the config struct instead
 * of syscall numbers.
 *
 * Build:
 *   gcc -ffreestanding -nostdlib -fPIC -Os -c pic_kblob.c -o pic_kblob.o
 *   ld -T kblob.ld -o pic_kblob.bin pic_kblob.o
 *
 * Or more practically, compile as part of the kernel module and
 * extract the .text section.
 */

/*
 * Kernel blob config struct — passed at config_offset.
 *
 * Since the blob can't call kernel functions by name (it has no
 * symbol resolution), the loader passes function pointers in the
 * config struct. The blob calls these pointers directly.
 *
 * This is the kernel equivalent of Windows PEB/IAT resolution —
 * the loader resolves symbols and passes addresses to the blob.
 */
struct kblob_config {
    /* Function pointers resolved by the loader (pic_kmod.c) */
    void (*printk)(const char *fmt, ...);
    void *(*kmalloc)(unsigned long size, unsigned int flags);
    void (*kfree)(void *ptr);

    /* Kernel addresses the blob might need */
    void *current_task;     /* pointer to current task_struct */
    void *init_task;        /* pointer to init_task (for task list walk) */

    /* Blob-specific config */
    unsigned long flags;
    char message[64];
};

/*
 * _start — Blob entry point (offset 0)
 *
 * Config struct is at a known offset from the start of the blob.
 * The loader writes function pointers into it before execution.
 */
void __attribute__((section(".text.pic_entry")))
__attribute__((used))
_start(void)
{
    /*
     * In a real kernel blob, you'd read the config offset from a
     * known location and use the function pointers. For this demo,
     * the concept is:
     *
     *   struct kblob_config *cfg = (void *)_start + CONFIG_OFFSET;
     *   cfg->printk("pic_kblob: running in ring 0!\n");
     *
     * The key insight: this code runs with FULL kernel privileges.
     * It can access any memory, call any function pointer, modify
     * any data structure. There is no verifier, no sandbox.
     */

    /* NOP sled for demonstration — in a real blob this would be
     * the actual payload code using config function pointers */
    __asm__ volatile (
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "ret\n"  /* return to caller (pic_kmod.c exec_pic_blob) */
    );
}
