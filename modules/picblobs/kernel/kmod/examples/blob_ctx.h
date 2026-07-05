/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * blob_ctx.h — Context struct for PIC blobs loaded via kshell !kload.
 *
 * Include this in your blob source. When loaded via !kload, the blob
 * receives a pointer to this struct as its first argument:
 *
 *   void _start(struct blob_ctx *ctx)
 *   {
 *       ctx->printf(ctx, "hello from ring 0!\n");
 *
 *       void *printk = ctx->resolve("printk");
 *       // ... use printk directly ...
 *
 *       ctx->send(ctx, data, len);  // send raw bytes to operator
 *   }
 *
 * The blob runs in its own kthread. The kshell stays alive.
 * Output sent via ctx->send/printf appears at the operator's terminal
 * in real time through the NaCl-encrypted channel.
 */
#ifndef _BLOB_CTX_H
#define _BLOB_CTX_H

struct blob_ctx {
    /* Send raw bytes to the operator. Returns bytes sent or <0 on error. */
    int (*send)(struct blob_ctx *ctx, const void *data, int len);

    /* Resolve a kernel symbol by name. Returns address or NULL.
     * Use this to call kernel functions: printk, kmalloc, kthread_run, etc. */
    void *(*resolve)(const char *name);

    /* Convenience: snprintf + send. Like printf but output goes to operator. */
    int (*printf)(struct blob_ctx *ctx, const char *fmt, ...);

    /* Private — do not touch */
    void *_kctx;
};

#endif /* _BLOB_CTX_H */
