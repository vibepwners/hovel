#include "iocpserver/server.h"

#include "iocpserver/iocp.h"
#include "iocpserver/net.h"
#include "base/win.h"
#include "sqlog/sqlog.h"

/* Pure Win32: HeapAlloc/HeapFree for memory, CreateThread for workers,
 * ZeroMemory/CopyMemory for fills. No C runtime. */

/* ------------------------------------------------------------------------- */
/* Tunables and protocol constants                                           */
/* ------------------------------------------------------------------------- */

enum {
    SQ_CONN_BUF_LEN    = 16384, /* per-direction connection buffer           */
    SQ_DEFAULT_ACCEPTS = 16,    /* outstanding AcceptEx ops when unspecified  */
    SQ_MAX_WORKERS     = 256    /* clamp auto-sized pools                     */
};

/* AcceptEx needs, for each of the local and remote address, the address size
 * plus 16 bytes of slack the API mandates. We size for sockaddr_storage so the
 * same buffer serves IPv4 and IPv6. */
#define SQ_ADDR_SLOT (sizeof(struct sockaddr_storage) + 16u)

/* Completion keys. Real I/O is recovered from the OVERLAPPED, so the key only
 * has to distinguish a hand-posted wake-up from everything else. */
#define SQ_KEY_IO   ((ULONG_PTR)1)
#define SQ_KEY_WAKE ((ULONG_PTR)2)

typedef enum sq_op_kind {
    SQ_OP_ACCEPT = 0,
    SQ_OP_RECV,
    SQ_OP_SEND
} sq_op_kind;

/* ------------------------------------------------------------------------- */
/* Connection                                                                */
/* ------------------------------------------------------------------------- */

/* One connection (or one in-flight accept). OVERLAPPED is deliberately the
 * first member so CONTAINING_RECORD recovers the connection from a completion.
 *
 * Invariant: a connection has exactly ONE operation outstanding at any time
 * (accept, then alternating recv/send). Therefore only one worker ever holds a
 * given connection, and no field below needs its own lock. The only shared
 * structure is the server's intrusive `live` list, guarded by list_lock. */
typedef struct sq_conn {
    OVERLAPPED overlapped; /* MUST be first */
    sq_op_kind kind;
    SOCKET     sock;
    struct sq_server *server;

    struct sq_conn *prev; /* live-list links (valid iff linked) */
    struct sq_conn *next;
    int             linked;

    DWORD send_len; /* bytes of sbuf to send     */
    DWORD send_off; /* bytes of sbuf sent so far */

    unsigned char rbuf[SQ_CONN_BUF_LEN];
    unsigned char sbuf[SQ_CONN_BUF_LEN];
    unsigned char accept_buf[2u * (sizeof(struct sockaddr_storage) + 16u)];
} sq_conn;

/* ------------------------------------------------------------------------- */
/* Server                                                                    */
/* ------------------------------------------------------------------------- */

struct sq_server {
    SOCKET     listener;
    int        family;
    HANDLE     iocp;
    sq_net_ext ext;
    sq_handler handler;

    HANDLE  *workers;      /* worker_count thread handles */
    unsigned worker_count;
    unsigned accept_count;

    HANDLE           stop_event; /* manual-reset; set by stop() */
    CRITICAL_SECTION list_lock;  /* guards `live` and the linked flags */
    sq_conn         *live;       /* head of established-connection list */

    volatile LONG stopping;    /* 0 running, 1 shutting down */
    volatile LONG outstanding; /* allocated conns with a pending op */

    int net_started; /* whether sq_net_startup succeeded (for teardown) */
};

/* Forward declarations for the mutually-recursive completion handlers. */
static sq_status post_accept(sq_server *s);
static sq_status post_recv(sq_conn *c);
static sq_status post_send(sq_conn *c);
static void wake_all_workers(sq_server *s);

/* ------------------------------------------------------------------------- */
/* Connection lifecycle                                                      */
/* ------------------------------------------------------------------------- */

static void conn_link(sq_server *s, sq_conn *c)
{
    EnterCriticalSection(&s->list_lock);
    c->prev = NULL;
    c->next = s->live;
    if (s->live != NULL) {
        s->live->prev = c;
    }
    s->live = c;
    c->linked = 1;
    LeaveCriticalSection(&s->list_lock);
}

static void conn_unlink(sq_conn *c)
{
    sq_server *s = c->server;

    EnterCriticalSection(&s->list_lock);
    if (c->linked != 0) {
        if (c->prev != NULL) {
            c->prev->next = c->next;
        } else {
            s->live = c->next;
        }
        if (c->next != NULL) {
            c->next->prev = c->prev;
        }
        c->prev = NULL;
        c->next = NULL;
        c->linked = 0;
    }
    LeaveCriticalSection(&s->list_lock);
}

static sq_conn *conn_alloc(sq_server *s)
{
    sq_conn *c = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *c);

    if (c == NULL) {
        SQLOG_ERROR(SQLOG_SUB_SERVER, L"connection allocation failed (%u bytes)",
                     (unsigned)sizeof *c);
        return NULL;
    }
    c->kind = SQ_OP_ACCEPT;
    c->sock = INVALID_SOCKET;
    c->server = s;
    (void)InterlockedIncrement(&s->outstanding);
    return c;
}

static void conn_free(sq_conn *c)
{
    sq_server *s = NULL;
    LONG remaining = 0;

    if (c == NULL) {
        return;
    }
    s = c->server;
    conn_unlink(c);
    sq_net_close(c->sock);
    c->sock = INVALID_SOCKET;
    remaining = InterlockedDecrement(&s->outstanding);
    (void)HeapFree(GetProcessHeap(), 0, c);

    /* When the last operation drains during shutdown, release the workers that
     * are blocked in GetQueuedCompletionStatus. Doing it here (rather than
     * eagerly in stop()) guarantees every connection is freed before any worker
     * exits, so nothing leaks. */
    if (remaining == 0 && s->stopping != 0) {
        wake_all_workers(s);
    }
}

/* ------------------------------------------------------------------------- */
/* Operation posting                                                         */
/* ------------------------------------------------------------------------- */

static sq_status post_accept(sq_server *s)
{
    sq_conn *c = NULL;
    sq_status st = SQ_OK;
    DWORD received = 0;
    BOOL ok = FALSE;

    if (s->stopping != 0) {
        return SQ_OK; /* do not refill the pool while shutting down */
    }
    c = conn_alloc(s);
    if (c == NULL) {
        return SQ_ERR_NOMEM;
    }
    st = sq_net_tcp_socket(s->family, &c->sock);
    if (st != SQ_OK) {
        conn_free(c);
        return st;
    }

    c->kind = SQ_OP_ACCEPT;
    ZeroMemory(&c->overlapped, sizeof c->overlapped);
    ok = s->ext.accept_ex(s->listener, c->sock, c->accept_buf,
                          0, /* receive no data on accept */
                          (DWORD)SQ_ADDR_SLOT, (DWORD)SQ_ADDR_SLOT,
                          &received, &c->overlapped);
    if (ok == FALSE) {
        int const err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            SQLOG_WINERR(SQLOG_SUB_SERVER, ERROR, (unsigned long)err,
                         L"AcceptEx failed");
            conn_free(c);
            return SQ_ERR_SYSTEM;
        }
    }
    return SQ_OK;
}

static sq_status post_recv(sq_conn *c)
{
    WSABUF wb = {0};
    DWORD flags = 0;
    DWORD received = 0;
    int rc = 0;

    wb.buf = (char *)c->rbuf;
    wb.len = (ULONG)SQ_CONN_BUF_LEN;
    c->kind = SQ_OP_RECV;
    ZeroMemory(&c->overlapped, sizeof c->overlapped);

    rc = WSARecv(c->sock, &wb, 1, &received, &flags, &c->overlapped, NULL);
    if (rc != 0) {
        int const err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            SQLOG_WINERR(SQLOG_SUB_SERVER, ERROR, (unsigned long)err,
                         L"WSARecv failed");
            return SQ_ERR_SYSTEM;
        }
    }
    return SQ_OK; /* completion will be delivered to the port */
}

static sq_status post_send(sq_conn *c)
{
    WSABUF wb = {0};
    DWORD sent = 0;
    int rc = 0;

    wb.buf = (char *)(c->sbuf + c->send_off);
    wb.len = (ULONG)(c->send_len - c->send_off);
    c->kind = SQ_OP_SEND;
    ZeroMemory(&c->overlapped, sizeof c->overlapped);

    rc = WSASend(c->sock, &wb, 1, &sent, 0, &c->overlapped, NULL);
    if (rc != 0) {
        int const err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            SQLOG_WINERR(SQLOG_SUB_SERVER, ERROR, (unsigned long)err,
                         L"WSASend failed");
            return SQ_ERR_SYSTEM;
        }
    }
    return SQ_OK;
}

/* ------------------------------------------------------------------------- */
/* Completion handlers (each runs on a worker thread)                        */
/* ------------------------------------------------------------------------- */

static void log_accepted_peer(sq_server *s, sq_conn *c)
{
    struct sockaddr *local = NULL;
    struct sockaddr *remote = NULL;
    int local_len = 0;
    int remote_len = 0;
    wchar_t peer[128] = {0};

    s->ext.get_accept_ex_sockaddrs(c->accept_buf, 0,
                                   (DWORD)SQ_ADDR_SLOT, (DWORD)SQ_ADDR_SLOT,
                                   &local, &local_len, &remote, &remote_len);
    sq_net_peer_str(remote, remote_len, peer, sizeof peer / sizeof peer[0]);
    SQLOG_DEBUG(SQLOG_SUB_SERVER, L"accepted connection from %s", peer);
}

static void on_accept_complete(sq_server *s, sq_conn *c, int failed)
{
    sq_status st = SQ_OK;

    if (failed != 0 || s->stopping != 0) {
        /* Aborted (listener closed) or shutting down: drop it. If we merely lost
         * an accept while still running, refill so the pool stays full. */
        int const should_refill = (s->stopping == 0);
        conn_free(c);
        if (should_refill) {
            (void)post_accept(s);
        }
        return;
    }

    /* The accepted socket must inherit the listener's context before it behaves
     * like a normal connected socket (getpeername, shutdown, etc.). */
    if (setsockopt(c->sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                   (const char *)&s->listener, (int)sizeof s->listener) != 0) {
        SQLOG_WINERR(SQLOG_SUB_SERVER, ERROR, (unsigned long)WSAGetLastError(),
                   L"SO_UPDATE_ACCEPT_CONTEXT failed");
        conn_free(c);
        (void)post_accept(s);
        return;
    }
    log_accepted_peer(s, c);

    if (sq_iocp_associate(s->iocp, (HANDLE)c->sock, SQ_KEY_IO) != SQ_OK) {
        conn_free(c);
        (void)post_accept(s);
        return;
    }
    conn_link(s, c);

    /* Keep the accept pool full, then start this connection's echo loop. */
    (void)post_accept(s);
    st = post_recv(c);
    if (st != SQ_OK) {
        conn_free(c);
    }
}

static void on_recv_complete(sq_server *s, sq_conn *c, DWORD bytes, int failed)
{
    size_t produced = 0;

    /* Failure, a graceful peer close (0 bytes), or shutdown all end the conn. */
    if (failed != 0 || bytes == 0 || s->stopping != 0) {
        conn_free(c);
        return;
    }

    produced = s->handler.on_recv(s->handler.user, c->rbuf, (size_t)bytes,
                                  c->sbuf, (size_t)SQ_CONN_BUF_LEN);
    if (produced == SQ_HANDLER_CLOSE) {
        conn_free(c);
        return;
    }
    if (produced == 0) {
        if (post_recv(c) != SQ_OK) { /* nothing to send; keep reading */
            conn_free(c);
        }
        return;
    }

    /* produced is bounded by out_cap == SQ_CONN_BUF_LEN, so it fits a DWORD. */
    c->send_len = (DWORD)produced;
    c->send_off = 0;
    if (post_send(c) != SQ_OK) {
        conn_free(c);
    }
}

static void on_send_complete(sq_server *s, sq_conn *c, DWORD bytes, int failed)
{
    if (failed != 0 || bytes == 0 || s->stopping != 0) {
        conn_free(c);
        return;
    }
    c->send_off += bytes;
    if (c->send_off < c->send_len) {
        if (post_send(c) != SQ_OK) { /* flush the remainder of a partial send */
            conn_free(c);
        }
        return;
    }
    /* Full response delivered; resume reading. */
    if (post_recv(c) != SQ_OK) {
        conn_free(c);
    }
}

/* ------------------------------------------------------------------------- */
/* Worker pool                                                               */
/* ------------------------------------------------------------------------- */

static void wake_all_workers(sq_server *s)
{
    unsigned i = 0;

    for (i = 0; i < s->worker_count; i++) {
        (void)sq_iocp_post(s->iocp, 0, SQ_KEY_WAKE, NULL);
    }
}

static BOOL should_exit_worker(sq_server *s, const sq_iocp_event *ev,
                               sq_status st)
{
    if (st != SQ_OK || ev->outcome == SQ_IOCP_CLOSED) {
        return TRUE;
    }
    if (ev->outcome == SQ_IOCP_TIMEOUT) {
        return FALSE;
    }
    return ev->overlapped == NULL && s->stopping != 0 && s->outstanding == 0;
}

static void dispatch_iocp_event(sq_server *s, const sq_iocp_event *ev)
{
    sq_conn *c = CONTAINING_RECORD(ev->overlapped, sq_conn, overlapped);

    switch (c->kind) {
    case SQ_OP_ACCEPT:
        on_accept_complete(s, c, ev->op_failed);
        break;
    case SQ_OP_RECV:
        on_recv_complete(s, c, ev->bytes, ev->op_failed);
        break;
    case SQ_OP_SEND:
        on_send_complete(s, c, ev->bytes, ev->op_failed);
        break;
    }
}

static DWORD WINAPI worker_main(LPVOID param)
{
    sq_server *s = (sq_server *)param;

    for (;;) {
        sq_iocp_event ev; /* fully zeroed by sq_iocp_wait */
        sq_status st = sq_iocp_wait(s->iocp, INFINITE, &ev);

        if (should_exit_worker(s, &ev, st)) {
            break;
        }
        if (ev.overlapped == NULL) {
            continue;
        }
        dispatch_iocp_event(s, &ev);
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Public lifecycle                                                          */
/* ------------------------------------------------------------------------- */

static unsigned default_worker_count(void)
{
    SYSTEM_INFO info = {0};
    unsigned n = 0;

    GetSystemInfo(&info);
    n = (unsigned)info.dwNumberOfProcessors;
    if (n == 0) {
        n = 1;
    }
    n *= 2; /* a common starting point for IOCP pools */
    if (n > SQ_MAX_WORKERS) {
        n = SQ_MAX_WORKERS;
    }
    return n;
}

static sq_server *server_alloc(const sq_server_config *cfg)
{
    sq_server *s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *s);

    if (s == NULL) {
        return NULL;
    }
    s->listener = INVALID_SOCKET;
    s->iocp = NULL;
    s->handler = cfg->handler;
    InitializeCriticalSection(&s->list_lock);
    return s;
}

static sq_status create_stop_event(sq_server *s)
{
    s->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (s->stop_event != NULL) {
        return SQ_OK;
    }
    SQLOG_WINERR(SQLOG_SUB_SERVER, ERROR, (unsigned long)GetLastError(),
                 L"CreateEvent failed");
    return SQ_ERR_SYSTEM;
}

static sq_status configure_counts(sq_server *s, const sq_server_config *cfg)
{
    s->worker_count = (cfg->worker_count > 0) ? cfg->worker_count
                                              : default_worker_count();
    if (s->worker_count > SQ_MAX_WORKERS) {
        s->worker_count = SQ_MAX_WORKERS;
    }
    s->accept_count = (cfg->accept_count > 0) ? cfg->accept_count
                                              : SQ_DEFAULT_ACCEPTS;
    s->workers = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                           (SIZE_T)s->worker_count * sizeof *s->workers);
    return (s->workers != NULL) ? SQ_OK : SQ_ERR_NOMEM;
}

static sq_status open_listener_and_iocp(sq_server *s,
                                        const sq_server_config *cfg)
{
    sq_status st = sq_net_listen(cfg->host, cfg->port, cfg->backlog,
                                 &s->listener, &s->family);

    if (st != SQ_OK) {
        return st;
    }
    st = sq_iocp_create(0, &s->iocp);
    if (st != SQ_OK) {
        return st;
    }
    st = sq_iocp_associate(s->iocp, (HANDLE)s->listener, SQ_KEY_IO);
    if (st != SQ_OK) {
        return st;
    }
    return sq_net_load_ext(s->listener, &s->ext);
}

static sq_status start_workers(sq_server *s)
{
    unsigned i = 0;

    for (i = 0; i < s->worker_count; i++) {
        HANDLE h = CreateThread(NULL, 0, worker_main, s, 0, NULL);
        if (h == NULL) {
            SQLOG_WINERR(SQLOG_SUB_SERVER, ERROR, (unsigned long)GetLastError(),
                         L"CreateThread failed");
            return SQ_ERR_SYSTEM;
        }
        s->workers[i] = h;
    }
    return SQ_OK;
}

static sq_status post_initial_accepts(sq_server *s)
{
    unsigned i = 0;

    for (i = 0; i < s->accept_count; i++) {
        sq_status st = post_accept(s);
        if (st != SQ_OK) {
            return st;
        }
    }
    return SQ_OK;
}

static BOOL valid_server_config(const sq_server_config *cfg)
{
    return cfg != NULL && cfg->port != NULL && cfg->handler.on_recv != NULL;
}

static sq_status setup_server(sq_server *s, const sq_server_config *cfg)
{
    sq_status st = create_stop_event(s);

    if (st == SQ_OK) {
        st = sq_net_startup();
    }
    if (st == SQ_OK) {
        s->net_started = 1;
        st = configure_counts(s, cfg);
    }
    if (st == SQ_OK) {
        st = open_listener_and_iocp(s, cfg);
    }
    if (st == SQ_OK) {
        st = start_workers(s);
    }
    if (st == SQ_OK) {
        st = post_initial_accepts(s);
    }
    return st;
}

sq_status sq_server_create(const sq_server_config *cfg, sq_server **out)
{
    sq_server *s = NULL;
    sq_status st = SQ_OK;

    if (out == NULL) {
        return SQ_ERR_PARAM;
    }
    *out = NULL;
    if (!valid_server_config(cfg)) {
        SQLOG_ERROR(SQLOG_SUB_SERVER,
                    L"sq_server_create: invalid configuration");
        return SQ_ERR_PARAM;
    }

    s = server_alloc(cfg);
    if (s == NULL) {
        return SQ_ERR_NOMEM;
    }

    st = setup_server(s, cfg);
    if (st != SQ_OK) {
        goto fail;
    }

    SQLOG_INFO(SQLOG_SUB_SERVER, L"listening on %s:%s (%u workers, %u accepts)",
                (cfg->host != NULL) ? cfg->host : L"*", cfg->port,
                s->worker_count, s->accept_count);
    *out = s;
    return SQ_OK;

fail:
    /* sq_server_destroy is written to tolerate any partially-built server: it
     * stops (if running), joins whatever threads exist, and frees the rest. */
    sq_server_destroy(s);
    return st;
}

void sq_server_stop(sq_server *s)
{
    sq_conn *c = NULL;

    if (s == NULL) {
        return;
    }
    if (InterlockedExchange(&s->stopping, 1) == 1) {
        return; /* already stopping */
    }
    SQLOG_INFO(SQLOG_SUB_SERVER, L"shutdown requested");

    /* Stop accepting: closing the listener aborts every outstanding AcceptEx. */
    sq_net_close(s->listener);
    s->listener = INVALID_SOCKET;

    /* Cancel in-flight I/O on established connections by closing their sockets.
     * Each connection has exactly one pending op, which completes as aborted and
     * is freed by the worker that dequeues it. We hold list_lock throughout, so
     * no conn_free can unlink (and thus free) a node we are walking. */
    EnterCriticalSection(&s->list_lock);
    for (c = s->live; c != NULL; c = c->next) {
        if (c->sock != INVALID_SOCKET) {
            (void)closesocket(c->sock);
            c->sock = INVALID_SOCKET;
        }
    }
    LeaveCriticalSection(&s->list_lock);

    /* Cover the case where nothing was outstanding to begin with. */
    wake_all_workers(s);

    if (s->stop_event != NULL) {
        (void)SetEvent(s->stop_event);
    }
}

sq_status sq_server_run(sq_server *s)
{
    unsigned i = 0;

    if (s == NULL) {
        return SQ_ERR_PARAM;
    }
    if (s->stop_event != NULL) {
        (void)WaitForSingleObject(s->stop_event, INFINITE);
    }
    for (i = 0; i < s->worker_count; i++) {
        if (s->workers != NULL && s->workers[i] != NULL) {
            (void)WaitForSingleObject(s->workers[i], INFINITE);
        }
    }
    SQLOG_INFO(SQLOG_SUB_SERVER, L"all workers stopped");
    return SQ_OK;
}

void sq_server_destroy(sq_server *s)
{
    unsigned i = 0;

    if (s == NULL) {
        return;
    }
    /* Make sure we are stopped and all workers have exited before any handle is
     * closed; closing the port out from under a blocked worker is a bug. */
    if (s->stopping == 0) {
        sq_server_stop(s);
    }
    for (i = 0; i < s->worker_count; i++) {
        if (s->workers != NULL && s->workers[i] != NULL) {
            (void)WaitForSingleObject(s->workers[i], INFINITE);
            (void)CloseHandle(s->workers[i]);
            s->workers[i] = NULL;
        }
    }

    sq_iocp_close(s->iocp);
    s->iocp = NULL;
    sq_net_close(s->listener);
    s->listener = INVALID_SOCKET;

    (void)HeapFree(GetProcessHeap(), 0, s->workers);
    s->workers = NULL;

    if (s->stop_event != NULL) {
        (void)CloseHandle(s->stop_event);
        s->stop_event = NULL;
    }
    DeleteCriticalSection(&s->list_lock);

    if (s->net_started != 0) {
        sq_net_cleanup();
    }
    (void)HeapFree(GetProcessHeap(), 0, s);
}
