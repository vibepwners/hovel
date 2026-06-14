/* server.h -- an IOCP + thread-pool TCP server.
 *
 * Design in one paragraph: one listening socket feeds a fixed pool of
 * outstanding AcceptEx operations. A completion port multiplexes every accept,
 * recv and send across a pool of worker threads. Each connection is a strict
 * half-duplex state machine -- accept -> recv -> (handler) -> send -> recv ...
 * -- so it has *exactly one* operation in flight at any instant. That single
 * invariant is what makes the whole thing thread-safe without per-connection
 * locks: a connection is only ever touched by the one worker dequeuing its one
 * completion. See server.c for the full lifecycle and shutdown protocol.
 *
 * Lifecycle: create() -> run() (blocks) -> destroy(). stop() may be called from
 * any thread (e.g. a console control handler) to make run() return.
 */
#ifndef SQ_SERVER_H
#define SQ_SERVER_H

#include "iocpserver/handler.h"
#include "iocpserver/result.h"

typedef struct sq_server sq_server; /* opaque */

typedef struct sq_server_config
{
        const wchar_t *host;   /* bind address; NULL = wildcard (all interfaces) */
        const wchar_t *port;   /* service/port string, required (e.g. L"9000")   */
        int backlog;           /* listen() backlog; <= 0 => SOMAXCONN            */
        unsigned worker_count; /* worker threads; 0 => 2 x logical processors    */
        unsigned accept_count; /* outstanding AcceptEx ops; 0 => a sane default  */
        sq_handler handler;    /* protocol callback; on_recv must be non-NULL    */
} sq_server_config;

/* Create and start serving. On success *out is a running server (workers
 * spawned, accepts posted) and SQ_OK is returned. On failure *out is NULL and
 * every partially acquired resource has been released. */
sq_status sq_server_create(const sq_server_config *cfg, sq_server **out);

/* Block the calling thread until stop() is requested and all workers have
 * drained and exited. Returns SQ_OK on an orderly shutdown. */
sq_status sq_server_run(sq_server *server);

/* Request shutdown: stop accepting, cancel in-flight I/O, and release the
 * worker threads. Idempotent and safe to call from another thread. */
void sq_server_stop(sq_server *server);

/* Release all resources. The server must have been run() to completion (or
 * never run). Tolerates NULL. */
void sq_server_destroy(sq_server *server);

#endif /* SQ_SERVER_H */
