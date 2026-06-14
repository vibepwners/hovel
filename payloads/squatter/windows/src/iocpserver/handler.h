/* handler.h -- the seam between the (generic) IOCP transport and a protocol.
 *
 * The server core knows nothing about what bytes mean. For each chunk of
 * received data it calls on_recv, which transforms input into the bytes to send
 * back. This is the whole extensibility surface: echo, a line protocol, an HTTP
 * stub, etc. are all just different on_recv implementations, with no change to
 * the accept/recv/send machinery.
 *
 * Contract for on_recv:
 *   - `in`/`in_len` is the freshly received data (in_len >= 1).
 *   - Write up to `out_cap` response bytes to `out`.
 *   - Return the number of response bytes written (0..out_cap), OR the sentinel
 *     SQ_HANDLER_CLOSE to ask the server to close the connection.
 *   - Must not retain `in` or `out` past the call; both are connection-owned.
 *   - Must be reentrant: it runs on many worker threads at once. Any shared
 *     state reached through `user` is the handler's own responsibility to guard.
 */
#ifndef SQ_HANDLER_H
#define SQ_HANDLER_H

#include <stddef.h>

/* Distinct from any valid byte count (which is bounded by out_cap << SIZE_MAX). */
#define SQ_HANDLER_CLOSE ((size_t)-1)

typedef size_t (*sq_handler_fn)(void *user, const unsigned char *in, size_t in_len, unsigned char *out, size_t out_cap);

typedef struct sq_handler
{
        sq_handler_fn on_recv;
        void *user; /* opaque context passed back to on_recv; may be NULL */
} sq_handler;

#endif /* SQ_HANDLER_H */
