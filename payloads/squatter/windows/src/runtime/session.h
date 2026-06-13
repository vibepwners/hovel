/* session.h -- one connection carrying many multiplexed streams.
 *
 * A session owns a channel (a TCP or pipe connection) and demultiplexes the
 * frame stream on it into independent streams. Each OPEN frame starts a module
 * on its own thread, bridged to the stream by a message-mode named pipe:
 *
 *     peer <--frames--> [session] <--message-mode pipe--> [module thread]
 *
 *   - inbound DATA frame  -> written as one pipe message -> module ReadFile
 *   - module WriteFile    -> read as one pipe message    -> outbound DATA frame
 *   - module returns      -> pipe closes                 -> outbound CLOSE frame
 *
 * Because a frame is only dispatched once whole (see framing.h) and a pipe
 * message is delivered whole, a module sees exactly the discrete messages the
 * peer sent for its stream, never spliced with another stream's.
 *
 * Concurrency model (deliberately lock-light): the frame-reader loop runs on one
 * internal thread and is the sole owner of the stream list. Each stream adds two
 * threads (the module, and a pump that turns module output into frames). Only
 * channel writes are shared, and they are serialized by one lock.
 */
#ifndef SQ_MUX_SESSION_H
#define SQ_MUX_SESSION_H

#include "runtime/channel.h"
#include "runtime/module.h"
#include "base/win.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sq_session sq_session;

/* Start a session over `ch` (ownership transferred) dispatching to `modules`
 * (borrowed; must outlive the session). The reader thread starts immediately.
 * Returns NULL on failure (in which case the caller still owns `ch`). */
sq_session *sq_session_create(sq_channel *ch, const sq_module_table *modules);

/* Stop the session: close the connection, end every module and stream, join all
 * threads, and free everything. Tolerates NULL. */
void sq_session_destroy(sq_session *s);

/* Nonblocking completion check. True once the peer disconnected or the reader
 * hit a protocol/read error; the caller may then destroy the session. */
int sq_session_done(sq_session *s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_SESSION_H */
