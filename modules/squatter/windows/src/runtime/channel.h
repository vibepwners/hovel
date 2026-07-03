/* channel.h -- a blocking byte channel over either a SOCKET or a pipe HANDLE.
 *
 * The session speaks frames over a `channel` and does not care whether the
 * underlying connection is a TCP socket or a named pipe. Reads and writes are
 * blocking; the session runs them on dedicated threads. (An IOCP-backed channel
 * is the scaling path; the session's framing logic is unchanged by it.)
 */
#ifndef SQ_MUX_CHANNEL_H
#define SQ_MUX_CHANNEL_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        typedef struct sq_channel sq_channel; /* opaque */

        /* Wrap a connected socket / pipe. The channel takes ownership and closes the
         * underlying handle in sq_channel_free. Returns NULL on allocation failure. */
        sq_channel *sq_channel_from_socket(SOCKET s);
        sq_channel *sq_channel_from_handle(HANDLE h);

        /* Read up to `cap` bytes. Returns >0 bytes read, 0 on orderly EOF, -1 on error. */
        int sq_channel_read_some(sq_channel *ch, BYTE *buf, UINT32 cap);

        /* Write exactly `len` bytes (looping as needed). Returns TRUE on success. */
        BOOL sq_channel_write_all(sq_channel *ch, const BYTE *buf, UINT32 len);

        /* Shut the channel down so a blocked reader unblocks (used to stop a session). */
        void sq_channel_close(sq_channel *ch);

        void sq_channel_free(sq_channel *ch);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_CHANNEL_H */
