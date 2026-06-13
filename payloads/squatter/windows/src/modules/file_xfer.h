/* file_xfer.h -- the getfile/putfile sub-protocol.
 *
 * getfile and putfile move arbitrarily large files through *fixed-size* buffers:
 * the file is sipped one SQ_XFER_CHUNK at a time, and nothing larger than a
 * chunk is ever resident. Backpressure does the rest -- TCP flow control, the
 * stream's message-mode pipe (which blocks a writer when full), and blocking
 * disk writes together cap how much is in flight, so memory stays bounded no
 * matter how big the file is.
 *
 * Client and server cooperate via typed messages carried in the stream's DATA
 * frames. Each message's first byte is a type tag:
 *
 *   'S' status   payload is a UTF-8 line, "OK ..." or "ERR ..."
 *   'D' data     payload is one file chunk (1..SQ_XFER_CHUNK bytes)
 *   'E' eof       payload empty; no more data follows
 *
 * getfile (server -> client): S "OK <size>", then D... , then E, then CLOSE.
 *                             (or S "ERR ..." then CLOSE on failure)
 * putfile (client -> server): server sends S "OK"; client sends D..., then E;
 *                             server replies S "OK <bytes>" (or "ERR ..."), CLOSE.
 *
 * A chunk plus its tag byte must fit a single pipe message, so SQ_XFER_CHUNK is
 * kept well under the session's 64 KiB pipe/read buffers.
 */
#ifndef SQ_MUX_FILE_XFER_H
#define SQ_MUX_FILE_XFER_H

#include "base/win.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SQ_XFER_CHUNK = 32768,                 /* file bytes per message      */
    SQ_XFER_MSG_MAX = 1 + SQ_XFER_CHUNK    /* tag byte + chunk            */
};

#define SQ_XFER_STAT ((BYTE)'S')
#define SQ_XFER_DATA ((BYTE)'D')
#define SQ_XFER_EOF  ((BYTE)'E')

/* Send a one-line status message (the tag is prepended). */
BOOL sq_xfer_send_stat(HANDLE pipe, const char *text);

/* Send the end-of-data marker. */
BOOL sq_xfer_send_eof(HANDLE pipe);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_FILE_XFER_H */
