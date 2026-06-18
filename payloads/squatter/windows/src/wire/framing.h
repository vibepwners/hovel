/* framing.h -- incremental frame (de)serialization over a byte stream.
 *
 * A transport (TCP, a pipe) delivers bytes in arbitrary chunks that have no
 * relation to frame boundaries: one read might contain half a header, or three
 * frames plus a sliver of a fourth. sq_frame_reader absorbs that. You push
 * whatever bytes arrive; it accumulates them and invokes your sink exactly once
 * per *complete* frame, with the whole payload contiguous. That is the
 * mechanism behind "messages complete, without intersplicing" -- a frame is
 * never surfaced until all of it has arrived, and frames are surfaced in order.
 *
 * The writer side (sq_frame_encode) is the trivial inverse: header + payload
 * into one buffer ready to hand to the transport.
 *
 * CRT-free: payload reassembly buffers come from the process heap (HeapAlloc).
 */
#ifndef SQ_MUX_FRAMING_H
#define SQ_MUX_FRAMING_H

#include "base/win.h"
#include "wire/frame.h"

#ifdef __cplusplus
extern "C"
{
#endif

        /* Called once per complete frame. `payload` is valid only for the duration of
         * the call (it is freed afterwards); copy what you need to keep. `length` may
         * be 0, in which case `payload` may be NULL. Return 0 to continue, non-zero to
         * abort the push (the value is propagated back to the caller). */
        typedef int (*sq_frame_sink)(void *ctx, UINT16 kind, UINT64 stream_id, const BYTE *payload, UINT32 length);

        typedef struct sq_frame_reader sq_frame_reader; /* opaque */

        /* Allocate a reader. Returns NULL on allocation failure. */
        sq_frame_reader *sq_frame_reader_new(void);
        void sq_frame_reader_free(sq_frame_reader *r);

        /* Feed `len` freshly received bytes. Invokes `sink` for each complete frame.
         * Returns:
         *    0  all consumed, reader ready for more
         *   >0  the sink asked to stop (its return value)
         *   -1  protocol error (bad header / oversize) or allocation failure; the
         *       reader is now unusable and the connection should be dropped. */
        int sq_frame_reader_push(sq_frame_reader *r, const BYTE *data, UINT32 len, sq_frame_sink sink, void *ctx);

        /* Serialize one frame into a freshly heap-allocated buffer. On success *out
         * points to (SQ_FRAME_HEADER_SIZE + length) bytes and *out_len holds that size;
         * free it with sq_frame_buffer_free. Returns FALSE on oversize or OOM. */
        BOOL sq_frame_encode(UINT16 kind, UINT64 stream_id, const BYTE *payload, UINT32 length, BYTE **out,
                             UINT32 *out_len);

        /* Free a buffer returned by sq_frame_encode. */
        void sq_frame_buffer_free(BYTE *buf);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_FRAMING_H */
