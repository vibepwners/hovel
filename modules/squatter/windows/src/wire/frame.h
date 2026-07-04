/* frame.h -- the wire framing for stream multiplexing.
 *
 * A connection carries a sequence of frames. Each frame is a fixed 16-byte
 * little-endian header followed by `length` payload bytes:
 *
 *     offset  size  field
 *     0       4     length     (UINT32) payload bytes that follow the header
 *     4       2     kind       (UINT16) sq_frame_kind
 *     6       2     flags      (UINT16) reserved, 0
 *     8       8     stream_id  (UINT64)
 *
 * A reader pulls the header, then exactly `length` payload bytes, before doing
 * anything with the frame. That is what makes a message "complete without
 * intersplicing": frames belonging to different streams interleave only at
 * frame boundaries, never inside a message.
 *
 * DATA frames carry a module's raw bytes as payload. OPEN/CLOSE/CONTROL frames
 * carry a protobuf-shaped control message (see proto/control.proto). The header
 * is hand-serialized little-endian so the format is independent of struct
 * padding and host endianness.
 *
 * Types are fixed-width Win32 spellings (UINT32/UINT16/UINT64/BYTE) by design.
 */
#ifndef SQ_MUX_FRAME_H
#define SQ_MUX_FRAME_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        enum
        {
                SQ_FRAME_HEADER_SIZE = 16,
                /* Largest payload a single frame may carry. A frame is one whole message;
                 * this bounds per-message memory. Tune as needed; it is not a connection or
                 * stream-count limit. */
                SQ_FRAME_MAX_PAYLOAD = 1 << 20 /* 1 MiB */
        };

        typedef enum sq_frame_kind
        {
                SQ_FRAME_DATA = 0,    /* payload: module raw bytes                         */
                SQ_FRAME_OPEN = 1,    /* payload: control.proto OpenStream                 */
                SQ_FRAME_CLOSE = 2,   /* payload: control.proto CloseStream (may be empty) */
                SQ_FRAME_CONTROL = 3, /* payload: control.proto StreamEvent                */
        } sq_frame_kind;

        typedef struct sq_frame_header
        {
                UINT32 length;
                UINT16 kind;
                UINT16 flags;
                UINT64 stream_id;
        } sq_frame_header;

        /* Serialize `h` into 16 little-endian bytes. Never fails. */
        void sq_frame_header_encode(const sq_frame_header *h, BYTE out[SQ_FRAME_HEADER_SIZE]);

        /* Parse 16 little-endian bytes into `out`. Returns FALSE (and leaves *out
         * zeroed) if the encoded length exceeds SQ_FRAME_MAX_PAYLOAD or the kind is not
         * a known sq_frame_kind -- both are signs of a corrupt or hostile peer. */
        BOOL sq_frame_header_decode(const BYTE in[SQ_FRAME_HEADER_SIZE], sq_frame_header *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_FRAME_H */
