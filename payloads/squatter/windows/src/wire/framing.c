#include "wire/framing.h"

/* Reader state machine: accumulate the 16-byte header, then `length` payload
 * bytes, emitting one frame each time the payload completes. */
struct sq_frame_reader
{
        BYTE header[SQ_FRAME_HEADER_SIZE];
        UINT32 header_have;  /* header bytes accumulated so far                 */
        sq_frame_header hdr; /* parsed header, valid once header_have == SIZE  */
        BYTE *payload;       /* heap buffer for the current frame's payload     */
        UINT32 payload_have; /* payload bytes accumulated so far               */
        BOOL in_payload;     /* TRUE once the header is parsed and we want body */
        BOOL broken;         /* a protocol error has occurred; refuse more      */
};

static void *heap_alloc(UINT32 n)
{
        return HeapAlloc(GetProcessHeap(), 0, (n == 0) ? 1u : (SIZE_T)n);
}

static void heap_free(void *p)
{
        if (p != NULL)
        {
                (void)HeapFree(GetProcessHeap(), 0, p);
        }
}

sq_frame_reader *sq_frame_reader_new(void)
{
        sq_frame_reader *r = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *r);
        return r; /* fields zeroed: header_have/in_payload/broken all 0/FALSE */
}

void sq_frame_reader_free(sq_frame_reader *r)
{
        if (r == NULL)
        {
                return;
        }
        heap_free(r->payload);
        heap_free(r);
}

/* Reset to "awaiting header" for the next frame. */
static void reader_reset(sq_frame_reader *r)
{
        heap_free(r->payload);
        r->payload = NULL;
        r->payload_have = 0;
        r->header_have = 0;
        r->in_payload = FALSE;
}

static int reader_emit(sq_frame_reader *r, sq_frame_sink sink, void *ctx, const BYTE *payload, UINT32 length)
{
        int rc = sink(ctx, r->hdr.kind, r->hdr.stream_id, payload, length);

        reader_reset(r);
        return rc;
}

static int reader_take_header(sq_frame_reader *r, const BYTE *data, UINT32 len, UINT32 *off, sq_frame_sink sink,
                              void *ctx)
{
        UINT32 need = (UINT32)SQ_FRAME_HEADER_SIZE - r->header_have;
        UINT32 avail = len - *off;
        UINT32 take = (avail < need) ? avail : need;

        CopyMemory(r->header + r->header_have, data + *off, take);
        r->header_have += take;
        *off += take;

        if (r->header_have < (UINT32)SQ_FRAME_HEADER_SIZE)
        {
                return 0;
        }
        if (!sq_frame_header_decode(r->header, &r->hdr))
        {
                r->broken = TRUE;
                return -1;
        }
        r->in_payload = TRUE;
        r->payload_have = 0;
        r->payload = NULL;
        if (r->hdr.length == 0)
        {
                return reader_emit(r, sink, ctx, NULL, 0);
        }
        r->payload = heap_alloc(r->hdr.length);
        if (r->payload == NULL)
        {
                r->broken = TRUE;
                return -1;
        }
        return 0;
}

static int reader_take_payload(sq_frame_reader *r, const BYTE *data, UINT32 len, UINT32 *off, sq_frame_sink sink,
                               void *ctx)
{
        UINT32 need = r->hdr.length - r->payload_have;
        UINT32 avail = len - *off;
        UINT32 take = (avail < need) ? avail : need;

        if (take > 0)
        {
                CopyMemory(r->payload + r->payload_have, data + *off, take);
                r->payload_have += take;
                *off += take;
        }
        if (r->payload_have < r->hdr.length)
        {
                return 0;
        }
        return reader_emit(r, sink, ctx, r->payload, r->hdr.length);
}

int sq_frame_reader_push(sq_frame_reader *r, const BYTE *data, UINT32 len, sq_frame_sink sink, void *ctx)
{
        UINT32 off = 0;

        if (r == NULL || sink == NULL || (data == NULL && len != 0))
        {
                return -1;
        }
        if (r->broken)
        {
                return -1;
        }

        while (off < len)
        {
                if (!r->in_payload)
                {
                        int rc = reader_take_header(r, data, len, &off, sink, ctx);
                        if (rc != 0)
                        {
                                return rc;
                        }
                }
                else
                {
                        int rc = reader_take_payload(r, data, len, &off, sink, ctx);
                        if (rc != 0)
                        {
                                return rc;
                        }
                }
        }
        return 0;
}

BOOL sq_frame_encode(UINT16 kind, UINT64 stream_id, const BYTE *payload, UINT32 length, BYTE **out, UINT32 *out_len)
{
        sq_frame_header hdr = {0};
        BYTE *buf = NULL;
        UINT32 total = 0;

        if (out == NULL || out_len == NULL)
        {
                return FALSE;
        }
        *out = NULL;
        *out_len = 0;
        if (length > (UINT32)SQ_FRAME_MAX_PAYLOAD)
        {
                return FALSE;
        }
        if (length > 0 && payload == NULL)
        {
                return FALSE;
        }

        total = (UINT32)SQ_FRAME_HEADER_SIZE + length;
        buf = heap_alloc(total);
        if (buf == NULL)
        {
                return FALSE;
        }

        hdr.length = length;
        hdr.kind = kind;
        hdr.flags = 0;
        hdr.stream_id = stream_id;
        sq_frame_header_encode(&hdr, buf);
        if (length > 0)
        {
                CopyMemory(buf + SQ_FRAME_HEADER_SIZE, payload, length);
        }

        *out = buf;
        *out_len = total;
        return TRUE;
}

void sq_frame_buffer_free(BYTE *buf)
{
        heap_free(buf);
}
