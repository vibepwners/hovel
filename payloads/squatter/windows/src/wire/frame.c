#include "wire/frame.h"

/* Explicit little-endian (de)serialization: independent of struct layout and of
 * the host's byte order, so the wire format is stable. */

static void put_u16(BYTE *p, UINT16 v)
{
    p[0] = (BYTE)(v & 0xFFu);
    p[1] = (BYTE)((v >> 8) & 0xFFu);
}

static void put_u32(BYTE *p, UINT32 v)
{
    p[0] = (BYTE)(v & 0xFFu);
    p[1] = (BYTE)((v >> 8) & 0xFFu);
    p[2] = (BYTE)((v >> 16) & 0xFFu);
    p[3] = (BYTE)((v >> 24) & 0xFFu);
}

static void put_u64(BYTE *p, UINT64 v)
{
    UINT32 i = 0;
    for (i = 0; i < 8u; i++) {
        p[i] = (BYTE)((v >> (8u * i)) & 0xFFu);
    }
}

static UINT16 get_u16(const BYTE *p)
{
    return (UINT16)((UINT16)p[0] | (UINT16)((UINT16)p[1] << 8));
}

static UINT32 get_u32(const BYTE *p)
{
    return (UINT32)p[0] |
           ((UINT32)p[1] << 8) |
           ((UINT32)p[2] << 16) |
           ((UINT32)p[3] << 24);
}

static UINT64 get_u64(const BYTE *p)
{
    UINT64 v = 0;
    UINT32 i = 0;
    for (i = 0; i < 8u; i++) {
        v |= ((UINT64)p[i]) << (8u * i);
    }
    return v;
}

void sq_frame_header_encode(const sq_frame_header *h, BYTE out[SQ_FRAME_HEADER_SIZE])
{
    put_u32(out + 0, h->length);
    put_u16(out + 4, h->kind);
    put_u16(out + 6, h->flags);
    put_u64(out + 8, h->stream_id);
}

BOOL sq_frame_header_decode(const BYTE in[SQ_FRAME_HEADER_SIZE], sq_frame_header *out)
{
    UINT32 length = 0;
    UINT16 kind = 0;

    out->length = 0;
    out->kind = 0;
    out->flags = 0;
    out->stream_id = 0;

    length = get_u32(in + 0);
    kind = get_u16(in + 4);

    if (length > (UINT32)SQ_FRAME_MAX_PAYLOAD) {
        return FALSE;
    }
    if (kind != SQ_FRAME_DATA && kind != SQ_FRAME_OPEN && kind != SQ_FRAME_CLOSE) {
        return FALSE;
    }

    out->length = length;
    out->kind = kind;
    out->flags = get_u16(in + 6);
    out->stream_id = get_u64(in + 8);
    return TRUE;
}
