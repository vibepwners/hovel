#include "wire/control_codec.h"

static void copy_bounded_len(char *dst, const BYTE *src, UINT32 len, int cap)
{
    int i = 0;
    int limit = 0;

    if (cap <= 0) {
        return;
    }
    limit = cap - 1;
    while (i < limit && (UINT32)i < len) {
        dst[i] = (char)src[i];
        i++;
    }
    dst[i] = '\0';
}

static UINT32 varint_size(UINT32 value)
{
    UINT32 size = 1;

    while (value >= 0x80u) {
        value >>= 7;
        size++;
    }
    return size;
}

static BYTE *write_varint(BYTE *cursor, UINT32 value)
{
    while (value >= 0x80u) {
        *cursor = (BYTE)((value & 0x7fu) | 0x80u);
        cursor++;
        value >>= 7;
    }
    *cursor = (BYTE)value;
    return cursor + 1;
}

static BOOL read_varint(const BYTE **cursor, const BYTE *end, UINT32 *out)
{
    UINT32 shift = 0;
    UINT32 value = 0;

    if (cursor == NULL || *cursor == NULL || out == NULL) {
        return FALSE;
    }
    while (*cursor < end && shift <= 28u) {
        BYTE b = **cursor;
        (*cursor)++;
        value |= ((UINT32)(b & 0x7fu)) << shift;
        if ((b & 0x80u) == 0) {
            *out = value;
            return TRUE;
        }
        shift += 7u;
    }
    return FALSE;
}

static UINT32 bounded_len(const char *value)
{
    UINT32 n = 0;

    if (value == NULL) {
        return 0;
    }
    while (value[n] != '\0') {
        n++;
    }
    return n;
}

static UINT32 encoded_string_size(UINT32 field, const char *value)
{
    UINT32 len = bounded_len(value);
    UINT32 tag = (field << 3) | 2u;

    return varint_size(tag) + varint_size(len) + len;
}

static BYTE *write_string(BYTE *cursor, UINT32 field, const char *value)
{
    UINT32 len = bounded_len(value);

    cursor = write_varint(cursor, (field << 3) | 2u);
    cursor = write_varint(cursor, len);
    if (len > 0) {
        CopyMemory(cursor, value, len);
        cursor += len;
    }
    return cursor;
}

BOOL sq_control_encode_open(const char *module, const char *const *args,
                            int n_args, BYTE **out, UINT32 *out_len)
{
    int i = 0;
    int count = 0;
    UINT32 total = 0;
    BYTE *buf = NULL;
    BYTE *cursor = NULL;

    if (out == NULL || out_len == NULL || module == NULL) {
        return FALSE;
    }
    *out = NULL;
    *out_len = 0;

    count = n_args;
    if (count < 0) {
        count = 0;
    }
    if (count > SQMUX_OPEN_ARGS_MAX) {
        count = SQMUX_OPEN_ARGS_MAX;
    }
    total = encoded_string_size(1u, module);
    for (i = 0; i < count; i++) {
        if (args != NULL && args[i] != NULL && args[i][0] != '\0') {
            total += encoded_string_size(2u, args[i]);
        }
    }

    buf = HeapAlloc(GetProcessHeap(), 0, (total == 0) ? 1u : (SIZE_T)total);
    if (buf == NULL) {
        return FALSE;
    }
    cursor = write_string(buf, 1u, module);
    for (i = 0; i < count; i++) {
        if (args != NULL && args[i] != NULL && args[i][0] != '\0') {
            cursor = write_string(cursor, 2u, args[i]);
        }
    }
    *out = buf;
    *out_len = (UINT32)(cursor - buf);
    return TRUE;
}

BOOL sq_control_decode_open(const BYTE *payload, UINT32 len,
                            sqmux_OpenStream *out)
{
    const BYTE *cursor = payload;
    const BYTE *end = NULL;

    if (out == NULL) {
        return FALSE;
    }
    ZeroMemory(out, sizeof *out);
    if (payload == NULL && len != 0) {
        return FALSE;
    }
    end = payload + len;
    while (cursor < end) {
        UINT32 tag = 0;
        UINT32 field = 0;
        UINT32 wire_type = 0;
        UINT32 value_len = 0;

        if (!read_varint(&cursor, end, &tag)) {
            return FALSE;
        }
        field = tag >> 3;
        wire_type = tag & 0x7u;
        if (wire_type != 2u || !read_varint(&cursor, end, &value_len)) {
            return FALSE;
        }
        if ((UINT32)(end - cursor) < value_len) {
            return FALSE;
        }
        if (field == 1u) {
            copy_bounded_len(out->module, cursor, value_len,
                             (int)sizeof out->module);
        } else if (field == 2u && out->args_count < SQMUX_OPEN_ARGS_MAX) {
            copy_bounded_len(out->args[out->args_count], cursor, value_len,
                             (int)sizeof out->args[out->args_count]);
            out->args_count++;
        }
        cursor += value_len;
    }
    return out->module[0] != '\0' ? TRUE : FALSE;
}

BOOL sq_control_encode_close(UINT32 code, BYTE **out, UINT32 *out_len)
{
    UINT32 total = varint_size((1u << 3) | 0u) + varint_size(code);
    BYTE *buf = NULL;
    BYTE *cursor = NULL;

    if (out == NULL || out_len == NULL) {
        return FALSE;
    }
    *out = NULL;
    *out_len = 0;
    buf = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)total);
    if (buf == NULL) {
        return FALSE;
    }
    cursor = write_varint(buf, (1u << 3) | 0u);
    cursor = write_varint(cursor, code);
    *out = buf;
    *out_len = (UINT32)(cursor - buf);
    return TRUE;
}

void sq_control_buffer_free(BYTE *buf)
{
    if (buf != NULL) {
        (void)HeapFree(GetProcessHeap(), 0, buf);
    }
}
