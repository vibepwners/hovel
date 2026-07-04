#include "runtime/module_wire.h"

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

static UINT16 get_u16(const BYTE *p)
{
        return (UINT16)((UINT16)p[0] | (UINT16)((UINT16)p[1] << 8));
}

static UINT32 get_u32(const BYTE *p)
{
        return (UINT32)p[0] | ((UINT32)p[1] << 8) | ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

static BOOL is_magic(const BYTE *buf)
{
        return buf[0] == 'S' && buf[1] == 'Q' && buf[2] == 'M' && buf[3] == '1';
}

static BOOL read_message(HANDLE input, BYTE *buf, DWORD cap, DWORD *out)
{
        OVERLAPPED ov;
        BOOL ok = FALSE;
        DWORD err = 0;

        if (input == INVALID_HANDLE_VALUE || input == NULL || buf == NULL || out == NULL || cap == 0)
        {
                return FALSE;
        }
        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
                return FALSE;
        }
        *out = 0;
        ok = ReadFile(input, buf, cap, out, &ov);
        if (ok == FALSE)
        {
                err = GetLastError();
                if (err == ERROR_IO_PENDING)
                {
                        ok = GetOverlappedResult(input, &ov, out, TRUE);
                }
        }
        (void)CloseHandle(ov.hEvent);
        return ok;
}

static BOOL write_all(HANDLE output, const BYTE *buf, DWORD len)
{
        DWORD wrote = 0;

        if (len == 0)
        {
                return TRUE;
        }
        return WriteFile(output, buf, len, &wrote, NULL) != FALSE && wrote == len;
}

BOOL sq_module_packet_encode(sq_module_packet_kind kind, UINT32 control_kind, UINT32 code, const BYTE *payload,
                             DWORD len, BYTE **out, DWORD *out_len)
{
        BYTE *buf = NULL;
        DWORD total = SQ_MODULE_PACKET_HEADER_SIZE + len;

        if (out == NULL || out_len == NULL || len > SQ_MODULE_PACKET_MAX_PAYLOAD || (payload == NULL && len > 0))
        {
                return FALSE;
        }
        *out = NULL;
        *out_len = 0;
        buf = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)total);
        if (buf == NULL)
        {
                return FALSE;
        }
        buf[0] = 'S';
        buf[1] = 'Q';
        buf[2] = 'M';
        buf[3] = '1';
        put_u16(buf + 4, (UINT16)kind);
        put_u16(buf + 6, (UINT16)control_kind);
        put_u32(buf + 8, code);
        put_u32(buf + 12, len);
        if (len > 0)
        {
                CopyMemory(buf + SQ_MODULE_PACKET_HEADER_SIZE, payload, len);
        }
        *out = buf;
        *out_len = total;
        return TRUE;
}

static BOOL write_packet(HANDLE output, sq_module_packet_kind kind, UINT32 control_kind, UINT32 code,
                         const BYTE *payload, DWORD len)
{
        BYTE *buf = NULL;
        DWORD total = 0;
        BOOL ok = FALSE;

        if (output == INVALID_HANDLE_VALUE || output == NULL)
        {
                return FALSE;
        }
        if (!sq_module_packet_encode(kind, control_kind, code, payload, len, &buf, &total))
        {
                return FALSE;
        }
        ok = write_all(output, buf, total);
        sq_module_packet_free(buf);
        return ok;
}

BOOL sq_module_packet_decode(const BYTE *buf, DWORD len, sq_module_packet *out)
{
        UINT16 kind = 0;
        UINT32 payload_len = 0;

        if (out == NULL)
        {
                return FALSE;
        }
        out->kind = SQ_MODULE_PACKET_NONE;
        out->control_kind = 0;
        out->code = 0;
        out->payload = buf;
        out->length = len;
        if (buf == NULL || len < SQ_MODULE_PACKET_HEADER_SIZE || !is_magic(buf))
        {
                return FALSE;
        }
        kind = get_u16(buf + 4);
        payload_len = get_u32(buf + 12);
        if (payload_len > len - SQ_MODULE_PACKET_HEADER_SIZE)
        {
                return FALSE;
        }
        if (kind != SQ_MODULE_PACKET_DATA && kind != SQ_MODULE_PACKET_CONTROL)
        {
                return FALSE;
        }
        out->kind = (sq_module_packet_kind)kind;
        out->control_kind = get_u16(buf + 6);
        out->code = get_u32(buf + 8);
        out->payload = buf + SQ_MODULE_PACKET_HEADER_SIZE;
        out->length = payload_len;
        return TRUE;
}

void sq_module_packet_free(BYTE *buf)
{
        if (buf != NULL)
        {
                (void)HeapFree(GetProcessHeap(), 0, buf);
        }
}

BOOL sq_module_read_packet(HANDLE input, BYTE *buf, DWORD cap, sq_module_packet *out)
{
        DWORD got = 0;

        if (!read_message(input, buf, cap, &got) || got == 0)
        {
                return FALSE;
        }
        if (sq_module_packet_decode(buf, got, out))
        {
                return TRUE;
        }
        if (out == NULL)
        {
                return FALSE;
        }
        out->kind = SQ_MODULE_PACKET_DATA;
        out->control_kind = 0;
        out->code = 0;
        out->payload = buf;
        out->length = got;
        return TRUE;
}

BOOL sq_module_read_data(HANDLE input, BYTE *buf, DWORD cap, DWORD *out_len)
{
        BYTE packet_buf[SQ_MODULE_PACKET_HEADER_SIZE + SQ_MODULE_PACKET_MAX_PAYLOAD];
        sq_module_packet packet;

        if (buf == NULL || out_len == NULL)
        {
                return FALSE;
        }
        *out_len = 0;
        for (;;)
        {
                if (!sq_module_read_packet(input, packet_buf, (DWORD)sizeof packet_buf, &packet))
                {
                        return FALSE;
                }
                if (packet.kind == SQ_MODULE_PACKET_DATA)
                {
                        if (packet.length > cap)
                        {
                                return FALSE;
                        }
                        if (packet.length > 0)
                        {
                                CopyMemory(buf, packet.payload, (SIZE_T)packet.length);
                        }
                        *out_len = packet.length;
                        return TRUE;
                }
                if (packet.kind == SQ_MODULE_PACKET_CONTROL && packet.control_kind == SQ_MODULE_CONTROL_CLOSE)
                {
                        return FALSE;
                }
        }
}

BOOL sq_module_write_data(HANDLE output, const BYTE *data, DWORD len)
{
        if (len == 0)
        {
                return TRUE;
        }
        return write_packet(output, SQ_MODULE_PACKET_DATA, 0, 0, data, len);
}

BOOL sq_module_write_control(HANDLE output, UINT32 kind, UINT32 code, const char *message)
{
        const BYTE *payload = NULL;
        DWORD len = 0;

        if (message != NULL)
        {
                payload = (const BYTE *)message;
                while (payload[len] != '\0')
                {
                        len++;
                }
        }
        return write_packet(output, SQ_MODULE_PACKET_CONTROL, kind, code, payload, len);
}
