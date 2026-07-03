#include "modules/json.h"

#include "runtime/module_wire.h"

static DWORD ascii_len(const char *text)
{
        DWORD n = 0;

        if (text == NULL)
        {
                return 0;
        }
        while (text[n] != '\0')
        {
                n++;
        }
        return n;
}

static BOOL reserve(sq_json *json, DWORD extra)
{
        if (json == NULL || json->data == NULL || json->cap == 0)
        {
                return FALSE;
        }
        return extra <= json->cap && json->len <= json->cap - extra;
}

static BOOL append_mem(sq_json *json, const char *text, DWORD len)
{
        if (len == 0)
        {
                return TRUE;
        }
        if (text == NULL || !reserve(json, len))
        {
                return FALSE;
        }
        CopyMemory(json->data + json->len, text, len);
        json->len += len;
        return TRUE;
}

static char hex_digit(BYTE value)
{
        value = (BYTE)(value & 0x0fu);
        if (value < 10u)
        {
                return (char)('0' + value);
        }
        return (char)('a' + (value - 10u));
}

static BOOL append_hex_escape(sq_json *json, BYTE value)
{
        char escaped[6];

        escaped[0] = '\\';
        escaped[1] = 'u';
        escaped[2] = '0';
        escaped[3] = '0';
        escaped[4] = hex_digit((BYTE)(value >> 4));
        escaped[5] = hex_digit(value);
        return append_mem(json, escaped, (DWORD)sizeof escaped);
}

static BOOL append_escaped_byte(sq_json *json, BYTE value)
{
        char escaped[2];

        if (value == (BYTE)'"')
        {
                escaped[0] = '\\';
                escaped[1] = '"';
                return append_mem(json, escaped, (DWORD)sizeof escaped);
        }
        if (value == (BYTE)'\\')
        {
                escaped[0] = '\\';
                escaped[1] = '\\';
                return append_mem(json, escaped, (DWORD)sizeof escaped);
        }
        if (value == (BYTE)'\n')
        {
                escaped[0] = '\\';
                escaped[1] = 'n';
                return append_mem(json, escaped, (DWORD)sizeof escaped);
        }
        if (value == (BYTE)'\r')
        {
                escaped[0] = '\\';
                escaped[1] = 'r';
                return append_mem(json, escaped, (DWORD)sizeof escaped);
        }
        if (value == (BYTE)'\t')
        {
                escaped[0] = '\\';
                escaped[1] = 't';
                return append_mem(json, escaped, (DWORD)sizeof escaped);
        }
        if (value < 0x20u)
        {
                return append_hex_escape(json, value);
        }
        return sq_json_append_char(json, (char)value);
}

BOOL sq_json_init(sq_json *json, DWORD cap)
{
        if (json == NULL || cap == 0 || cap > SQ_MODULE_PACKET_MAX_PAYLOAD)
        {
                return FALSE;
        }
        json->data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)cap);
        json->len = 0;
        json->cap = cap;
        return json->data != NULL;
}

void sq_json_free(sq_json *json)
{
        if (json != NULL && json->data != NULL)
        {
                (void)HeapFree(GetProcessHeap(), 0, json->data);
                json->data = NULL;
                json->len = 0;
                json->cap = 0;
        }
}

BOOL sq_json_append_ascii(sq_json *json, const char *text)
{
        return append_mem(json, text, ascii_len(text));
}

BOOL sq_json_append_char(sq_json *json, char ch)
{
        return append_mem(json, &ch, 1);
}

BOOL sq_json_append_utf8_string(sq_json *json, const char *text)
{
        const char *cur = text;

        if (!sq_json_append_char(json, '"'))
        {
                return FALSE;
        }
        while (cur != NULL && *cur != '\0')
        {
                if (!append_escaped_byte(json, (BYTE)*cur))
                {
                        return FALSE;
                }
                cur++;
        }
        return sq_json_append_char(json, '"');
}

BOOL sq_json_append_bytes_string(sq_json *json, const BYTE *data, DWORD len)
{
        DWORD i = 0;

        if (!sq_json_append_char(json, '"'))
        {
                return FALSE;
        }
        for (i = 0; i < len; i++)
        {
                if (!append_escaped_byte(json, data[i]))
                {
                        return FALSE;
                }
        }
        return sq_json_append_char(json, '"');
}

BOOL sq_json_append_wide_string(sq_json *json, const wchar_t *text)
{
        int needed = 0;
        char *utf8 = NULL;
        BOOL ok = FALSE;

        if (text == NULL)
        {
                return sq_json_append_utf8_string(json, "");
        }
        needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
        if (needed <= 0)
        {
                return sq_json_append_utf8_string(json, "");
        }
        utf8 = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)needed);
        if (utf8 == NULL)
        {
                return FALSE;
        }
        if (WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, needed, NULL, NULL) > 0)
        {
                ok = sq_json_append_utf8_string(json, utf8);
        }
        (void)HeapFree(GetProcessHeap(), 0, utf8);
        return ok;
}

static BOOL append_wide_number(sq_json *json, const wchar_t *fmt, unsigned long long value)
{
        wchar_t wide[64];
        char utf8[64];
        int n = 0;

        (void)wnsprintfW(wide, (int)(sizeof wide / sizeof wide[0]), fmt, value);
        n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, (int)sizeof utf8, NULL, NULL);
        if (n <= 0)
        {
                return FALSE;
        }
        return sq_json_append_ascii(json, utf8);
}

BOOL sq_json_append_u32(sq_json *json, DWORD value)
{
        return append_wide_number(json, L"%lu", (unsigned long long)value);
}

BOOL sq_json_append_u64(sq_json *json, unsigned long long value)
{
        return append_wide_number(json, L"%I64u", value);
}

BOOL sq_json_append_i32(sq_json *json, LONG value)
{
        wchar_t wide[64];
        char utf8[64];
        int n = 0;

        (void)wnsprintfW(wide, (int)(sizeof wide / sizeof wide[0]), L"%ld", value);
        n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, (int)sizeof utf8, NULL, NULL);
        if (n <= 0)
        {
                return FALSE;
        }
        return sq_json_append_ascii(json, utf8);
}

BOOL sq_json_append_bool(sq_json *json, BOOL value)
{
        return sq_json_append_ascii(json, value ? "true" : "false");
}

BOOL sq_json_append_null(sq_json *json)
{
        return sq_json_append_ascii(json, "null");
}

BOOL sq_json_write(HANDLE output, const sq_json *json)
{
        if (json == NULL || json->data == NULL)
        {
                return FALSE;
        }
        return sq_module_write_data(output, (const BYTE *)json->data, json->len);
}

int sq_wide_to_utf8(const wchar_t *wide, char *out, int cap)
{
        if (wide == NULL || out == NULL || cap <= 0)
        {
                return 0;
        }
        return WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, cap, NULL, NULL);
}
