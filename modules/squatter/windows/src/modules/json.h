#ifndef SQ_MODULES_JSON_H
#define SQ_MODULES_JSON_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        typedef struct sq_json
        {
                char *data;
                DWORD len;
                DWORD cap;
        } sq_json;

        BOOL sq_json_init(sq_json *json, DWORD cap);
        void sq_json_free(sq_json *json);
        BOOL sq_json_append_ascii(sq_json *json, const char *text);
        BOOL sq_json_append_char(sq_json *json, char ch);
        BOOL sq_json_append_utf8_string(sq_json *json, const char *text);
        BOOL sq_json_append_bytes_string(sq_json *json, const BYTE *data, DWORD len);
        BOOL sq_json_append_wide_string(sq_json *json, const wchar_t *text);
        BOOL sq_json_append_u32(sq_json *json, DWORD value);
        BOOL sq_json_append_u64(sq_json *json, unsigned long long value);
        BOOL sq_json_append_i32(sq_json *json, LONG value);
        BOOL sq_json_append_bool(sq_json *json, BOOL value);
        BOOL sq_json_append_null(sq_json *json);
        BOOL sq_json_write(HANDLE output, const sq_json *json);
        int sq_wide_to_utf8(const wchar_t *wide, char *out, int cap);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_JSON_H */
