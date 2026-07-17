#include "modules/evidence.h"

#include "modules/json.h"
#include "runtime/module_wire.h"
#include "wire/control_codec.h"

enum
{
        SQ_JSON_DOC_CAP = 60000,
        SQ_IO_CHUNK = 8192,
        SQ_REG_VALUE_CAP = 8192,
        SQ_EVENT_BUF = 65536,
        SQ_DEFAULT_EVENT_LIMIT = 10
};

#ifndef CALG_SHA_256
#define CALG_SHA_256 ((ALG_ID)0x0000800cu)
#endif

static BOOL json_field_name(sq_json *json, const char *name, BOOL *first)
{
        if (!*first && !sq_json_append_char(json, ','))
        {
                return FALSE;
        }
        *first = FALSE;
        return sq_json_append_utf8_string(json, name) && sq_json_append_char(json, ':');
}

static BOOL append_wide_field(sq_json *json, const char *name, const wchar_t *value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_wide_string(json, value);
}

static BOOL append_u32_field(sq_json *json, const char *name, DWORD value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_u32(json, value);
}

static unsigned long long filetime_u64(FILETIME ft)
{
        return ((unsigned long long)ft.dwHighDateTime << 32) | (unsigned long long)ft.dwLowDateTime;
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

static BOOL append_hex_string(sq_json *json, const BYTE *data, DWORD len)
{
        DWORD i = 0;

        if (!sq_json_append_char(json, '"'))
        {
                return FALSE;
        }
        for (i = 0; i < len; i++)
        {
                if (!sq_json_append_char(json, hex_digit((BYTE)(data[i] >> 4))) ||
                    !sq_json_append_char(json, hex_digit(data[i])))
                {
                        return FALSE;
                }
        }
        return sq_json_append_char(json, '"');
}

static BOOL hash_file_sha256(const wchar_t *path, BYTE *hash, DWORD *hash_len)
{
        /* #lizard forgive -- bounded WinAPI hashing has linear cleanup exits. */
        HCRYPTPROV provider = 0;
        HCRYPTHASH hasher = 0;
        HANDLE file = INVALID_HANDLE_VALUE;
        BYTE chunk[SQ_IO_CHUNK];
        DWORD got = 0;
        BOOL ok = FALSE;

        if (hash == NULL || hash_len == NULL)
        {
                return FALSE;
        }
        file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
                return FALSE;
        }
        if (CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == FALSE &&
            CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)
        {
                (void)CloseHandle(file);
                return FALSE;
        }
        if (CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hasher) == FALSE)
        {
                (void)CryptReleaseContext(provider, 0);
                (void)CloseHandle(file);
                return FALSE;
        }
        for (;;)
        {
                got = 0;
                if (ReadFile(file, chunk, (DWORD)sizeof chunk, &got, NULL) == FALSE)
                {
                        break;
                }
                if (got == 0)
                {
                        ok = TRUE;
                        break;
                }
                if (CryptHashData(hasher, chunk, got, 0) == FALSE)
                {
                        break;
                }
        }
        if (ok)
        {
                ok = CryptGetHashParam(hasher, HP_HASHVAL, hash, hash_len, 0);
        }
        (void)CryptDestroyHash(hasher);
        (void)CryptReleaseContext(provider, 0);
        (void)CloseHandle(file);
        return ok;
}

int sq_file_stat_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- evidence JSON marshalling is linear field emission. */
        WIN32_FILE_ATTRIBUTE_DATA data;
        BYTE hash[32];
        DWORD hash_len = (DWORD)sizeof hash;
        LARGE_INTEGER size;
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;
        BOOL hashed = FALSE;

        (void)input;
        if (argc < 2)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "usage: file.stat <path>");
                return 1;
        }
        ZeroMemory(&data, sizeof data);
        if (GetFileAttributesExW(argv[1], GetFileExInfoStandard, &data) == FALSE)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "file stat failed");
                return 1;
        }
        size.HighPart = (LONG)data.nFileSizeHigh;
        size.LowPart = data.nFileSizeLow;
        hashed = hash_file_sha256(argv[1], hash, &hash_len);
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "path", argv[1], &first) &&
             append_u32_field(&json, "attributes", data.dwFileAttributes, &first) &&
             json_field_name(&json, "size", &first) && sq_json_append_u64(&json, (unsigned long long)size.QuadPart) &&
             json_field_name(&json, "createdFiletime", &first) &&
             sq_json_append_u64(&json, filetime_u64(data.ftCreationTime)) &&
             json_field_name(&json, "accessedFiletime", &first) &&
             sq_json_append_u64(&json, filetime_u64(data.ftLastAccessTime)) &&
             json_field_name(&json, "modifiedFiletime", &first) &&
             sq_json_append_u64(&json, filetime_u64(data.ftLastWriteTime)) && json_field_name(&json, "sha256", &first);
        if (ok && hashed)
        {
                ok = append_hex_string(&json, hash, hash_len);
        }
        else if (ok)
        {
                ok = sq_json_append_null(&json);
        }
        ok = ok && sq_json_append_char(&json, '}') && sq_json_write(output, &json);
        sq_json_free(&json);
        return ok ? 0 : 1;
}

static HKEY parse_hive(const wchar_t *text)
{
        /* #lizard forgive -- explicit hive aliases avoid locale-sensitive parsing. */
        if (text == NULL)
        {
                return NULL;
        }
        if (lstrlenW(text) == 4 && text[0] == L'H' && text[1] == L'K' && text[2] == L'L' && text[3] == L'M')
        {
                return HKEY_LOCAL_MACHINE;
        }
        if (lstrlenW(text) == 4 && text[0] == L'H' && text[1] == L'K' && text[2] == L'C' && text[3] == L'U')
        {
                return HKEY_CURRENT_USER;
        }
        if (lstrlenW(text) == 4 && text[0] == L'H' && text[1] == L'K' && text[2] == L'C' && text[3] == L'R')
        {
                return HKEY_CLASSES_ROOT;
        }
        if (lstrlenW(text) == 3 && text[0] == L'H' && text[1] == L'K' && text[2] == L'U')
        {
                return HKEY_USERS;
        }
        return NULL;
}

int sq_registry_query_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- registry evidence has type-specific output branches. */
        HKEY root = NULL;
        HKEY key = NULL;
        BYTE value[SQ_REG_VALUE_CAP];
        DWORD value_len = (DWORD)sizeof value;
        DWORD value_type = 0;
        const wchar_t *value_name = NULL;
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;

        (void)input;
        if (argc < 3)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1,
                                              "usage: registry.query <HKLM|HKCU|HKCR|HKU> <key> [value]");
                return 1;
        }
        root = parse_hive(argv[1]);
        if (root == NULL)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "unsupported registry hive");
                return 1;
        }
        if (RegOpenKeyExW(root, argv[2], 0, KEY_READ, &key) != ERROR_SUCCESS)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "registry open failed");
                return 1;
        }
        value_name = argc > 3 ? argv[3] : NULL;
        if (RegQueryValueExW(key, value_name, NULL, &value_type, value, &value_len) != ERROR_SUCCESS)
        {
                (void)RegCloseKey(key);
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "registry query failed");
                return 1;
        }
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                (void)RegCloseKey(key);
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "hive", argv[1], &first) &&
             append_wide_field(&json, "key", argv[2], &first) &&
             append_wide_field(&json, "value", value_name != NULL ? value_name : L"", &first) &&
             append_u32_field(&json, "type", value_type, &first) && json_field_name(&json, "data", &first);
        if (ok && (value_type == REG_SZ || value_type == REG_EXPAND_SZ))
        {
                ok = sq_json_append_wide_string(&json, (const wchar_t *)value);
        }
        else if (ok && value_type == REG_DWORD && value_len >= sizeof(DWORD))
        {
                ok = sq_json_append_u32(&json, *(DWORD *)value);
        }
        else if (ok)
        {
                ok = append_hex_string(&json, value, value_len);
        }
        ok = ok && sq_json_append_char(&json, '}') && sq_json_write(output, &json);
        sq_json_free(&json);
        (void)RegCloseKey(key);
        return ok ? 0 : 1;
}

static DWORD parse_limit(const wchar_t *text)
{
        DWORD value = 0;

        if (text == NULL || text[0] == L'\0')
        {
                return SQ_DEFAULT_EVENT_LIMIT;
        }
        while (*text != L'\0')
        {
                if (*text < L'0' || *text > L'9')
                {
                        return SQ_DEFAULT_EVENT_LIMIT;
                }
                value = value * 10u + (DWORD)(*text - L'0');
                text++;
        }
        if (value == 0 || value > 50)
        {
                return SQ_DEFAULT_EVENT_LIMIT;
        }
        return value;
}

int sq_eventlog_query_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- event record walking is bounded and linear. */
        HANDLE log = NULL;
        BYTE buffer[SQ_EVENT_BUF];
        DWORD read = 0;
        DWORD needed = 0;
        DWORD emitted = 0;
        DWORD limit = SQ_DEFAULT_EVENT_LIMIT;
        sq_json json;
        BOOL ok = FALSE;

        (void)input;
        if (argc < 2)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "usage: eventlog.query <log> [limit]");
                return 1;
        }
        if (argc > 2)
        {
                limit = parse_limit(argv[2]);
        }
        log = OpenEventLogW(NULL, argv[1]);
        if (log == NULL)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "event log open failed");
                return 1;
        }
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                (void)CloseEventLog(log);
                return 1;
        }
        ok = sq_json_append_char(&json, '[');
        while (ok && emitted < limit &&
               ReadEventLogW(log, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, buffer, (DWORD)sizeof buffer,
                             &read, &needed) != FALSE)
        {
                DWORD offset = 0;

                while (ok && offset + sizeof(EVENTLOGRECORD) <= read && emitted < limit)
                {
                        EVENTLOGRECORD *record = (EVENTLOGRECORD *)(buffer + offset);
                        char *source = (char *)(record + 1);
                        BOOL item_first = TRUE;

                        if (emitted > 0 && !sq_json_append_char(&json, ','))
                        {
                                ok = FALSE;
                                break;
                        }
                        ok = sq_json_append_char(&json, '{') &&
                             append_u32_field(&json, "recordNumber", record->RecordNumber, &item_first) &&
                             append_u32_field(&json, "timeGenerated", record->TimeGenerated, &item_first) &&
                             append_u32_field(&json, "eventId", record->EventID, &item_first) &&
                             json_field_name(&json, "source", &item_first) &&
                             sq_json_append_utf8_string(&json, source) && sq_json_append_char(&json, '}');
                        if (record->Length == 0)
                        {
                                break;
                        }
                        offset += record->Length;
                        emitted++;
                }
        }
        ok = ok && sq_json_append_char(&json, ']') && sq_json_write(output, &json);
        sq_json_free(&json);
        (void)CloseEventLog(log);
        return ok ? 0 : 1;
}

int sq_drive_list_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- drive JSON marshalling is a bounded list walk. */
        wchar_t drives[512];
        DWORD len = 0;
        DWORD pos = 0;
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;

        (void)input;
        (void)argc;
        (void)argv;
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return 1;
        }
        len = GetLogicalDriveStringsW((DWORD)(sizeof drives / sizeof drives[0]), drives);
        ok = sq_json_append_char(&json, '[');
        while (ok && len > 0 && pos < len && drives[pos] != L'\0')
        {
                const wchar_t *drive = drives + pos;
                BOOL item_first = TRUE;

                if (!first && !sq_json_append_char(&json, ','))
                {
                        ok = FALSE;
                        break;
                }
                first = FALSE;
                ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "path", drive, &item_first) &&
                     append_u32_field(&json, "type", GetDriveTypeW(drive), &item_first) &&
                     sq_json_append_char(&json, '}');
                pos += (DWORD)lstrlenW(drive) + 1u;
        }
        ok = ok && sq_json_append_char(&json, ']') && sq_json_write(output, &json);
        sq_json_free(&json);
        return ok ? 0 : 1;
}

int sq_share_list_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- share JSON marshalling is a bounded list walk. */
        SHARE_INFO_1 *shares = NULL;
        DWORD read = 0;
        DWORD total = 0;
        DWORD resume = 0;
        DWORD i = 0;
        NET_API_STATUS status = 0;
        sq_json json;
        BOOL ok = FALSE;

        (void)input;
        (void)argc;
        (void)argv;
        status = NetShareEnum(NULL, 1, (LPBYTE *)&shares, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        /* Wine implements the API boundary but reports ERROR_NOT_SUPPORTED
         * when no server service is available. That is equivalent to an empty
         * local share inventory, and keeps this evidence command useful in
         * isolated assessment sandboxes instead of turning absence into a
         * transport-level module failure. */
        if (status == ERROR_NOT_SUPPORTED)
        {
                status = NERR_Success;
                read = 0;
        }
        if (status != NERR_Success && status != ERROR_MORE_DATA)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, status, "share enumeration failed");
                return 1;
        }
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                if (shares != NULL)
                {
                        (void)NetApiBufferFree(shares);
                }
                return 1;
        }
        ok = sq_json_append_char(&json, '[');
        for (i = 0; ok && i < read; i++)
        {
                BOOL item_first = TRUE;

                if (i > 0 && !sq_json_append_char(&json, ','))
                {
                        ok = FALSE;
                        break;
                }
                ok = sq_json_append_char(&json, '{') &&
                     append_wide_field(&json, "name", shares[i].shi1_netname, &item_first) &&
                     append_u32_field(&json, "type", shares[i].shi1_type, &item_first) &&
                     append_wide_field(&json, "remark", shares[i].shi1_remark, &item_first) &&
                     sq_json_append_char(&json, '}');
        }
        ok = ok && sq_json_append_char(&json, ']') && sq_json_write(output, &json);
        sq_json_free(&json);
        if (shares != NULL)
        {
                (void)NetApiBufferFree(shares);
        }
        return ok ? 0 : 1;
}

int sq_acl_stat_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        PSECURITY_DESCRIPTOR sd = NULL;
        LPWSTR sddl = NULL;
        DWORD status = 0;
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;

        (void)input;
        if (argc < 2)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "usage: acl.stat <path>");
                return 1;
        }
        status = GetNamedSecurityInfoW(argv[1], SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                       NULL, NULL, NULL, NULL, &sd);
        if (status != ERROR_SUCCESS)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, status, "acl query failed");
                return 1;
        }
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sddl, NULL) == FALSE)
        {
                (void)LocalFree(sd);
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "sddl conversion failed");
                return 1;
        }
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                (void)LocalFree(sddl);
                (void)LocalFree(sd);
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "path", argv[1], &first) &&
             append_wide_field(&json, "sddl", sddl, &first) && sq_json_append_char(&json, '}') &&
             sq_json_write(output, &json);
        sq_json_free(&json);
        (void)LocalFree(sddl);
        (void)LocalFree(sd);
        return ok ? 0 : 1;
}
