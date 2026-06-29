#include "modules/wininfo.h"

#include "modules/json.h"
#include "runtime/module_wire.h"
#include "wire/control_codec.h"

enum
{
        SQ_JSON_DOC_CAP = 60000,
        SQ_SMALL_WIDE = 256,
        SQ_HOTFIX_LIMIT = 64
};

static BOOL json_field_name(sq_json *json, const char *name, BOOL *first)
{
        if (!*first && !sq_json_append_char(json, ','))
        {
                return FALSE;
        }
        *first = FALSE;
        return sq_json_append_utf8_string(json, name) && sq_json_append_char(json, ':');
}

static const char *arch_name(WORD arch)
{
        switch (arch)
        {
        case PROCESSOR_ARCHITECTURE_AMD64:
                return "x64";
        case PROCESSOR_ARCHITECTURE_INTEL:
                return "x86";
        case PROCESSOR_ARCHITECTURE_ARM:
                return "arm";
#ifdef PROCESSOR_ARCHITECTURE_ARM64
        case PROCESSOR_ARCHITECTURE_ARM64:
                return "arm64";
#endif
        default:
                return "unknown";
        }
}

static BOOL append_wide_field(sq_json *json, const char *name, const wchar_t *value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_wide_string(json, value);
}

static BOOL append_u32_field(sq_json *json, const char *name, DWORD value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_u32(json, value);
}

static void read_computer_name(COMPUTER_NAME_FORMAT format, wchar_t *out, DWORD cap)
{
        DWORD len = cap;

        if (out == NULL || cap == 0)
        {
                return;
        }
        out[0] = L'\0';
        if (GetComputerNameExW(format, out, &len) == FALSE)
        {
                out[0] = L'\0';
        }
}

static BOOL append_privileges(sq_json *json)
{
        /* #lizard forgive -- token privilege JSON is a bounded list walk. */
        HANDLE token = NULL;
        DWORD needed = 0;
        TOKEN_PRIVILEGES *privileges = NULL;
        DWORD i = 0;
        BOOL first = TRUE;

        if (!sq_json_append_char(json, '['))
        {
                return FALSE;
        }
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE)
        {
                return sq_json_append_char(json, ']');
        }
        (void)GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
        if (needed == 0)
        {
                (void)CloseHandle(token);
                return sq_json_append_char(json, ']');
        }
        privileges = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)needed);
        if (privileges == NULL)
        {
                (void)CloseHandle(token);
                return FALSE;
        }
        if (GetTokenInformation(token, TokenPrivileges, privileges, needed, &needed) != FALSE)
        {
                for (i = 0; i < privileges->PrivilegeCount; i++)
                {
                        wchar_t name[128];
                        DWORD name_len = (DWORD)(sizeof name / sizeof name[0]);
                        BOOL item_first = TRUE;

                        if (LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, name, &name_len) == FALSE)
                        {
                                continue;
                        }
                        if (!first && !sq_json_append_char(json, ','))
                        {
                                break;
                        }
                        first = FALSE;
                        if (!sq_json_append_char(json, '{') || !append_wide_field(json, "name", name, &item_first) ||
                            !json_field_name(json, "enabled", &item_first) ||
                            !sq_json_append_bool(json,
                                                 (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0) ||
                            !sq_json_append_char(json, '}'))
                        {
                                break;
                        }
                }
        }
        (void)HeapFree(GetProcessHeap(), 0, privileges);
        (void)CloseHandle(token);
        return sq_json_append_char(json, ']');
}

static BOOL append_drives(sq_json *json)
{
        /* #lizard forgive -- drive JSON marshalling is a bounded list walk. */
        wchar_t drives[512];
        DWORD len = 0;
        DWORD pos = 0;
        BOOL first = TRUE;

        if (!sq_json_append_char(json, '['))
        {
                return FALSE;
        }
        len = GetLogicalDriveStringsW((DWORD)(sizeof drives / sizeof drives[0]), drives);
        while (len > 0 && pos < len && drives[pos] != L'\0')
        {
                const wchar_t *drive = drives + pos;
                BOOL item_first = TRUE;
                UINT type = GetDriveTypeW(drive);

                if (!first && !sq_json_append_char(json, ','))
                {
                        return FALSE;
                }
                first = FALSE;
                if (!sq_json_append_char(json, '{') || !append_wide_field(json, "path", drive, &item_first) ||
                    !json_field_name(json, "type", &item_first) || !sq_json_append_u32(json, (DWORD)type) ||
                    !sq_json_append_char(json, '}'))
                {
                        return FALSE;
                }
                pos += (DWORD)lstrlenW(drive) + 1u;
        }
        return sq_json_append_char(json, ']');
}

static BOOL append_adapters(sq_json *json)
{
        /* #lizard forgive -- adapter JSON marshalling is a bounded list walk. */
        ULONG len = 0;
        IP_ADAPTER_INFO *info = NULL;
        IP_ADAPTER_INFO *cur = NULL;
        BOOL first = TRUE;

        if (!sq_json_append_char(json, '['))
        {
                return FALSE;
        }
        if (GetAdaptersInfo(NULL, &len) != ERROR_BUFFER_OVERFLOW || len == 0)
        {
                return sq_json_append_char(json, ']');
        }
        info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)len);
        if (info == NULL)
        {
                return FALSE;
        }
        if (GetAdaptersInfo(info, &len) == NO_ERROR)
        {
                for (cur = info; cur != NULL; cur = cur->Next)
                {
                        BOOL item_first = TRUE;

                        if (!first && !sq_json_append_char(json, ','))
                        {
                                break;
                        }
                        first = FALSE;
                        if (!sq_json_append_char(json, '{') || !json_field_name(json, "name", &item_first) ||
                            !sq_json_append_utf8_string(json, cur->AdapterName) ||
                            !json_field_name(json, "description", &item_first) ||
                            !sq_json_append_utf8_string(json, cur->Description) ||
                            !json_field_name(json, "ip", &item_first) ||
                            !sq_json_append_utf8_string(json, cur->IpAddressList.IpAddress.String) ||
                            !sq_json_append_char(json, '}'))
                        {
                                break;
                        }
                }
        }
        (void)HeapFree(GetProcessHeap(), 0, info);
        return sq_json_append_char(json, ']');
}

static BOOL append_hotfixes(sq_json *json)
{
        HKEY key = NULL;
        DWORD index = 0;
        DWORD count = 0;
        BOOL first = TRUE;

        if (!sq_json_append_char(json, '['))
        {
                return FALSE;
        }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix", 0, KEY_READ,
                          &key) != ERROR_SUCCESS)
        {
                return sq_json_append_char(json, ']');
        }
        while (count < SQ_HOTFIX_LIMIT)
        {
                wchar_t name[SQ_SMALL_WIDE];
                DWORD name_len = (DWORD)(sizeof name / sizeof name[0]);
                LONG rc = RegEnumKeyExW(key, index, name, &name_len, NULL, NULL, NULL, NULL);

                if (rc != ERROR_SUCCESS)
                {
                        break;
                }
                if (!first && !sq_json_append_char(json, ','))
                {
                        break;
                }
                first = FALSE;
                if (!sq_json_append_wide_string(json, name))
                {
                        break;
                }
                index++;
                count++;
        }
        (void)RegCloseKey(key);
        return sq_json_append_char(json, ']');
}

int sq_wininfo_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- host facts are linear WinAPI collection and JSON emission. */
        sq_json json;
        OSVERSIONINFOW os;
        SYSTEM_INFO sys;
        wchar_t hostname[SQ_SMALL_WIDE];
        wchar_t domain[SQ_SMALL_WIDE];
        wchar_t user[SQ_SMALL_WIDE];
        DWORD user_len = (DWORD)(sizeof user / sizeof user[0]);
        BOOL first = TRUE;
        BOOL ok = FALSE;

        (void)input;
        (void)argc;
        (void)argv;
        ZeroMemory(&os, sizeof os);
        ZeroMemory(&sys, sizeof sys);
        ZeroMemory(hostname, sizeof hostname);
        ZeroMemory(domain, sizeof domain);
        ZeroMemory(user, sizeof user);
        os.dwOSVersionInfoSize = sizeof os;
        (void)GetVersionExW(&os);
        read_computer_name(ComputerNameDnsHostname, hostname, (DWORD)(sizeof hostname / sizeof hostname[0]));
        read_computer_name(ComputerNameDnsDomain, domain, (DWORD)(sizeof domain / sizeof domain[0]));
        if (domain[0] == L'\0')
        {
                (void)GetEnvironmentVariableW(L"USERDOMAIN", domain, (DWORD)(sizeof domain / sizeof domain[0]));
        }
        (void)GetUserNameW(user, &user_len);
        GetNativeSystemInfo(&sys);

        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "hostname", hostname, &first) &&
             append_wide_field(&json, "domainOrWorkgroup", domain, &first) &&
             append_wide_field(&json, "currentUser", user, &first) && json_field_name(&json, "arch", &first) &&
             sq_json_append_utf8_string(&json, arch_name(sys.wProcessorArchitecture)) &&
             append_u32_field(&json, "osMajor", os.dwMajorVersion, &first) &&
             append_u32_field(&json, "osMinor", os.dwMinorVersion, &first) &&
             append_u32_field(&json, "osBuild", os.dwBuildNumber, &first) &&
             append_u32_field(&json, "uptimeMs", GetTickCount(), &first) &&
             json_field_name(&json, "tokenPrivileges", &first) && append_privileges(&json) &&
             json_field_name(&json, "networkAdapters", &first) && append_adapters(&json) &&
             json_field_name(&json, "drives", &first) && append_drives(&json) &&
             json_field_name(&json, "hotfixes", &first) && append_hotfixes(&json) && sq_json_append_char(&json, '}') &&
             sq_json_write(output, &json);
        sq_json_free(&json);
        if (!ok)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "wininfo failed");
                return 1;
        }
        return 0;
}
