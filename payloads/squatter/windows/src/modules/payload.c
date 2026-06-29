#include "modules/payload.h"

#include "modules/json.h"
#include "runtime/module_wire.h"

enum
{
        SQ_JSON_DOC_CAP = 60000,
        SQ_PATH_MAX = 1024,
        SQ_CLEANUP_CMD_MAX = 4096
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

static BOOL append_wide_field(sq_json *json, const char *name, const wchar_t *value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_wide_string(json, value);
}

static BOOL append_u32_field(sq_json *json, const char *name, DWORD value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_u32(json, value);
}

static BOOL arg_equals(const wchar_t *a, const wchar_t *b)
{
        int i = 0;

        if (a == NULL || b == NULL)
        {
                return FALSE;
        }
        while (a[i] != L'\0' && b[i] != L'\0')
        {
                if (a[i] != b[i])
                {
                        return FALSE;
                }
                i++;
        }
        return a[i] == b[i];
}

static BOOL has_arg(int argc, wchar_t **argv, const wchar_t *want)
{
        int i = 0;

        for (i = 1; i < argc; i++)
        {
                if (arg_equals(argv[i], want))
                {
                        return TRUE;
                }
        }
        return FALSE;
}

static DWORD WINAPI delayed_exit_thread(LPVOID param)
{
        (void)param;
        Sleep(750);
        ExitProcess(0);
        return 0;
}

static BOOL schedule_delete(const wchar_t *path)
{
        wchar_t command[SQ_CLEANUP_CMD_MAX];
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;

        if (path == NULL || path[0] == L'\0')
        {
                return FALSE;
        }
        ZeroMemory(&si, sizeof si);
        ZeroMemory(&pi, sizeof pi);
        si.cb = sizeof si;
        (void)wnsprintfW(command, (int)(sizeof command / sizeof command[0]),
                         L"cmd.exe /C ping 127.0.0.1 -n 3 > nul & del /F /Q \"%s\"", path);
        if (CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == FALSE)
        {
                return FALSE;
        }
        (void)CloseHandle(pi.hThread);
        (void)CloseHandle(pi.hProcess);
        return TRUE;
}

int sq_payload_status_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        wchar_t path[SQ_PATH_MAX];
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;

        (void)input;
        (void)argc;
        (void)argv;
        ZeroMemory(path, sizeof path);
        (void)GetModuleFileNameW(NULL, path, (DWORD)(sizeof path / sizeof path[0]));
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_u32_field(&json, "pid", GetCurrentProcessId(), &first) &&
             append_wide_field(&json, "imagePath", path, &first) &&
             append_u32_field(&json, "uptimeMs", GetTickCount(), &first) && json_field_name(&json, "cleanup", &first) &&
             sq_json_append_utf8_string(&json, "self-stop; optional delayed self-delete") &&
             sq_json_append_char(&json, '}') && sq_json_write(output, &json);
        sq_json_free(&json);
        return ok ? 0 : 1;
}

int sq_payload_cleanup_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- cleanup is a small state report plus optional self-stop. */
        wchar_t path[SQ_PATH_MAX];
        HANDLE thread = NULL;
        sq_json json;
        BOOL first = TRUE;
        BOOL stop = TRUE;
        BOOL delete_file = FALSE;
        BOOL delete_scheduled = FALSE;
        BOOL ok = FALSE;

        (void)input;
        ZeroMemory(path, sizeof path);
        (void)GetModuleFileNameW(NULL, path, (DWORD)(sizeof path / sizeof path[0]));
        delete_file = has_arg(argc, argv, L"--delete-file");
        stop = !has_arg(argc, argv, L"--no-stop");
        if (delete_file)
        {
                delete_scheduled = schedule_delete(path);
        }
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "imagePath", path, &first) &&
             json_field_name(&json, "stopScheduled", &first) && sq_json_append_bool(&json, stop) &&
             json_field_name(&json, "deleteFileRequested", &first) && sq_json_append_bool(&json, delete_file) &&
             json_field_name(&json, "deleteFileScheduled", &first) && sq_json_append_bool(&json, delete_scheduled) &&
             sq_json_append_char(&json, '}') && sq_json_write(output, &json);
        sq_json_free(&json);
        if (ok && stop)
        {
                thread = CreateThread(NULL, 0, delayed_exit_thread, NULL, 0, NULL);
                if (thread != NULL)
                {
                        (void)CloseHandle(thread);
                }
        }
        return ok ? 0 : 1;
}
