#include "modules/process.h"

#include "modules/json.h"
#include "runtime/module_wire.h"
#include "wire/control_codec.h"

enum
{
        SQ_JSON_DOC_CAP = 60000,
        SQ_CAPTURE_CAP = 24000,
        SQ_READ_CHUNK = 4096,
        SQ_COMMAND_LINE_MAX = 8192,
        SQ_DEFAULT_TIMEOUT_MS = 15000
};

typedef struct capture_state
{
        HANDLE read_pipe;
        BYTE *buf;
        DWORD len;
        DWORD cap;
} capture_state;

typedef struct source_process_info
{
        DWORD pid;
        DWORD session_id;
        BOOL has_session_id;
} source_process_info;

BOOL WINAPI CreateEnvironmentBlock(LPVOID *environment, HANDLE token, BOOL inherit);
BOOL WINAPI DestroyEnvironmentBlock(LPVOID environment);

static DWORD parse_u32(const wchar_t *text, DWORD fallback)
{
        DWORD value = 0;

        if (text == NULL || text[0] == L'\0')
        {
                return fallback;
        }
        while (*text != L'\0')
        {
                if (*text < L'0' || *text > L'9')
                {
                        return fallback;
                }
                value = value * 10u + (DWORD)(*text - L'0');
                text++;
        }
        return value;
}

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

static BOOL append_bool_field(sq_json *json, const char *name, BOOL value, BOOL *first)
{
        return json_field_name(json, name, first) && sq_json_append_bool(json, value);
}

static BOOL append_nullable_u32_field(sq_json *json, const char *name, DWORD value, BOOL has_value, BOOL *first)
{
        if (!json_field_name(json, name, first))
        {
                return FALSE;
        }
        return has_value ? sq_json_append_u32(json, value) : sq_json_append_null(json);
}

static BOOL append_nullable_wide_field(sq_json *json, const char *name, const wchar_t *value, BOOL *first)
{
        if (!json_field_name(json, name, first))
        {
                return FALSE;
        }
        return value != NULL ? sq_json_append_wide_string(json, value) : sq_json_append_null(json);
}

static wchar_t ascii_lower_w(wchar_t ch)
{
        if (ch >= L'A' && ch <= L'Z')
        {
                return ch + (wchar_t)(L'a' - L'A');
        }
        return ch;
}

static BOOL wide_ascii_equal_ci(const wchar_t *a, const wchar_t *b)
{
        if (a == NULL || b == NULL)
        {
                return FALSE;
        }
        while (*a != L'\0' && *b != L'\0')
        {
                if (ascii_lower_w(*a) != ascii_lower_w(*b))
                {
                        return FALSE;
                }
                a++;
                b++;
        }
        return *a == *b;
}

static BOOL set_source_session(source_process_info *source)
{
        DWORD session_id = 0;

        if (source == NULL)
        {
                return FALSE;
        }
        if (ProcessIdToSessionId(source->pid, &session_id) == FALSE)
        {
                source->has_session_id = FALSE;
                source->session_id = 0;
                return FALSE;
        }
        source->session_id = session_id;
        source->has_session_id = TRUE;
        return TRUE;
}

static BOOL find_default_source_process(source_process_info *source)
{
        /* #lizard forgive -- default token source selection is a bounded process snapshot walk. */
        HANDLE snapshot = INVALID_HANDLE_VALUE;
        PROCESSENTRY32W entry;
        source_process_info fallback;
        DWORD active_session = WTSGetActiveConsoleSessionId();
        BOOL have_fallback = FALSE;
        BOOL found = FALSE;

        if (source == NULL)
        {
                return FALSE;
        }
        ZeroMemory(source, sizeof *source);
        ZeroMemory(&fallback, sizeof fallback);
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
                return FALSE;
        }
        ZeroMemory(&entry, sizeof entry);
        entry.dwSize = sizeof entry;
        if (Process32FirstW(snapshot, &entry) != FALSE)
        {
                do
                {
                        source_process_info candidate;

                        if (!wide_ascii_equal_ci(entry.szExeFile, L"explorer.exe"))
                        {
                                continue;
                        }
                        ZeroMemory(&candidate, sizeof candidate);
                        candidate.pid = entry.th32ProcessID;
                        (void)set_source_session(&candidate);
                        if (!have_fallback)
                        {
                                fallback = candidate;
                                have_fallback = TRUE;
                        }
                        if (candidate.has_session_id && active_session != 0xffffffffu &&
                            candidate.session_id == active_session)
                        {
                                *source = candidate;
                                found = TRUE;
                                break;
                        }
                } while (Process32NextW(snapshot, &entry) != FALSE);
        }
        (void)CloseHandle(snapshot);
        if (!found && have_fallback)
        {
                *source = fallback;
                found = TRUE;
        }
        return found;
}

static BOOL enable_current_process_privilege(const wchar_t *name)
{
        HANDLE token = NULL;
        TOKEN_PRIVILEGES privileges;
        BOOL ok = FALSE;

        if (name == NULL)
        {
                return FALSE;
        }
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == FALSE)
        {
                return FALSE;
        }
        ZeroMemory(&privileges, sizeof privileges);
        privileges.PrivilegeCount = 1;
        if (LookupPrivilegeValueW(NULL, name, &privileges.Privileges[0].Luid) != FALSE)
        {
                privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                ok = AdjustTokenPrivileges(token, FALSE, &privileges, (DWORD)sizeof privileges, NULL, NULL);
        }
        (void)CloseHandle(token);
        return ok;
}

static BOOL append_run_as_user_json(HANDLE output, const wchar_t *command, const wchar_t *cwd, DWORD pid,
                                    const source_process_info *source, BOOL used_environment)
{
        /* #lizard forgive -- run-as-user result JSON is linear field emission. */
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;

        if (source == NULL || !sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return FALSE;
        }
        ok = sq_json_append_char(&json, '{') && append_u32_field(&json, "pid", pid, &first) &&
             append_u32_field(&json, "sourcePid", source->pid, &first) &&
             append_nullable_u32_field(&json, "sessionId", source->session_id, source->has_session_id, &first) &&
             append_wide_field(&json, "command", command, &first) &&
             append_nullable_wide_field(&json, "cwd", cwd, &first) &&
             append_bool_field(&json, "usedEnvironment", used_environment, &first) && sq_json_append_char(&json, '}') &&
             sq_json_write(output, &json);
        sq_json_free(&json);
        return ok;
}

int sq_process_list_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- process JSON marshalling is a bounded snapshot walk. */
        HANDLE snapshot = INVALID_HANDLE_VALUE;
        PROCESSENTRY32W entry;
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
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
                sq_json_free(&json);
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "process snapshot failed");
                return 1;
        }
        ZeroMemory(&entry, sizeof entry);
        entry.dwSize = sizeof entry;
        ok = sq_json_append_char(&json, '[');
        if (ok && Process32FirstW(snapshot, &entry) != FALSE)
        {
                do
                {
                        DWORD session_id = 0;
                        BOOL item_first = TRUE;

                        if (!first && !sq_json_append_char(&json, ','))
                        {
                                ok = FALSE;
                                break;
                        }
                        first = FALSE;
                        ok = sq_json_append_char(&json, '{') &&
                             append_u32_field(&json, "pid", entry.th32ProcessID, &item_first) &&
                             append_u32_field(&json, "parentPid", entry.th32ParentProcessID, &item_first) &&
                             append_wide_field(&json, "imageName", entry.szExeFile, &item_first) &&
                             json_field_name(&json, "sessionId", &item_first);
                        if (ok)
                        {
                                if (ProcessIdToSessionId(entry.th32ProcessID, &session_id) != FALSE)
                                {
                                        ok = sq_json_append_u32(&json, session_id);
                                }
                                else
                                {
                                        ok = sq_json_append_null(&json);
                                }
                        }
                        ok = ok && sq_json_append_char(&json, '}');
                        if (!ok)
                        {
                                break;
                        }
                } while (Process32NextW(snapshot, &entry) != FALSE);
        }
        (void)CloseHandle(snapshot);
        ok = ok && sq_json_append_char(&json, ']') && sq_json_write(output, &json);
        sq_json_free(&json);
        return ok ? 0 : 1;
}

static DWORD WINAPI capture_thread(LPVOID param)
{
        capture_state *state = (capture_state *)param;
        BYTE chunk[SQ_READ_CHUNK];
        DWORD got = 0;

        if (state == NULL || state->read_pipe == INVALID_HANDLE_VALUE)
        {
                return 1;
        }
        for (;;)
        {
                got = 0;
                if (ReadFile(state->read_pipe, chunk, (DWORD)sizeof chunk, &got, NULL) == FALSE || got == 0)
                {
                        break;
                }
                if (state->len < state->cap)
                {
                        DWORD room = state->cap - state->len;
                        DWORD copy = got < room ? got : room;

                        CopyMemory(state->buf + state->len, chunk, copy);
                        state->len += copy;
                }
        }
        return 0;
}

static BOOL init_capture(capture_state *state)
{
        if (state == NULL)
        {
                return FALSE;
        }
        state->buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SQ_CAPTURE_CAP);
        state->len = 0;
        state->cap = SQ_CAPTURE_CAP;
        return state->buf != NULL;
}

static void free_capture(capture_state *state)
{
        if (state != NULL && state->buf != NULL)
        {
                (void)HeapFree(GetProcessHeap(), 0, state->buf);
                state->buf = NULL;
                state->len = 0;
                state->cap = 0;
        }
}

static BOOL make_pipe_pair(HANDLE *read_pipe, HANDLE *write_pipe)
{
        SECURITY_ATTRIBUTES sa;

        ZeroMemory(&sa, sizeof sa);
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        if (CreatePipe(read_pipe, write_pipe, &sa, 0) == FALSE)
        {
                return FALSE;
        }
        if (SetHandleInformation(*read_pipe, HANDLE_FLAG_INHERIT, 0) == FALSE)
        {
                (void)CloseHandle(*read_pipe);
                (void)CloseHandle(*write_pipe);
                *read_pipe = INVALID_HANDLE_VALUE;
                *write_pipe = INVALID_HANDLE_VALUE;
                return FALSE;
        }
        return TRUE;
}

static BOOL copy_command_line(const wchar_t *src, wchar_t *dst, int cap)
{
        if (src == NULL || dst == NULL || cap <= 0)
        {
                return FALSE;
        }
        if (lstrlenW(src) >= cap)
        {
                return FALSE;
        }
        (void)lstrcpynW(dst, src, cap);
        return TRUE;
}

static BOOL append_run_json(HANDLE output, const wchar_t *command, DWORD pid, DWORD exit_code, BOOL timed_out,
                            const capture_state *stdout_capture, const capture_state *stderr_capture)
{
        /* #lizard forgive -- process result JSON is linear field emission. */
        sq_json json;
        BOOL first = TRUE;
        BOOL ok = FALSE;

        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return FALSE;
        }
        ok = sq_json_append_char(&json, '{') && append_wide_field(&json, "command", command, &first) &&
             append_u32_field(&json, "pid", pid, &first) && append_u32_field(&json, "exitCode", exit_code, &first) &&
             json_field_name(&json, "timedOut", &first) && sq_json_append_bool(&json, timed_out) &&
             json_field_name(&json, "stdout", &first) &&
             sq_json_append_bytes_string(&json, stdout_capture->buf, stdout_capture->len) &&
             json_field_name(&json, "stderr", &first) &&
             sq_json_append_bytes_string(&json, stderr_capture->buf, stderr_capture->len) &&
             sq_json_append_char(&json, '}') && sq_json_write(output, &json);
        sq_json_free(&json);
        return ok;
}

int sq_process_run_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- WinAPI process setup requires explicit cleanup exits. */
        wchar_t command[SQ_COMMAND_LINE_MAX];
        HANDLE stdout_read = INVALID_HANDLE_VALUE;
        HANDLE stdout_write = INVALID_HANDLE_VALUE;
        HANDLE stderr_read = INVALID_HANDLE_VALUE;
        HANDLE stderr_write = INVALID_HANDLE_VALUE;
        HANDLE stdin_read = INVALID_HANDLE_VALUE;
        HANDLE stdin_write = INVALID_HANDLE_VALUE;
        HANDLE stdout_thread = NULL;
        HANDLE stderr_thread = NULL;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        capture_state stdout_capture;
        capture_state stderr_capture;
        DWORD timeout_ms = SQ_DEFAULT_TIMEOUT_MS;
        DWORD wait_rc = WAIT_FAILED;
        DWORD exit_code = 0;
        BOOL ok = FALSE;

        (void)input;
        ZeroMemory(&si, sizeof si);
        ZeroMemory(&pi, sizeof pi);
        ZeroMemory(&stdout_capture, sizeof stdout_capture);
        ZeroMemory(&stderr_capture, sizeof stderr_capture);
        if (argc < 2 || !copy_command_line(argv[1], command, (int)(sizeof command / sizeof command[0])))
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1,
                                              "usage: process.run <command-line> [timeout-ms] [cwd]");
                return 1;
        }
        if (argc > 2)
        {
                timeout_ms = parse_u32(argv[2], SQ_DEFAULT_TIMEOUT_MS);
        }
        if (!init_capture(&stdout_capture) || !init_capture(&stderr_capture) ||
            !make_pipe_pair(&stdout_read, &stdout_write) || !make_pipe_pair(&stderr_read, &stderr_write) ||
            !make_pipe_pair(&stdin_read, &stdin_write))
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "pipe setup failed");
                goto done;
        }
        (void)CloseHandle(stdin_write);
        stdin_write = INVALID_HANDLE_VALUE;
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdin_read;
        si.hStdOutput = stdout_write;
        si.hStdError = stderr_write;
        if (CreateProcessW(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, argc > 3 ? argv[3] : NULL, &si,
                           &pi) == FALSE)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "process create failed");
                goto done;
        }
        stdout_capture.read_pipe = stdout_read;
        stderr_capture.read_pipe = stderr_read;
        stdout_thread = CreateThread(NULL, 0, capture_thread, &stdout_capture, 0, NULL);
        stderr_thread = CreateThread(NULL, 0, capture_thread, &stderr_capture, 0, NULL);
        (void)CloseHandle(stdout_write);
        stdout_write = INVALID_HANDLE_VALUE;
        (void)CloseHandle(stderr_write);
        stderr_write = INVALID_HANDLE_VALUE;
        (void)CloseHandle(stdin_read);
        stdin_read = INVALID_HANDLE_VALUE;

        wait_rc = WaitForSingleObject(pi.hProcess, timeout_ms);
        if (wait_rc == WAIT_TIMEOUT)
        {
                (void)TerminateProcess(pi.hProcess, 1);
                (void)WaitForSingleObject(pi.hProcess, 5000);
        }
        (void)GetExitCodeProcess(pi.hProcess, &exit_code);
        if (stdout_thread != NULL)
        {
                (void)WaitForSingleObject(stdout_thread, 5000);
        }
        if (stderr_thread != NULL)
        {
                (void)WaitForSingleObject(stderr_thread, 5000);
        }
        ok = append_run_json(output, argv[1], pi.dwProcessId, exit_code, wait_rc == WAIT_TIMEOUT, &stdout_capture,
                             &stderr_capture);

done:
        if (stdout_thread != NULL)
        {
                (void)CloseHandle(stdout_thread);
        }
        if (stderr_thread != NULL)
        {
                (void)CloseHandle(stderr_thread);
        }
        if (pi.hThread != NULL)
        {
                (void)CloseHandle(pi.hThread);
        }
        if (pi.hProcess != NULL)
        {
                (void)CloseHandle(pi.hProcess);
        }
        if (stdout_read != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(stdout_read);
        }
        if (stdout_write != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(stdout_write);
        }
        if (stderr_read != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(stderr_read);
        }
        if (stderr_write != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(stderr_write);
        }
        if (stdin_read != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(stdin_read);
        }
        if (stdin_write != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(stdin_write);
        }
        free_capture(&stdout_capture);
        free_capture(&stderr_capture);
        return ok ? 0 : 1;
}

int sq_process_run_as_user_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- token duplication and process launch require explicit cleanup exits. */
        enum
        {
                SOURCE_TOKEN_ACCESS =
                    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
        };
        static const wchar_t assign_primary_privilege[] = L"SeAssignPrimaryTokenPrivilege";
        static const wchar_t increase_quota_privilege[] = L"SeIncreaseQuotaPrivilege";
        wchar_t command[SQ_COMMAND_LINE_MAX];
        wchar_t desktop[] = L"winsta0\\default";
        const wchar_t *cwd = NULL;
        source_process_info source;
        HANDLE source_process = NULL;
        HANDLE source_token = NULL;
        HANDLE primary_token = NULL;
        LPVOID environment = NULL;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        DWORD creation_flags = 0;
        BOOL used_environment = FALSE;
        BOOL ok = FALSE;

        (void)input;
        ZeroMemory(&source, sizeof source);
        ZeroMemory(&si, sizeof si);
        ZeroMemory(&pi, sizeof pi);
        if (argc < 2 || !copy_command_line(argv[1], command, (int)(sizeof command / sizeof command[0])))
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1,
                                              "usage: process.run_as_user <command-line> [cwd] [source-pid]");
                return 1;
        }
        if (argc > 2 && argv[2] != NULL && argv[2][0] != L'\0')
        {
                cwd = argv[2];
        }
        if (argc > 3)
        {
                source.pid = parse_u32(argv[3], 0);
                if (source.pid == 0)
                {
                        (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "invalid source process ID");
                        return 1;
                }
                (void)set_source_session(&source);
        }
        else if (!find_default_source_process(&source))
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(),
                                              "interactive user source process not found");
                return 1;
        }
        source_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, source.pid);
        if (source_process == NULL)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "source process open failed");
                goto done;
        }
        if (OpenProcessToken(source_process, SOURCE_TOKEN_ACCESS, &source_token) == FALSE)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(), "source token open failed");
                goto done;
        }
        (void)enable_current_process_privilege(assign_primary_privilege);
        (void)enable_current_process_privilege(increase_quota_privilege);
        if (DuplicateTokenEx(source_token, SOURCE_TOKEN_ACCESS, NULL, SecurityImpersonation, TokenPrimary,
                             &primary_token) == FALSE)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(),
                                              "source token duplicate failed");
                goto done;
        }
        if (CreateEnvironmentBlock(&environment, primary_token, FALSE) != FALSE)
        {
                used_environment = TRUE;
                creation_flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        si.cb = sizeof si;
        si.lpDesktop = desktop;
        if (CreateProcessAsUserW(primary_token, NULL, command, NULL, NULL, FALSE, creation_flags, environment, cwd, &si,
                                 &pi) == FALSE)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, GetLastError(),
                                              "process create-as-user failed");
                goto done;
        }
        ok = append_run_as_user_json(output, argv[1], cwd, pi.dwProcessId, &source, used_environment);

done:
        if (pi.hThread != NULL)
        {
                (void)CloseHandle(pi.hThread);
        }
        if (pi.hProcess != NULL)
        {
                (void)CloseHandle(pi.hProcess);
        }
        if (used_environment)
        {
                (void)DestroyEnvironmentBlock(environment);
        }
        if (primary_token != NULL)
        {
                (void)CloseHandle(primary_token);
        }
        if (source_token != NULL)
        {
                (void)CloseHandle(source_token);
        }
        if (source_process != NULL)
        {
                (void)CloseHandle(source_process);
        }
        return ok ? 0 : 1;
}

int sq_process_kill_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        /* #lizard forgive -- kill result is a small destructive action report. */
        DWORD pid = 0;
        HANDLE process = NULL;
        sq_json json;
        BOOL first = TRUE;
        BOOL killed = FALSE;
        BOOL ok = FALSE;

        (void)input;
        if (argc < 2)
        {
                (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, 1, "usage: process.kill <pid>");
                return 1;
        }
        pid = parse_u32(argv[1], 0);
        process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (process != NULL)
        {
                killed = TerminateProcess(process, 1);
                (void)CloseHandle(process);
        }
        if (!sq_json_init(&json, SQ_JSON_DOC_CAP))
        {
                return 1;
        }
        ok = sq_json_append_char(&json, '{') && append_u32_field(&json, "pid", pid, &first) &&
             json_field_name(&json, "killed", &first) && sq_json_append_bool(&json, killed) &&
             sq_json_append_char(&json, '}') && sq_json_write(output, &json);
        sq_json_free(&json);
        return ok && killed ? 0 : 1;
}
