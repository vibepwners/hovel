#include "modules/cmd.h"

#include "base/win.h"

enum {
    SQ_CMD_LINE_MAX = 8192,
    SQ_CMD_IO_BUF = 4096,
    SQ_CMD_MSG_MAX = 256,
    SQ_CMD_SHUTDOWN_MS = 5000
};

typedef struct sq_cmd_pump {
    HANDLE out_read;
    HANDLE module_pipe;
    HANDLE process;
    BOOL overlapped;
    BOOL debug;
} sq_cmd_pump;

typedef struct sq_cmd_pipe_pair {
    HANDLE read;
    HANDLE write;
} sq_cmd_pipe_pair;

static LONG sq_cmd_pipe_counter;

static int append_wide(wchar_t *dst, int pos, int cap, const wchar_t *src)
{
    int i = 0;

    if (dst == NULL || src == NULL || cap <= 0) {
        return pos;
    }
    while (src[i] != L'\0' && pos < cap - 1) {
        dst[pos++] = src[i++];
    }
    dst[pos] = L'\0';
    return pos;
}

static int build_command_line(int argc, wchar_t **argv, wchar_t *out, int cap)
{
    int pos = 0;
    int i = 0;

    if (argc < 2 || out == NULL || cap <= 0) {
        return 0;
    }
    pos = append_wide(out, pos, cap, L"cmd.exe /c ");
    for (i = 1; i < argc; i++) {
        if (i > 1) {
            pos = append_wide(out, pos, cap, L" ");
        }
        pos = append_wide(out, pos, cap, argv[i] != NULL ? argv[i] : L"");
    }
    return pos;
}

static BOOL build_interactive_command_line(wchar_t *out, int cap)
{
    if (out == NULL || cap <= 0) {
        return FALSE;
    }
    out[0] = L'\0';
    (void)append_wide(out, 0, cap, L"cmd.exe /Q /K");
    return TRUE;
}

static BOOL write_utf8(HANDLE pipe, const wchar_t *message)
{
    char buf[SQ_CMD_MSG_MAX];
    int n = 0;
    DWORD wrote = 0;

    n = WideCharToMultiByte(CP_UTF8, 0, message, -1, buf, (int)sizeof buf,
                            NULL, NULL);
    if (n <= 1) {
        return FALSE;
    }
    return WriteFile(pipe, buf, (DWORD)(n - 1), &wrote, NULL);
}

static BOOL arg_equal(const wchar_t *a, const wchar_t *b)
{
    int i = 0;

    if (a == NULL || b == NULL) {
        return FALSE;
    }
    while (a[i] != L'\0' && b[i] != L'\0') {
        if (a[i] != b[i]) {
            return FALSE;
        }
        i++;
    }
    return a[i] == b[i];
}

static BOOL arg_is_interactive(const wchar_t *arg)
{
    return arg_equal(arg, L"--interactive") || arg_equal(arg, L"-i");
}

static BOOL has_arg(int argc, wchar_t **argv, const wchar_t *want)
{
    int i = 0;

    for (i = 1; i < argc; i++) {
        if (arg_equal(argv[i], want)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL has_interactive_arg(int argc, wchar_t **argv)
{
    int i = 0;

    for (i = 1; i < argc; i++) {
        if (arg_is_interactive(argv[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL interactive_requested(int argc, wchar_t **argv)
{
    if (argc < 2) {
        return TRUE;
    }
    if (argc == 2 && (arg_is_interactive(argv[1]) ||
                      arg_equal(argv[1], L"--debug"))) {
        return TRUE;
    }
    if (argc == 3 && has_arg(argc, argv, L"--debug") &&
        has_interactive_arg(argc, argv)) {
        return TRUE;
    }
    return FALSE;
}

static BOOL debug_requested(int argc, wchar_t **argv)
{
    return has_arg(argc, argv, L"--debug");
}

static void debug_line(HANDLE pipe, BOOL enabled, const wchar_t *event,
                       DWORD value, DWORD err)
{
    wchar_t msg[SQ_CMD_MSG_MAX];

    if (enabled == FALSE || pipe == INVALID_HANDLE_VALUE || pipe == NULL ||
        event == NULL) {
        return;
    }
    (void)wnsprintfW(msg, (int)(sizeof msg / sizeof msg[0]),
                     L"[sqcmd] %s value=%lu err=%lu", event,
                     (unsigned long)value, (unsigned long)err);
    (void)write_utf8(pipe, msg);
}

static BOOL write_exit(HANDLE pipe, DWORD exit_code)
{
    wchar_t msg[SQ_CMD_MSG_MAX];

    (void)wnsprintfW(msg, (int)(sizeof msg / sizeof msg[0]), L"exit=%lu",
                     (unsigned long)exit_code);
    return write_utf8(pipe, msg);
}

static BOOL wait_overlapped(HANDLE h, OVERLAPPED *ov, DWORD *transferred,
                            HANDLE debug_pipe, BOOL debug, HANDLE process)
{
    DWORD wait = 0;
    DWORD exit_code = 0;

    for (;;) {
        wait = WaitForSingleObject(ov->hEvent, 1000);
        if (wait == WAIT_OBJECT_0) {
            return GetOverlappedResult(h, ov, transferred, FALSE);
        }
        if (wait != WAIT_TIMEOUT) {
            return FALSE;
        }
        if (process != INVALID_HANDLE_VALUE && process != NULL &&
            WaitForSingleObject(process, 0) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(process, &exit_code) != FALSE) {
            debug_line(debug_pipe, debug, L"read wait process exited",
                       exit_code, 0);
        } else {
            debug_line(debug_pipe, debug, L"read wait pending", 0, 0);
        }
    }
}

static BOOL finish_pending_read(HANDLE h, OVERLAPPED *ov, DWORD *out,
                                HANDLE debug_pipe, BOOL debug, HANDLE process)
{
    BOOL ok = FALSE;
    DWORD exit_code = 0;

    debug_line(debug_pipe, debug, L"read pending", 0, ERROR_IO_PENDING);
    if (process != INVALID_HANDLE_VALUE && process != NULL &&
        WaitForSingleObject(process, 0) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process, &exit_code) != FALSE) {
        debug_line(debug_pipe, debug, L"process exited while pending",
                   exit_code, 0);
    }
    ok = wait_overlapped(h, ov, out, debug_pipe, debug, process);
    debug_line(debug_pipe, debug, ok ? L"read complete" : L"read wait failed",
               ok ? *out : 0, ok ? 0 : GetLastError());
    return ok;
}

static BOOL read_file_overlapped(HANDLE h, BYTE *buf, DWORD cap, DWORD *out,
                                 HANDLE debug_pipe, BOOL debug,
                                 HANDLE process)
{
    OVERLAPPED ov;
    BOOL ok = FALSE;
    DWORD err = 0;

    ZeroMemory(&ov, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        debug_line(debug_pipe, debug, L"read event failed", 0, GetLastError());
        return FALSE;
    }
    debug_line(debug_pipe, debug, L"read begin", cap, 0);
    ok = ReadFile(h, buf, cap, out, &ov);
    if (ok == FALSE) {
        err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            ok = finish_pending_read(h, &ov, out, debug_pipe, debug, process);
        } else if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) {
            debug_line(debug_pipe, debug, L"read eof", 0, err);
            ok = FALSE;
        } else {
            debug_line(debug_pipe, debug, L"read failed", 0, err);
        }
    } else {
        debug_line(debug_pipe, debug, L"read immediate", *out, 0);
    }
    (void)CloseHandle(ov.hEvent);
    return ok;
}

static void close_pipe_pair(sq_cmd_pipe_pair *pair)
{
    if (pair == NULL) {
        return;
    }
    if (pair->read != INVALID_HANDLE_VALUE && pair->read != NULL) {
        (void)CloseHandle(pair->read);
        pair->read = INVALID_HANDLE_VALUE;
    }
    if (pair->write != INVALID_HANDLE_VALUE && pair->write != NULL) {
        (void)CloseHandle(pair->write);
        pair->write = INVALID_HANDLE_VALUE;
    }
}

static BOOL make_child_output_pipe(sq_cmd_pipe_pair *pair, HANDLE debug_pipe,
                                   BOOL debug)
{
    SECURITY_ATTRIBUTES sa;
    wchar_t name[160];
    DWORD seq = 0;

    if (pair == NULL) {
        return FALSE;
    }
    pair->read = INVALID_HANDLE_VALUE;
    pair->write = INVALID_HANDLE_VALUE;

    seq = (DWORD)InterlockedIncrement(&sq_cmd_pipe_counter);
    (void)wnsprintfW(name, (int)(sizeof name / sizeof name[0]),
                     L"\\\\.\\pipe\\sqcmd-out-%lu-%lu",
                     (unsigned long)GetCurrentProcessId(),
                     (unsigned long)seq);

    pair->read = CreateNamedPipeW(
        name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT, 1, SQ_CMD_IO_BUF, SQ_CMD_IO_BUF, 120 * 1000,
        NULL);
    if (pair->read == INVALID_HANDLE_VALUE) {
        debug_line(debug_pipe, debug, L"stdout read pipe failed", 0,
                   GetLastError());
        return FALSE;
    }
    debug_line(debug_pipe, debug, L"stdout read pipe created", seq, 0);

    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    pair->write = CreateFileW(name, GENERIC_WRITE, 0, &sa, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (pair->write == INVALID_HANDLE_VALUE) {
        debug_line(debug_pipe, debug, L"stdout write pipe failed", 0,
                   GetLastError());
        close_pipe_pair(pair);
        return FALSE;
    }
    debug_line(debug_pipe, debug, L"stdout write pipe opened", seq, 0);
    (void)SetHandleInformation(pair->read, HANDLE_FLAG_INHERIT, 0);
    (void)SetHandleInformation(pair->write, HANDLE_FLAG_INHERIT,
                               HANDLE_FLAG_INHERIT);
    return TRUE;
}

static BOOL drain_child_output(HANDLE out_read, HANDLE module_pipe,
                               BOOL overlapped, BOOL debug, HANDLE process)
{
    BYTE buf[SQ_CMD_IO_BUF];
    DWORD got = 0;
    DWORD wrote = 0;

    for (;;) {
        if ((overlapped ? read_file_overlapped(out_read, buf, (DWORD)sizeof buf,
                                               &got, module_pipe, debug,
                                               process)
                        : ReadFile(out_read, buf, (DWORD)sizeof buf, &got,
                                   NULL)) == FALSE) {
            debug_line(module_pipe, debug, L"pump drain ended", 0,
                       GetLastError());
            return TRUE;
        }
        if (got == 0) {
            debug_line(module_pipe, debug, L"pump zero read", 0, 0);
            return TRUE;
        }
        debug_line(module_pipe, debug, L"pump forwarding", got, 0);
        if (WriteFile(module_pipe, buf, got, &wrote, NULL) == FALSE) {
            debug_line(module_pipe, debug, L"pump write failed", wrote,
                       GetLastError());
            return FALSE;
        }
    }
}

static DWORD WINAPI pump_child_output(LPVOID param)
{
    sq_cmd_pump *pump = (sq_cmd_pump *)param;

    if (pump == NULL) {
        return 1;
    }
    return drain_child_output(pump->out_read, pump->module_pipe,
                              pump->overlapped, pump->debug, pump->process)
               ? 0
               : 1;
}

static void stop_child_process(HANDLE process, HANDLE debug_pipe, BOOL debug)
{
    DWORD exit_code = 0;

    if (process == INVALID_HANDLE_VALUE || process == NULL) {
        return;
    }
    if (WaitForSingleObject(process, SQ_CMD_SHUTDOWN_MS) == WAIT_OBJECT_0) {
        return;
    }
    if (GetExitCodeProcess(process, &exit_code) != FALSE &&
        exit_code == STILL_ACTIVE) {
        debug_line(debug_pipe, debug, L"terminating child", 0, 0);
        (void)TerminateProcess(process, 1);
        (void)WaitForSingleObject(process, INFINITE);
    }
}

static BOOL start_cmd_process(const wchar_t *command_line, HANDLE in_read,
                              HANDLE out_write, PROCESS_INFORMATION *pi)
{
    STARTUPINFOW si;
    wchar_t mutable_command[SQ_CMD_LINE_MAX];

    if (command_line == NULL || pi == NULL) {
        return FALSE;
    }
    mutable_command[0] = L'\0';
    (void)append_wide(mutable_command, 0,
                      (int)(sizeof mutable_command / sizeof mutable_command[0]),
                      command_line);

    ZeroMemory(&si, sizeof si);
    ZeroMemory(pi, sizeof *pi);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read;
    si.hStdOutput = out_write;
    si.hStdError = out_write;

    return CreateProcessW(NULL, mutable_command, NULL, NULL, TRUE,
                          CREATE_NO_WINDOW, NULL, NULL, &si, pi);
}

static int run_one_shot(HANDLE output, int argc, wchar_t **argv)
{
    SECURITY_ATTRIBUTES sa;
    PROCESS_INFORMATION pi;
    HANDLE out_read = INVALID_HANDLE_VALUE;
    HANDLE out_write = INVALID_HANDLE_VALUE;
    wchar_t command_line[SQ_CMD_LINE_MAX];
    DWORD exit_code = 1;
    BOOL drained = FALSE;

    if (argc < 2) {
        (void)write_utf8(output, L"ERR usage: cmd <command...>");
        return 1;
    }
    if (build_command_line(argc, argv, command_line,
                           (int)(sizeof command_line / sizeof command_line[0])) <=
        0) {
        (void)write_utf8(output, L"ERR command line too long");
        return 1;
    }

    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    if (CreatePipe(&out_read, &out_write, &sa, 0) == FALSE) {
        (void)write_utf8(output, L"ERR CreatePipe failed");
        return 1;
    }
    (void)SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);

    if (start_cmd_process(command_line, GetStdHandle(STD_INPUT_HANDLE),
                          out_write, &pi) == FALSE) {
        (void)CloseHandle(out_read);
        (void)CloseHandle(out_write);
        (void)write_utf8(output, L"ERR CreateProcessW failed");
        return 1;
    }

    (void)CloseHandle(out_write);
    out_write = INVALID_HANDLE_VALUE;

    drained = drain_child_output(out_read, output, FALSE, FALSE,
                                 INVALID_HANDLE_VALUE);
    (void)WaitForSingleObject(pi.hProcess, INFINITE);
    (void)GetExitCodeProcess(pi.hProcess, &exit_code);

    (void)CloseHandle(pi.hThread);
    (void)CloseHandle(pi.hProcess);
    (void)CloseHandle(out_read);

    if (drained == FALSE) {
        return 1;
    }
    (void)write_exit(output, exit_code);
    return exit_code == 0 ? 0 : 1;
}

static BOOL create_child_stdin(HANDLE *in_read, HANDLE *in_write,
                               HANDLE output, BOOL debug)
{
    SECURITY_ATTRIBUTES sa;

    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    if (CreatePipe(in_read, in_write, &sa, 0) == FALSE) {
        debug_line(output, debug, L"stdin pipe failed", 0, GetLastError());
        (void)write_utf8(output, L"ERR stdin pipe failed");
        return FALSE;
    }
    debug_line(output, debug, L"stdin pipe created", 0, 0);
    (void)SetHandleInformation(*in_read, HANDLE_FLAG_INHERIT,
                               HANDLE_FLAG_INHERIT);
    (void)SetHandleInformation(*in_write, HANDLE_FLAG_INHERIT, 0);
    return TRUE;
}

static BOOL start_interactive_child(const wchar_t *command_line, HANDLE in_read,
                                    sq_cmd_pipe_pair *child_output,
                                    HANDLE output, BOOL debug,
                                    PROCESS_INFORMATION *pi)
{
    if (make_child_output_pipe(child_output, output, debug) == FALSE) {
        (void)write_utf8(output, L"ERR stdout pipe failed");
        return FALSE;
    }

    if (start_cmd_process(command_line, in_read, child_output->write, pi) ==
        FALSE) {
        debug_line(output, debug, L"create process failed", 0, GetLastError());
        close_pipe_pair(child_output);
        (void)write_utf8(output, L"ERR CreateProcessW failed");
        return FALSE;
    }
    debug_line(output, debug, L"process started", pi->dwProcessId, 0);
    return TRUE;
}

static BOOL start_output_pump(sq_cmd_pipe_pair *child_output,
                              PROCESS_INFORMATION *pi, HANDLE output,
                              BOOL debug, sq_cmd_pump *pump,
                              HANDLE *pump_thread)
{
    pump->out_read = child_output->read;
    pump->module_pipe = output;
    pump->process = pi->hProcess;
    pump->overlapped = TRUE;
    pump->debug = debug;
    *pump_thread = CreateThread(NULL, 0, pump_child_output, pump, 0, NULL);
    if (*pump_thread == NULL) {
        debug_line(output, debug, L"pump thread failed", 0, GetLastError());
        return FALSE;
    }
    debug_line(output, debug, L"pump thread started", 0, 0);
    return TRUE;
}

static void forward_operator_input(HANDLE input, HANDLE output, HANDLE in_write,
                                   HANDLE process, BOOL debug)
{
    BYTE buf[SQ_CMD_IO_BUF];
    DWORD got = 0;
    DWORD wrote = 0;
    DWORD exit_code = 0;

    for (;;) {
        if (ReadFile(input, buf, (DWORD)sizeof buf, &got, NULL) == FALSE) {
            debug_line(output, debug, L"module read failed", 0, GetLastError());
            return;
        }
        if (got == 0) {
            debug_line(output, debug, L"module zero read", 0, 0);
            return;
        }
        debug_line(output, debug, L"module input", got, 0);
        if (WriteFile(in_write, buf, got, &wrote, NULL) == FALSE ||
            wrote != got) {
            debug_line(output, debug, L"stdin write failed", wrote,
                       GetLastError());
            (void)wrote;
            return;
        }
        debug_line(output, debug, L"stdin write ok", wrote, 0);
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(process, &exit_code) != FALSE) {
            debug_line(output, debug, L"process exited after input", exit_code,
                       0);
        }
    }
}

static int run_interactive(HANDLE input, HANDLE output, BOOL debug)
{
    PROCESS_INFORMATION pi;
    HANDLE in_read = INVALID_HANDLE_VALUE;
    HANDLE in_write = INVALID_HANDLE_VALUE;
    sq_cmd_pipe_pair child_output;
    HANDLE pump_thread = INVALID_HANDLE_VALUE;
    sq_cmd_pump pump;
    wchar_t command_line[SQ_CMD_LINE_MAX];
    DWORD exit_code = 1;

    child_output.read = INVALID_HANDLE_VALUE;
    child_output.write = INVALID_HANDLE_VALUE;

    if (build_interactive_command_line(command_line,
                                       (int)(sizeof command_line /
                                             sizeof command_line[0])) == FALSE) {
        (void)write_utf8(output, L"ERR command line too long");
        return 1;
    }
    if (!create_child_stdin(&in_read, &in_write, output, debug)) {
        return 1;
    }
    if (!start_interactive_child(command_line, in_read, &child_output, output,
                                 debug, &pi)) {
        (void)CloseHandle(in_read);
        (void)CloseHandle(in_write);
        return 1;
    }

    (void)CloseHandle(in_read);
    in_read = INVALID_HANDLE_VALUE;
    (void)CloseHandle(child_output.write);
    child_output.write = INVALID_HANDLE_VALUE;

    (void)write_utf8(output, L"interactive cmd.exe started");
    debug_line(output, debug, L"startup marker sent", 0, 0);

    if (!start_output_pump(&child_output, &pi, output, debug, &pump,
                           &pump_thread)) {
        (void)CloseHandle(in_write);
        close_pipe_pair(&child_output);
        (void)CloseHandle(pi.hThread);
        stop_child_process(pi.hProcess, output, debug);
        (void)CloseHandle(pi.hProcess);
        return 1;
    }

    forward_operator_input(input, output, in_write, pi.hProcess, debug);

    (void)CloseHandle(in_write);
    in_write = INVALID_HANDLE_VALUE;
    stop_child_process(pi.hProcess, output, debug);
    (void)GetExitCodeProcess(pi.hProcess, &exit_code);
    debug_line(output, debug, L"process exit", exit_code, 0);
    (void)WaitForSingleObject(pump_thread, INFINITE);
    debug_line(output, debug, L"pump thread joined", 0, 0);

    (void)CloseHandle(pump_thread);
    close_pipe_pair(&child_output);
    (void)CloseHandle(pi.hThread);
    (void)CloseHandle(pi.hProcess);

    return exit_code == 0 ? 0 : 1;
}

int sq_cmd_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
    if (interactive_requested(argc, argv)) {
        return run_interactive(input, output, debug_requested(argc, argv));
    }
    (void)input;
    return run_one_shot(output, argc, argv);
}
