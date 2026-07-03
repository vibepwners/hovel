#include "modules/process_io.h"

#include "runtime/module_wire.h"
#include "wire/control_codec.h"

enum
{
        SQ_PROCESS_IO_BUF = 4096,
        SQ_PROCESS_MSG_MAX = 256,
        SQ_PROCESS_DEFAULT_AUTO_INTERACTIVE_MS = 1000,
        SQ_PROCESS_DEFAULT_SHUTDOWN_MS = 5000
};

typedef struct sq_child_pipe
{
        HANDLE parent;
        HANDLE child;
} sq_child_pipe;

typedef struct sq_output_pump
{
        HANDLE read_pipe;
        HANDLE module_output;
        BOOL debug;
} sq_output_pump;

static LONG sq_process_pipe_counter;

static void close_handle_if_open(HANDLE *h)
{
        if (h != NULL && *h != INVALID_HANDLE_VALUE && *h != NULL)
        {
                (void)CloseHandle(*h);
                *h = INVALID_HANDLE_VALUE;
        }
}

static void close_child_pipe(sq_child_pipe *pipe)
{
        if (pipe == NULL)
        {
                return;
        }
        close_handle_if_open(&pipe->parent);
        close_handle_if_open(&pipe->child);
}

static BOOL wait_overlapped(HANDLE h, OVERLAPPED *ov, DWORD *transferred)
{
        if (WaitForSingleObject(ov->hEvent, INFINITE) != WAIT_OBJECT_0)
        {
                return FALSE;
        }
        return GetOverlappedResult(h, ov, transferred, FALSE);
}

static BOOL connect_pipe(HANDLE pipe)
{
        OVERLAPPED ov;
        BOOL ok = FALSE;
        DWORD transferred = 0;
        DWORD err = 0;

        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
                return FALSE;
        }
        ok = ConnectNamedPipe(pipe, &ov);
        if (!ok)
        {
                err = GetLastError();
                if (err == ERROR_PIPE_CONNECTED)
                {
                        ok = TRUE;
                }
                else if (err == ERROR_IO_PENDING)
                {
                        ok = wait_overlapped(pipe, &ov, &transferred);
                }
        }
        (void)CloseHandle(ov.hEvent);
        return ok;
}

static void write_control(HANDLE output, UINT32 kind, UINT32 code, const char *message)
{
        (void)sq_module_write_control(output, kind, code, message);
}

static void write_error(HANDLE output, DWORD code, const char *message)
{
        write_control(output, SQMUX_EVENT_ERROR, code, message);
}

static void debug_line(HANDLE output, BOOL enabled, const wchar_t *event, DWORD value, DWORD err)
{
        char text[SQ_PROCESS_MSG_MAX];
        wchar_t wide[SQ_PROCESS_MSG_MAX];
        int n = 0;

        if (!enabled || output == INVALID_HANDLE_VALUE || output == NULL || event == NULL)
        {
                return;
        }
        (void)wnsprintfW(wide, (int)(sizeof wide / sizeof wide[0]), L"%s value=%lu err=%lu", event,
                         (unsigned long)value, (unsigned long)err);
        n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, text, (int)sizeof text, NULL, NULL);
        if (n <= 0)
        {
                write_control(output, SQMUX_EVENT_DEBUG, err, "debug message encoding failed");
                return;
        }
        write_control(output, SQMUX_EVENT_DEBUG, err, text);
}

static void make_pipe_name(wchar_t *name, int cap, const wchar_t *role)
{
        DWORD seq = (DWORD)InterlockedIncrement(&sq_process_pipe_counter);

        (void)wnsprintfW(name, cap, L"\\\\.\\pipe\\sqproc-%lu-%lu-%s", (unsigned long)GetCurrentProcessId(),
                         (unsigned long)seq, role);
}

static BOOL open_child_end(const wchar_t *name, DWORD access, HANDLE *child)
{
        SECURITY_ATTRIBUTES sa;

        ZeroMemory(&sa, sizeof sa);
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        *child = CreateFileW(name, access, 0, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return *child != INVALID_HANDLE_VALUE;
}

static BOOL create_stdin_pipe(sq_child_pipe *pipe)
{
        wchar_t name[160];

        make_pipe_name(name, (int)(sizeof name / sizeof name[0]), L"in");
        pipe->parent = CreateNamedPipeW(name, PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT,
                                        1, (DWORD)SQ_PROCESS_IO_BUF, (DWORD)SQ_PROCESS_IO_BUF, 120u * 1000u, NULL);
        if (pipe->parent == INVALID_HANDLE_VALUE)
        {
                return FALSE;
        }
        if (!open_child_end(name, GENERIC_READ, &pipe->child) || !connect_pipe(pipe->parent))
        {
                close_child_pipe(pipe);
                return FALSE;
        }
        return TRUE;
}

static BOOL create_stdout_pipe(sq_child_pipe *pipe)
{
        wchar_t name[160];

        make_pipe_name(name, (int)(sizeof name / sizeof name[0]), L"out");
        pipe->parent = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1,
                                        (DWORD)SQ_PROCESS_IO_BUF, (DWORD)SQ_PROCESS_IO_BUF, 120u * 1000u, NULL);
        if (pipe->parent == INVALID_HANDLE_VALUE)
        {
                return FALSE;
        }
        if (!open_child_end(name, GENERIC_WRITE, &pipe->child) || !connect_pipe(pipe->parent))
        {
                close_child_pipe(pipe);
                return FALSE;
        }
        return TRUE;
}

static BOOL start_process(const wchar_t *command_line, HANDLE stdin_read, HANDLE stdout_write, PROCESS_INFORMATION *pi)
{
        STARTUPINFOW si;
        wchar_t mutable_command[8192];

        if (command_line == NULL || pi == NULL)
        {
                return FALSE;
        }
        mutable_command[0] = L'\0';
        (void)wnsprintfW(mutable_command, (int)(sizeof mutable_command / sizeof mutable_command[0]), L"%s",
                         command_line);
        ZeroMemory(&si, sizeof si);
        ZeroMemory(pi, sizeof *pi);
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdin_read;
        si.hStdOutput = stdout_write;
        si.hStdError = stdout_write;
        return CreateProcessW(NULL, mutable_command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, pi);
}

static BOOL read_child_output(HANDLE read_pipe, BYTE *buf, DWORD cap, DWORD *got)
{
        OVERLAPPED ov;
        BOOL ok = FALSE;
        DWORD err = 0;

        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
                return FALSE;
        }
        *got = 0;
        ok = ReadFile(read_pipe, buf, cap, got, &ov);
        if (!ok)
        {
                err = GetLastError();
                if (err == ERROR_IO_PENDING)
                {
                        ok = wait_overlapped(read_pipe, &ov, got);
                }
        }
        (void)CloseHandle(ov.hEvent);
        return ok;
}

static DWORD WINAPI output_pump_main(LPVOID param)
{
        sq_output_pump *pump = (sq_output_pump *)param;
        BYTE buf[SQ_PROCESS_IO_BUF];

        if (pump == NULL)
        {
                return 1;
        }
        for (;;)
        {
                DWORD got = 0;

                if (!read_child_output(pump->read_pipe, buf, (DWORD)sizeof buf, &got) || got == 0)
                {
                        return 0;
                }
                debug_line(pump->module_output, pump->debug, L"process output", got, 0);
                if (!sq_module_write_data(pump->module_output, buf, got))
                {
                        return 1;
                }
        }
}

static BOOL start_output_pump(HANDLE read_pipe, HANDLE output, BOOL debug, sq_output_pump *pump, HANDLE *thread)
{
        pump->read_pipe = read_pipe;
        pump->module_output = output;
        pump->debug = debug;
        *thread = CreateThread(NULL, 0, output_pump_main, pump, 0, NULL);
        if (*thread == NULL)
        {
                write_error(output, GetLastError(), "output pump failed");
                return FALSE;
        }
        return TRUE;
}

static BOOL start_module_read(HANDLE input, BYTE *buf, OVERLAPPED *ov, DWORD *got, BOOL *pending)
{
        DWORD err = 0;

        *got = 0;
        *pending = FALSE;
        (void)ResetEvent(ov->hEvent);
        if (ReadFile(input, buf, (DWORD)(SQ_MODULE_PACKET_HEADER_SIZE + SQ_MODULE_PACKET_MAX_PAYLOAD), got, ov) !=
            FALSE)
        {
                return TRUE;
        }
        err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
                *pending = TRUE;
                return TRUE;
        }
        return FALSE;
}

static BOOL wait_module_read(HANDLE input, HANDLE process, OVERLAPPED *ov, DWORD *got, BOOL *process_done)
{
        HANDLE waits[2];
        DWORD wait = 0;

        waits[0] = process;
        waits[1] = ov->hEvent;
        *process_done = FALSE;
        wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0)
        {
                *process_done = TRUE;
                (void)CancelIo(input);
                return TRUE;
        }
        if (wait != WAIT_OBJECT_0 + 1)
        {
                return FALSE;
        }
        return GetOverlappedResult(input, ov, got, FALSE);
}

static BOOL read_module_message(HANDLE input, HANDLE process, BYTE *buf, DWORD *got, BOOL *done)
{
        OVERLAPPED ov;
        BOOL pending = FALSE;
        BOOL process_done = FALSE;

        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
                return FALSE;
        }
        *done = FALSE;
        if (!start_module_read(input, buf, &ov, got, &pending))
        {
                *done = TRUE;
        }
        else if (pending && !wait_module_read(input, process, &ov, got, &process_done))
        {
                *done = TRUE;
        }
        (void)CloseHandle(ov.hEvent);
        if (*done || process_done || *got == 0)
        {
                *done = TRUE;
                return TRUE;
        }
        return TRUE;
}

static BOOL module_message_to_data(BYTE *buf, DWORD *got, BOOL *done)
{
        sq_module_packet packet;

        if (!sq_module_packet_decode(buf, *got, &packet))
        {
                return TRUE;
        }
        if (packet.kind == SQ_MODULE_PACKET_CONTROL && packet.control_kind == SQ_MODULE_CONTROL_CLOSE)
        {
                *done = TRUE;
                return TRUE;
        }
        if (packet.kind == SQ_MODULE_PACKET_DATA && packet.payload != buf)
        {
                MoveMemory(buf, packet.payload, (SIZE_T)packet.length);
                *got = packet.length;
        }
        return TRUE;
}

static BOOL next_module_data(HANDLE input, HANDLE process, BYTE *buf, DWORD *got, BOOL *done)
{
        if (!read_module_message(input, process, buf, got, done))
        {
                return FALSE;
        }
        if (*done)
        {
                return TRUE;
        }
        return module_message_to_data(buf, got, done);
}

static BOOL wait_child_stdin_write(HANDLE write_pipe, HANDLE process, OVERLAPPED *ov, DWORD *wrote)
{
        HANDLE waits[2];
        DWORD wait = 0;

        waits[0] = process;
        waits[1] = ov->hEvent;
        wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0)
        {
                (void)CancelIo(write_pipe);
                return FALSE;
        }
        if (wait != WAIT_OBJECT_0 + 1)
        {
                return FALSE;
        }
        return GetOverlappedResult(write_pipe, ov, wrote, FALSE);
}

static BOOL write_child_stdin(HANDLE write_pipe, HANDLE process, const BYTE *buf, DWORD len)
{
        OVERLAPPED ov;
        DWORD wrote = 0;
        DWORD err = 0;
        BOOL ok = FALSE;

        if (len == 0)
        {
                return TRUE;
        }
        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
                return FALSE;
        }
        ok = WriteFile(write_pipe, buf, len, &wrote, &ov);
        if (!ok)
        {
                err = GetLastError();
                if (err == ERROR_IO_PENDING)
                {
                        ok = wait_child_stdin_write(write_pipe, process, &ov, &wrote);
                }
        }
        (void)CloseHandle(ov.hEvent);
        return ok && wrote == len;
}

static BOOL forward_input(HANDLE input, HANDLE stdin_write, HANDLE process, HANDLE output, BOOL debug)
{
        BYTE buf[SQ_MODULE_PACKET_HEADER_SIZE + SQ_MODULE_PACKET_MAX_PAYLOAD];

        for (;;)
        {
                DWORD got = 0;
                BOOL done = FALSE;

                if (!next_module_data(input, process, buf, &got, &done))
                {
                        debug_line(output, debug, L"module input failed", 0, GetLastError());
                        return FALSE;
                }
                if (done)
                {
                        return TRUE;
                }
                if (!write_child_stdin(stdin_write, process, buf, got))
                {
                        debug_line(output, debug, L"stdin write failed", got, GetLastError());
                        return FALSE;
                }
                debug_line(output, debug, L"stdin data", got, 0);
        }
}

static DWORD auto_interactive_ms(const sq_process_spec *spec)
{
        return spec->auto_interactive_ms != 0 ? spec->auto_interactive_ms
                                              : (DWORD)SQ_PROCESS_DEFAULT_AUTO_INTERACTIVE_MS;
}

static DWORD shutdown_ms(const sq_process_spec *spec)
{
        return spec->shutdown_ms != 0 ? spec->shutdown_ms : (DWORD)SQ_PROCESS_DEFAULT_SHUTDOWN_MS;
}

static int finish_process(PROCESS_INFORMATION *pi, HANDLE output, BOOL debug)
{
        DWORD exit_code = 1;

        (void)WaitForSingleObject(pi->hProcess, INFINITE);
        (void)GetExitCodeProcess(pi->hProcess, &exit_code);
        debug_line(output, debug, L"process exit", exit_code, 0);
        return (int)exit_code;
}

static void stop_process(PROCESS_INFORMATION *pi, DWORD timeout_ms, HANDLE output, BOOL debug)
{
        DWORD exit_code = 0;

        if (WaitForSingleObject(pi->hProcess, timeout_ms) == WAIT_OBJECT_0)
        {
                return;
        }
        if (GetExitCodeProcess(pi->hProcess, &exit_code) != FALSE && exit_code == STILL_ACTIVE)
        {
                debug_line(output, debug, L"terminating child", 0, 0);
                (void)TerminateProcess(pi->hProcess, 1);
        }
}

static void close_process_handles(PROCESS_INFORMATION *pi)
{
        close_handle_if_open(&pi->hThread);
        close_handle_if_open(&pi->hProcess);
}

static void wait_output_pump(HANDLE *thread)
{
        if (thread != NULL && *thread != INVALID_HANDLE_VALUE && *thread != NULL)
        {
                (void)WaitForSingleObject(*thread, INFINITE);
                (void)CloseHandle(*thread);
                *thread = INVALID_HANDLE_VALUE;
        }
}

static BOOL setup_child_pipes(sq_child_pipe *stdin_pipe, sq_child_pipe *stdout_pipe, HANDLE output, BOOL debug)
{
        if (!create_stdin_pipe(stdin_pipe))
        {
                debug_line(output, debug, L"stdin pipe failed", 0, GetLastError());
                write_error(output, GetLastError(), "stdin pipe failed");
                return FALSE;
        }
        if (!create_stdout_pipe(stdout_pipe))
        {
                debug_line(output, debug, L"stdout pipe failed", 0, GetLastError());
                write_error(output, GetLastError(), "stdout pipe failed");
                close_child_pipe(stdin_pipe);
                return FALSE;
        }
        return TRUE;
}

static BOOL setup_process(const sq_process_spec *spec, sq_child_pipe *stdin_pipe, sq_child_pipe *stdout_pipe,
                          PROCESS_INFORMATION *pi)
{
        if (!setup_child_pipes(stdin_pipe, stdout_pipe, spec->module_output, spec->debug))
        {
                return FALSE;
        }
        if (!start_process(spec->command_line, stdin_pipe->child, stdout_pipe->child, pi))
        {
                debug_line(spec->module_output, spec->debug, L"create process failed", 0, GetLastError());
                write_error(spec->module_output, GetLastError(), "CreateProcessW failed");
                close_child_pipe(stdin_pipe);
                close_child_pipe(stdout_pipe);
                return FALSE;
        }
        debug_line(spec->module_output, spec->debug, L"process started", pi->dwProcessId, 0);
        close_handle_if_open(&stdin_pipe->child);
        close_handle_if_open(&stdout_pipe->child);
        return TRUE;
}

static int finish_run(PROCESS_INFORMATION *pi, sq_child_pipe *stdin_pipe, sq_child_pipe *stdout_pipe,
                      HANDLE *pump_thread, const sq_process_spec *spec)
{
        int exit_code = 1;

        close_handle_if_open(&stdin_pipe->parent);
        exit_code = finish_process(pi, spec->module_output, spec->debug);
        wait_output_pump(pump_thread);
        close_child_pipe(stdout_pipe);
        close_process_handles(pi);
        write_control(spec->module_output, SQMUX_EVENT_EXITED, (UINT32)exit_code, NULL);
        return exit_code;
}

int sq_process_run(const sq_process_spec *spec)
{
        PROCESS_INFORMATION pi;
        sq_child_pipe stdin_pipe = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
        sq_child_pipe stdout_pipe = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
        sq_output_pump pump;
        HANDLE pump_thread = INVALID_HANDLE_VALUE;

        if (spec == NULL || spec->command_line == NULL)
        {
                return 1;
        }
        ZeroMemory(&pi, sizeof pi);
        ZeroMemory(&pump, sizeof pump);
        if (!setup_process(spec, &stdin_pipe, &stdout_pipe, &pi))
        {
                return 1;
        }
        if (!start_output_pump(stdout_pipe.parent, spec->module_output, spec->debug, &pump, &pump_thread))
        {
                stop_process(&pi, shutdown_ms(spec), spec->module_output, spec->debug);
                close_child_pipe(&stdin_pipe);
                close_child_pipe(&stdout_pipe);
                close_process_handles(&pi);
                return 1;
        }
        if (!spec->interactive && WaitForSingleObject(pi.hProcess, auto_interactive_ms(spec)) == WAIT_OBJECT_0)
        {
                return finish_run(&pi, &stdin_pipe, &stdout_pipe, &pump_thread, spec);
        }
        write_control(spec->module_output, SQMUX_EVENT_INTERACTIVE, 1, NULL);
        (void)forward_input(spec->module_input, stdin_pipe.parent, pi.hProcess, spec->module_output, spec->debug);
        close_handle_if_open(&stdin_pipe.parent);
        stop_process(&pi, shutdown_ms(spec), spec->module_output, spec->debug);
        return finish_run(&pi, &stdin_pipe, &stdout_pipe, &pump_thread, spec);
}
