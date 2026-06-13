/* main.c -- command-line entry point for the squatter IOCP server.
 *
 * Parses options, installs a console control handler so Ctrl-C triggers an
 * orderly shutdown, and runs the server until that shutdown completes.
 *
 * Pure Win32: no C runtime. Diagnostics go to the standard handles via
 * WriteFile, formatting through the shlwapi wnsprintf family. */
#include "iocpserver/echo.h"
#include "iocpserver/result.h"
#include "iocpserver/server.h"
#include "base/win.h"
#include "sqlog/sqlog.h"

/* Process exit codes (we avoid <stdlib.h>'s EXIT_* to stay CRT-free). */
#define SQ_EXIT_OK  0
#define SQ_EXIT_ERR 1

/* The console control handler runs on a thread the OS spins up and is given no
 * user pointer, so the running server is reached through this single global. It
 * is written once before the handler is installed and only read thereafter;
 * pointer-sized aligned access is atomic on every Windows architecture. */
static sq_server *volatile g_server = NULL;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT: {
        sq_server *s = g_server;
        if (s != NULL) {
            sq_server_stop(s);
        }
        return TRUE; /* handled; do not run the default terminator */
    }
    default:
        return FALSE;
    }
}

/* Write a (wide) NUL-terminated string to a standard handle as UTF-8. */
static void write_handle(DWORD std_handle, const wchar_t *text)
{
    HANDLE h = GetStdHandle(std_handle);
    char utf8[1024];
    int n = 0;
    DWORD wrote = 0;

    if (h == NULL || h == INVALID_HANDLE_VALUE || text == NULL) {
        return;
    }
    n = WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, (int)sizeof utf8, NULL,
                            NULL);
    if (n > 1) { /* n includes the NUL terminator */
        (void)WriteFile(h, utf8, (DWORD)(n - 1), &wrote, NULL);
    }
}

static void print_usage(const wchar_t *argv0)
{
    const wchar_t *name = (argv0 != NULL) ? argv0 : L"squatter";
    wchar_t buf[768];

    (void)wnsprintfW(buf, (int)(sizeof buf / sizeof buf[0]),
        L"usage: %s [options]\r\n"
        L"  -p, --port PORT        listen port (default 9000)\r\n"
        L"  -H, --host HOST        bind address (default: all interfaces)\r\n"
        L"  -w, --workers N        worker threads (default: 2 x CPUs)\r\n"
        L"  -a, --accepts N        outstanding accepts (default 16)\r\n"
        L"  -v, --verbose          enable debug logging\r\n"
        L"  -h, --help             show this help and exit\r\n",
        name);
    write_handle(STD_ERROR_HANDLE, buf);
}

/* Parse an unsigned decimal argument fully and in range, without the CRT.
 * Returns SQ_OK and sets *out only on a clean parse. */
static sq_status parse_uint(const wchar_t *s, unsigned max, unsigned *out)
{
    unsigned long v = 0;
    const wchar_t *p = NULL;

    if (s == NULL || *s == L'\0' || out == NULL) {
        return SQ_ERR_PARAM;
    }
    for (p = s; *p != L'\0'; p++) {
        unsigned digit = 0;
        if (*p < L'0' || *p > L'9') {
            return SQ_ERR_PARAM;
        }
        digit = (unsigned)(*p - L'0');
        if (v > (0xFFFFFFFFUL - digit) / 10UL) { /* would overflow 32 bits */
            return SQ_ERR_PARAM;
        }
        v = v * 10UL + digit;
    }
    if (v > (unsigned long)max) {
        return SQ_ERR_PARAM;
    }
    *out = (unsigned)v;
    return SQ_OK;
}

/* Match an option, supporting both "--opt value" and "-o value". Returns 1 and
 * advances *i past the value on a match; 0 on no match. On a match with a
 * missing value, *value is left NULL for the caller to reject. */
static int take_value(wchar_t **argv, int argc, int *i,
                      const wchar_t *shortopt, const wchar_t *longopt,
                      const wchar_t **value)
{
    const wchar_t *arg = argv[*i];

    if (lstrcmpW(arg, shortopt) != 0 && lstrcmpW(arg, longopt) != 0) {
        return 0;
    }
    if (*i + 1 >= argc) {
        write_handle(STD_ERROR_HANDLE, L"option requires a value\r\n");
        *value = NULL;
        return 1;
    }
    *i += 1;
    *value = argv[*i];
    return 1;
}

int wmain(int argc, wchar_t **argv); /* -municode entry */

int wmain(int argc, wchar_t **argv)
{
    sq_server_config cfg = {0};
    sq_server *server = NULL;
    sq_status st = SQ_OK;
    const wchar_t *port = L"9000";
    const wchar_t *host = NULL;
    int i = 0;

    cfg.backlog = 0;      /* SOMAXCONN */
    cfg.worker_count = 0; /* auto */
    cfg.accept_count = 0; /* default */

    /* Logging defaults to INFO and above; --verbose drops the floor to DEBUG. */
    sqlog_init();
    sqlog_set_level(SQLOG_LEVEL_INFO);

    for (i = 1; i < argc; i++) {
        const wchar_t *arg = argv[i];
        const wchar_t *value = NULL;

        if (lstrcmpW(arg, L"-h") == 0 || lstrcmpW(arg, L"--help") == 0) {
            print_usage(argv[0]);
            return SQ_EXIT_OK;
        }
        if (lstrcmpW(arg, L"-v") == 0 || lstrcmpW(arg, L"--verbose") == 0) {
            sqlog_set_level(SQLOG_LEVEL_DEBUG);
            continue;
        }
        if (take_value(argv, argc, &i, L"-p", L"--port", &value)) {
            if (value == NULL) { return SQ_EXIT_ERR; }
            port = value;
            continue;
        }
        if (take_value(argv, argc, &i, L"-H", L"--host", &value)) {
            if (value == NULL) { return SQ_EXIT_ERR; }
            host = value;
            continue;
        }
        if (take_value(argv, argc, &i, L"-w", L"--workers", &value)) {
            if (value == NULL ||
                parse_uint(value, 4096, &cfg.worker_count) != SQ_OK) {
                write_handle(STD_ERROR_HANDLE, L"invalid --workers value\r\n");
                return SQ_EXIT_ERR;
            }
            continue;
        }
        if (take_value(argv, argc, &i, L"-a", L"--accepts", &value)) {
            if (value == NULL ||
                parse_uint(value, 65536, &cfg.accept_count) != SQ_OK) {
                write_handle(STD_ERROR_HANDLE, L"invalid --accepts value\r\n");
                return SQ_EXIT_ERR;
            }
            continue;
        }
        write_handle(STD_ERROR_HANDLE, L"unknown option\r\n");
        print_usage(argv[0]);
        return SQ_EXIT_ERR;
    }

    cfg.host = host;
    cfg.port = port;
    cfg.handler = sq_echo_handler();

    if (SetConsoleCtrlHandler(console_ctrl_handler, TRUE) == FALSE) {
        SQLOG_WINERR(SQLOG_SUB_GENERAL, ERROR, (unsigned long)GetLastError(),
                     L"SetConsoleCtrlHandler failed");
        return SQ_EXIT_ERR;
    }

    st = sq_server_create(&cfg, &server);
    if (st != SQ_OK) {
        SQLOG_ERROR(SQLOG_SUB_GENERAL, L"server failed to start: %S",
                    sq_status_str(st));
        return SQ_EXIT_ERR;
    }
    g_server = server;

    SQLOG_INFO(SQLOG_SUB_GENERAL, L"press Ctrl-C to stop");
    st = sq_server_run(server);

    g_server = NULL;
    sq_server_destroy(server);
    (void)SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    sqlog_shutdown();

    return (st == SQ_OK) ? SQ_EXIT_OK : SQ_EXIT_ERR;
}
