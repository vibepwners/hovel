#include "modules/echo.h"

#include "base/win.h"

enum {
    SQ_ECHO_ARGV_MSG_MAX = 4096,
    SQ_ECHO_IO_BUF = 65536
};

/* Build "argc=<N> <argv0> <argv1> ..." in wide, then encode it to UTF-8 bytes
 * for the wire. Returns the UTF-8 byte length. */
static int format_argv(int argc, wchar_t **argv, char *msg, int cap)
{
    wchar_t wbuf[SQ_ECHO_ARGV_MSG_MAX];
    int pos = 0;
    int i = 0;

    pos = wnsprintfW(wbuf, (int)(sizeof wbuf / sizeof wbuf[0]), L"argc=%d", argc);
    if (pos < 0) {
        return 0;
    }
    for (i = 0; i < argc; i++) {
        int remaining = (int)(sizeof wbuf / sizeof wbuf[0]) - pos;
        if (remaining <= 1) {
            break;
        }
        pos += wnsprintfW(wbuf + pos, remaining, L" %s",
                          (argv[i] != NULL) ? argv[i] : L"");
    }
    return WideCharToMultiByte(CP_UTF8, 0, wbuf, pos, msg, cap, NULL, NULL);
}

static BOOL is_end(const BYTE *buf, DWORD n)
{
    return (n == 3 && buf[0] == 'E' && buf[1] == 'N' && buf[2] == 'D');
}

int sq_echo_module_main(HANDLE pipe, int argc, wchar_t **argv)
{
    char argv_msg[SQ_ECHO_ARGV_MSG_MAX];
    int argv_len = 0;
    DWORD wrote = 0;

    /* 1. Echo argc/argv back as one message. */
    argv_len = format_argv(argc, argv, argv_msg, (int)sizeof argv_msg);
    if (argv_len > 0) {
        if (WriteFile(pipe, argv_msg, (DWORD)argv_len, &wrote, NULL) == FALSE) {
            return 1;
        }
    }

    /* 2. Echo each message until "END". */
    for (;;) {
        BYTE buf[SQ_ECHO_IO_BUF];
        DWORD n = 0;

        if (ReadFile(pipe, buf, (DWORD)sizeof buf, &n, NULL) == FALSE) {
            break; /* pipe closed by the runtime (peer CLOSE) */
        }
        if (n == 0) {
            break;
        }
        if (is_end(buf, n)) {
            break; /* 3. graceful close */
        }
        if (WriteFile(pipe, buf, n, &wrote, NULL) == FALSE) {
            break;
        }
    }
    return 0;
}
