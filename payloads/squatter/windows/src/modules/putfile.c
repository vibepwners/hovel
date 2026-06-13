#include "modules/putfile.h"

#include "modules/file_xfer.h"
#include "base/win.h"

int sq_putfile_module_main(HANDLE pipe, int argc, wchar_t **argv)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE buf[SQ_XFER_MSG_MAX];
    unsigned long long total = 0;
    wchar_t wack[64];
    char ack[64];
    DWORD got = 0;
    DWORD wrote = 0;

    if (argc < 2) {
        (void)sq_xfer_send_stat(pipe, "ERR usage: putfile <remote-path>");
        return 1;
    }
    file = CreateFileW(argv[1], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        (void)sq_xfer_send_stat(pipe, "ERR cannot create file");
        return 1;
    }
    if (sq_xfer_send_stat(pipe, "OK") == FALSE) {
        (void)CloseHandle(file);
        return 1;
    }

    for (;;) {
        if (ReadFile(pipe, buf, (DWORD)sizeof buf, &got, NULL) == FALSE) {
            break; /* peer closed the stream before EOF: treat as aborted */
        }
        if (got == 0) {
            break;
        }
        if (buf[0] == SQ_XFER_DATA) {
            if (got > 1) {
                if (WriteFile(file, buf + 1, got - 1, &wrote, NULL) == FALSE) {
                    (void)sq_xfer_send_stat(pipe, "ERR write failed");
                    (void)CloseHandle(file);
                    return 1;
                }
                total += (unsigned long long)(got - 1);
            }
        } else if (buf[0] == SQ_XFER_EOF) {
            (void)CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
            (void)wnsprintfW(wack, (int)(sizeof wack / sizeof wack[0]),
                             L"OK %I64u", total);
            (void)WideCharToMultiByte(CP_UTF8, 0, wack, -1, ack,
                                      (int)sizeof ack, NULL, NULL);
            (void)sq_xfer_send_stat(pipe, ack);
            return 0;
        }
        /* unknown tag: ignore */
    }

    if (file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(file);
    }
    return 1; /* aborted */
}
