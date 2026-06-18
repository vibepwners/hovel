#include "modules/putfile.h"

#include "base/win.h"
#include "modules/file_xfer.h"
#include "runtime/module_wire.h"

static BOOL write_file_chunk(HANDLE file, const BYTE *buf, DWORD got, unsigned long long *total)
{
        DWORD wrote = 0;

        if (got <= 1)
        {
                return TRUE;
        }
        if (WriteFile(file, buf + 1, got - 1, &wrote, NULL) == FALSE || wrote != got - 1)
        {
                return FALSE;
        }
        *total += (unsigned long long)(got - 1);
        return TRUE;
}

static BOOL send_putfile_ack(HANDLE output, unsigned long long total)
{
        wchar_t wack[64];
        char ack[64];

        (void)wnsprintfW(wack, (int)(sizeof wack / sizeof wack[0]), L"OK %I64u", total);
        (void)WideCharToMultiByte(CP_UTF8, 0, wack, -1, ack, (int)sizeof ack, NULL, NULL);
        return sq_xfer_send_stat(output, ack);
}

static int handle_putfile_message(HANDLE file, HANDLE output, const BYTE *buf, DWORD got, unsigned long long *total)
{
        if (buf[0] == SQ_XFER_DATA)
        {
                if (!write_file_chunk(file, buf, got, total))
                {
                        (void)sq_xfer_send_stat(output, "ERR write failed");
                        return 1;
                }
                return 0;
        }
        if (buf[0] == SQ_XFER_EOF)
        {
                (void)CloseHandle(file);
                return send_putfile_ack(output, *total) ? 2 : 1;
        }
        return 0;
}

int sq_putfile_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        HANDLE file = INVALID_HANDLE_VALUE;
        BYTE buf[SQ_XFER_MSG_MAX];
        unsigned long long total = 0;
        DWORD got = 0;

        if (argc < 2)
        {
                (void)sq_xfer_send_stat(output, "ERR usage: putfile <remote-path>");
                return 1;
        }
        file = CreateFileW(argv[1], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
                (void)sq_xfer_send_stat(output, "ERR cannot create file");
                return 1;
        }
        if (sq_xfer_send_stat(output, "OK") == FALSE)
        {
                (void)CloseHandle(file);
                return 1;
        }

        for (;;)
        {
                if (!sq_module_read_data(input, buf, (DWORD)sizeof buf, &got))
                {
                        break; /* peer closed the stream before EOF: treat as aborted */
                }
                if (got == 0)
                {
                        break;
                }
                {
                        int action = handle_putfile_message(file, output, buf, got, &total);
                        if (action == 1)
                        {
                                (void)CloseHandle(file);
                                return 1;
                        }
                        if (action == 2)
                        {
                                return 0;
                        }
                }
        }

        if (file != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(file);
        }
        return 1; /* aborted */
}
