#include "modules/getfile.h"

#include "base/win.h"
#include "modules/file_xfer.h"
#include "runtime/module_wire.h"

int sq_getfile_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        HANDLE file = INVALID_HANDLE_VALUE;
        BYTE buf[SQ_XFER_MSG_MAX];
        LARGE_INTEGER size;
        wchar_t wheader[64];
        char header[64];
        DWORD got = 0;

        (void)input;
        if (argc < 2)
        {
                (void)sq_xfer_send_stat(output, "ERR usage: getfile <remote-path>");
                return 1;
        }
        file =
            CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
                (void)sq_xfer_send_stat(output, "ERR cannot open file");
                return 1;
        }

        size.QuadPart = 0;
        (void)GetFileSizeEx(file, &size);
        (void)wnsprintfW(wheader, (int)(sizeof wheader / sizeof wheader[0]), L"OK %I64u",
                         (unsigned long long)size.QuadPart);
        (void)WideCharToMultiByte(CP_UTF8, 0, wheader, -1, header, (int)sizeof header, NULL, NULL);
        if (sq_xfer_send_stat(output, header) == FALSE)
        {
                (void)CloseHandle(file);
                return 1;
        }

        /* Sip the file: one bounded chunk in memory at a time. */
        buf[0] = SQ_XFER_DATA;
        for (;;)
        {
                if (ReadFile(file, buf + 1, (DWORD)SQ_XFER_CHUNK, &got, NULL) == FALSE)
                {
                        (void)CloseHandle(file);
                        (void)sq_xfer_send_stat(output, "ERR read failed");
                        return 1;
                }
                if (got == 0)
                {
                        break; /* end of file */
                }
                if (!sq_module_write_data(output, buf, 1 + got))
                {
                        (void)CloseHandle(file);
                        return 1; /* peer went away */
                }
        }

        (void)CloseHandle(file);
        (void)sq_xfer_send_eof(output);
        return 0;
}
