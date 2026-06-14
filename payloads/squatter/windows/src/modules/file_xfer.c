#include "modules/file_xfer.h"

/* Wire bytes are UTF-8; a status line is built by the (wide) caller and handed
 * here already encoded. A plain byte count (not lstrlenA) keeps this off the
 * ANSI WinAPI. */
static int byte_len(const char *s)
{
        int n = 0;

        if (s != NULL)
        {
                while (s[n] != '\0')
                {
                        n++;
                }
        }
        return n;
}

BOOL sq_xfer_send_stat(HANDLE pipe, const char *text)
{
        BYTE buf[256];
        int n = byte_len(text);
        DWORD wrote = 0;

        if (n > (int)sizeof buf - 1)
        {
                n = (int)sizeof buf - 1;
        }
        buf[0] = SQ_XFER_STAT;
        if (n > 0)
        {
                CopyMemory(buf + 1, text, (SIZE_T)n);
        }
        return WriteFile(pipe, buf, (DWORD)(1 + n), &wrote, NULL) != FALSE && wrote == (DWORD)(1 + n);
}

BOOL sq_xfer_send_eof(HANDLE pipe)
{
        BYTE tag = SQ_XFER_EOF;
        DWORD wrote = 0;

        return WriteFile(pipe, &tag, 1, &wrote, NULL) != FALSE && wrote == 1;
}
