#include "runtime/channel.h"

typedef enum channel_kind
{
        CHANNEL_SOCKET = 0,
        CHANNEL_HANDLE
} channel_kind;

struct sq_channel
{
        channel_kind kind;
        SOCKET sock;
        HANDLE handle;
};

static sq_channel *channel_alloc(void)
{
        sq_channel *ch = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *ch);
        if (ch != NULL)
        {
                ch->sock = INVALID_SOCKET;
                ch->handle = INVALID_HANDLE_VALUE;
        }
        return ch;
}

sq_channel *sq_channel_from_socket(SOCKET s)
{
        sq_channel *ch = channel_alloc();
        if (ch != NULL)
        {
                ch->kind = CHANNEL_SOCKET;
                ch->sock = s;
        }
        return ch;
}

sq_channel *sq_channel_from_handle(HANDLE h)
{
        sq_channel *ch = channel_alloc();
        if (ch != NULL)
        {
                ch->kind = CHANNEL_HANDLE;
                ch->handle = h;
        }
        return ch;
}

static int socket_read_some(SOCKET s, BYTE *buf, UINT32 cap)
{
        int n = recv(s, (char *)buf, (int)cap, 0);

        if (n > 0)
        {
                return n;
        }
        return (n == 0) ? 0 : -1;
}

static int handle_read_some(HANDLE h, BYTE *buf, UINT32 cap)
{
        DWORD got = 0;

        if (ReadFile(h, buf, cap, &got, NULL) == FALSE)
        {
                DWORD const err = GetLastError();
                return (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) ? 0 : -1;
        }
        return (got == 0) ? 0 : (int)got;
}

int sq_channel_read_some(sq_channel *ch, BYTE *buf, UINT32 cap)
{
        if (ch == NULL || buf == NULL || cap == 0)
        {
                return -1;
        }
        if (ch->kind == CHANNEL_SOCKET)
        {
                return socket_read_some(ch->sock, buf, cap);
        }
        return handle_read_some(ch->handle, buf, cap);
}

BOOL sq_channel_write_all(sq_channel *ch, const BYTE *buf, UINT32 len)
{
        UINT32 off = 0;

        if (ch == NULL || (buf == NULL && len != 0))
        {
                return FALSE;
        }
        while (off < len)
        {
                UINT32 remaining = len - off;
                if (ch->kind == CHANNEL_SOCKET)
                {
                        int n = send(ch->sock, (const char *)(buf + off), (int)remaining, 0);
                        if (n <= 0)
                        {
                                return FALSE;
                        }
                        off += (UINT32)n;
                }
                else
                {
                        DWORD put = 0;
                        if (WriteFile(ch->handle, buf + off, remaining, &put, NULL) == FALSE)
                        {
                                return FALSE;
                        }
                        if (put == 0)
                        {
                                return FALSE;
                        }
                        off += put;
                }
        }
        return TRUE;
}

void sq_channel_close(sq_channel *ch)
{
        if (ch == NULL)
        {
                return;
        }
        if (ch->kind == CHANNEL_SOCKET)
        {
                if (ch->sock != INVALID_SOCKET)
                {
                        (void)shutdown(ch->sock, SD_BOTH);
                        (void)closesocket(ch->sock);
                        ch->sock = INVALID_SOCKET;
                }
        }
        else
        {
                if (ch->handle != INVALID_HANDLE_VALUE && ch->handle != NULL)
                {
                        (void)CloseHandle(ch->handle);
                        ch->handle = INVALID_HANDLE_VALUE;
                }
        }
}

void sq_channel_free(sq_channel *ch)
{
        if (ch == NULL)
        {
                return;
        }
        sq_channel_close(ch);
        (void)HeapFree(GetProcessHeap(), 0, ch);
}
