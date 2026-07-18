#include "runtime/channel.h"

#include "security/tls.h"

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
        sq_tls_session *tls;
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
                if (sq_tls_runtime_enabled())
                {
                        ch->tls = sq_tls_session_create(s);
                        if (ch->tls == NULL)
                        {
                                (void)HeapFree(GetProcessHeap(), 0, ch);
                                return NULL;
                        }
                }
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
        OVERLAPPED ov;
        DWORD got = 0;
        BOOL ok = FALSE;
        DWORD err = 0;

        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
                return -1;
        }
        ok = ReadFile(h, buf, cap, &got, &ov);
        if (ok == FALSE)
        {
                err = GetLastError();
                if (err == ERROR_IO_PENDING)
                {
                        ok = GetOverlappedResult(h, &ov, &got, TRUE);
                        err = ok ? 0 : GetLastError();
                }
        }
        (void)CloseHandle(ov.hEvent);
        if (ok == FALSE)
        {
                return (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF || err == ERROR_OPERATION_ABORTED) ? 0 : -1;
        }
        return (got == 0) ? 0 : (int)got;
}

static BOOL handle_write_some(HANDLE h, const BYTE *buf, UINT32 len, DWORD *put)
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
        ok = WriteFile(h, buf, len, put, &ov);
        if (ok == FALSE)
        {
                err = GetLastError();
                if (err == ERROR_IO_PENDING)
                {
                        ok = GetOverlappedResult(h, &ov, put, TRUE);
                        err = ok ? 0 : GetLastError();
                }
        }
        (void)CloseHandle(ov.hEvent);
        (void)err;
        return ok;
}

int sq_channel_read_some(sq_channel *ch, BYTE *buf, UINT32 cap)
{
        if (ch == NULL || buf == NULL || cap == 0)
        {
                return -1;
        }
        if (ch->kind == CHANNEL_SOCKET)
        {
                if (ch->tls != NULL)
                {
                        return sq_tls_session_read_some(ch->tls, buf, cap);
                }
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
                        if (ch->tls != NULL)
                        {
                                return sq_tls_session_write_all(ch->tls, buf + off, remaining);
                        }
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
                        if (handle_write_some(ch->handle, buf + off, remaining, &put) == FALSE)
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
                if (ch->tls != NULL)
                {
                        sq_tls_session_close(ch->tls);
                        ch->sock = INVALID_SOCKET;
                        return;
                }
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
        if (ch->tls != NULL)
        {
                sq_tls_session_free(ch->tls);
        }
        (void)HeapFree(GetProcessHeap(), 0, ch);
}
