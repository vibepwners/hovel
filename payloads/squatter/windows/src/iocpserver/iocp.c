#include "iocpserver/iocp.h"

#include "sqlog/sqlog.h"

sq_status sq_iocp_create(DWORD concurrency, HANDLE *out)
{
        HANDLE port = NULL;

        if (out == NULL)
        {
                return SQ_ERR_PARAM;
        }
        *out = NULL;

        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, concurrency);
        if (port == NULL)
        {
                SQLOG_WINERR(SQLOG_SUB_IOCP, ERROR, (unsigned long)GetLastError(),
                             L"CreateIoCompletionPort(create) failed");
                return SQ_ERR_SYSTEM;
        }
        *out = port;
        return SQ_OK;
}

sq_status sq_iocp_associate(HANDLE port, HANDLE device, ULONG_PTR key)
{
        HANDLE result = NULL;

        if (port == NULL || port == INVALID_HANDLE_VALUE || device == NULL || device == INVALID_HANDLE_VALUE)
        {
                return SQ_ERR_PARAM;
        }

        /* On association the call returns the same port handle; NULL is failure. */
        result = CreateIoCompletionPort(device, port, key, 0);
        if (result == NULL)
        {
                SQLOG_WINERR(SQLOG_SUB_IOCP, ERROR, (unsigned long)GetLastError(),
                             L"CreateIoCompletionPort(associate) failed");
                return SQ_ERR_SYSTEM;
        }
        return SQ_OK;
}

sq_status sq_iocp_post(HANDLE port, DWORD bytes, ULONG_PTR key, OVERLAPPED *overlapped)
{
        if (port == NULL || port == INVALID_HANDLE_VALUE)
        {
                return SQ_ERR_PARAM;
        }
        if (PostQueuedCompletionStatus(port, bytes, key, overlapped) == FALSE)
        {
                SQLOG_WINERR(SQLOG_SUB_IOCP, ERROR, (unsigned long)GetLastError(),
                             L"PostQueuedCompletionStatus failed");
                return SQ_ERR_SYSTEM;
        }
        return SQ_OK;
}

sq_status sq_iocp_wait(HANDLE port, DWORD timeout_ms, sq_iocp_event *out)
{
        BOOL ok = FALSE;
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED *ov = NULL;
        DWORD err = 0;

        if (out == NULL)
        {
                return SQ_ERR_PARAM;
        }
        ZeroMemory(out, sizeof *out);
        if (port == NULL || port == INVALID_HANDLE_VALUE)
        {
                return SQ_ERR_PARAM;
        }

        ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov, timeout_ms);
        if (ok != FALSE)
        {
                out->outcome = SQ_IOCP_COMPLETION;
                out->overlapped = ov;
                out->key = key;
                out->bytes = bytes;
                out->op_failed = 0;
                return SQ_OK;
        }

        err = GetLastError();
        if (ov != NULL)
        {
                /* A real operation completed but failed. The caller still owns `ov`
                 * (its OVERLAPPED lives in a connection object) and must free it. */
                out->outcome = SQ_IOCP_COMPLETION;
                out->overlapped = ov;
                out->key = key;
                out->bytes = bytes;
                out->op_failed = 1;
                out->op_error = err;
                return SQ_OK;
        }
        if (err == WAIT_TIMEOUT)
        {
                out->outcome = SQ_IOCP_TIMEOUT;
                return SQ_OK;
        }

        /* ov == NULL and not a timeout: the port has been closed underneath us
         * (ERROR_ABANDONED_WAIT_0) or another unrecoverable port error. */
        out->outcome = SQ_IOCP_CLOSED;
        out->op_error = err;
        return SQ_OK;
}

void sq_iocp_close(HANDLE port)
{
        if (port == NULL || port == INVALID_HANDLE_VALUE)
        {
                return;
        }
        if (CloseHandle(port) == FALSE)
        {
                SQLOG_WINERR(SQLOG_SUB_IOCP, ERROR, (unsigned long)GetLastError(), L"CloseHandle(iocp) failed");
        }
}
