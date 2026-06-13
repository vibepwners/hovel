/* iocp.h -- a thin, correct wrapper over an I/O completion port.
 *
 * The value of this module is that it makes the four-way result of
 * GetQueuedCompletionStatus explicit. That call overloads its BOOL return and
 * lpOverlapped out-param to encode four distinct situations, and conflating any
 * two of them is a classic IOCP bug:
 *
 *   return TRUE                  -> a packet dequeued; the operation succeeded
 *   return FALSE, *ov != NULL    -> a packet dequeued; the operation FAILED
 *   return FALSE, *ov == NULL,
 *       err == WAIT_TIMEOUT      -> nothing ready within the timeout
 *   return FALSE, *ov == NULL,
 *       err != WAIT_TIMEOUT      -> the port is gone (closed/abandoned)
 *
 * sq_iocp_wait collapses these into a tagged sq_iocp_event so callers branch on
 * an enum instead of re-deriving the truth table at every call site.
 */
#ifndef SQ_IOCP_H
#define SQ_IOCP_H

#include "iocpserver/result.h"
#include "base/win.h"

typedef enum sq_iocp_outcome {
    SQ_IOCP_COMPLETION = 0, /* a packet was dequeued (see op_failed)        */
    SQ_IOCP_TIMEOUT,        /* no packet within the timeout                 */
    SQ_IOCP_CLOSED          /* the port was closed; stop the worker         */
} sq_iocp_outcome;

typedef struct sq_iocp_event {
    sq_iocp_outcome outcome;
    OVERLAPPED *overlapped; /* the op's OVERLAPPED (valid iff COMPLETION)   */
    ULONG_PTR   key;        /* the completion key set at association time   */
    DWORD       bytes;      /* bytes transferred (valid iff COMPLETION)     */
    int         op_failed;  /* nonzero if the dequeued op itself failed     */
    DWORD       op_error;   /* the op's error (valid iff op_failed)         */
} sq_iocp_event;

/* Create a completion port. `concurrency` is the max number of threads the
 * kernel lets run packets concurrently; 0 means "one per processor". */
sq_status sq_iocp_create(DWORD concurrency, HANDLE *out);

/* Associate a socket/handle with the port under `key`. An IOCP association is
 * permanent for the life of the handle; there is no dissociate. */
sq_status sq_iocp_associate(HANDLE port, HANDLE device, ULONG_PTR key);

/* Hand-post a packet, e.g. a wake-up for shutdown. */
sq_status sq_iocp_post(HANDLE port, DWORD bytes, ULONG_PTR key,
                       OVERLAPPED *overlapped);

/* Dequeue one packet (or time out). Never returns a raw failure for the normal
 * I/O-failed case: that is reported as outcome==COMPLETION with op_failed set,
 * because the caller still owns the OVERLAPPED and must clean it up. */
sq_status sq_iocp_wait(HANDLE port, DWORD timeout_ms, sq_iocp_event *out);

/* Close the port handle; tolerates NULL/INVALID_HANDLE_VALUE. */
void sq_iocp_close(HANDLE port);

#endif /* SQ_IOCP_H */
