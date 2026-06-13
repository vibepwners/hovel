/* result.h -- a single, total status type for the whole codebase.
 *
 * Rationale: every fallible function returns `sq_status`. There is exactly one
 * success value (SQ_OK == 0) so the canonical check is `if (st != SQ_OK)`.
 * Win32/Winsock error numbers are *not* smuggled through this enum; when a
 * call fails, the originating GetLastError()/WSAGetLastError() value is logged
 * at the failure site (see SQLOG_WINERR) and an sq_status category is returned.
 * Callers branch on the category; the operator reads the system error in the
 * log. This keeps the type small and total while preserving the OS detail.
 *
 * This header has no dependencies and pulls in nothing; include it anywhere.
 */
#ifndef SQ_RESULT_H
#define SQ_RESULT_H

typedef enum sq_status {
    SQ_OK = 0,          /* operation succeeded                                 */
    SQ_ERR_PARAM,       /* a precondition on an argument was violated          */
    SQ_ERR_NOMEM,       /* allocation failed                                   */
    SQ_ERR_SYSTEM,      /* an OS/Winsock primitive failed (detail in the log)  */
    SQ_ERR_ADDRESS,     /* an address/port string could not be parsed          */
    SQ_ERR_STATE        /* the object was used outside its valid lifecycle     */
} sq_status;

/* Human-readable name for a status, for logging. Never returns NULL and never
 * fails: an out-of-range value yields the literal "SQ_ERR_<unknown>". */
const char *sq_status_str(sq_status status);

#endif /* SQ_RESULT_H */
