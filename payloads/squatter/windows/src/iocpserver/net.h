/* net.h -- Winsock lifecycle and socket primitives.
 *
 * Every function reports failure through sq_status and logs the underlying
 * WSA/Win32 error at the failure site. SOCKET handles are raw because they are
 * passed straight to Winsock; INVALID_SOCKET is the only invalid sentinel and
 * is what every out-parameter is set to on failure.
 */
#ifndef SQ_NET_H
#define SQ_NET_H

#include "base/win.h"
#include "iocpserver/result.h"

/* Bundle of Winsock extension function pointers that must be resolved at
 * runtime via WSAIoctl rather than linked. Zero-initialize before loading. */
typedef struct sq_net_ext
{
        LPFN_ACCEPTEX accept_ex;
        LPFN_GETACCEPTEXSOCKADDRS get_accept_ex_sockaddrs;
} sq_net_ext;

/* Bring up Winsock 2.2. Idempotent at the WSAStartup level (ref-counted by the
 * OS), but pair each successful call with exactly one sq_net_cleanup(). */
sq_status sq_net_startup(void);
void sq_net_cleanup(void);

/* Create an overlapped (IOCP-capable) TCP socket in `family` (AF_INET or
 * AF_INET6). On success *out is a valid SOCKET; on failure it is INVALID_SOCKET. */
sq_status sq_net_tcp_socket(int family, SOCKET *out);

/* Resolve host/port and return a bound, listening, overlapped TCP socket.
 * `host` may be NULL for the wildcard address. `backlog` <= 0 means
 * SOMAXCONN. On success *out_listener is valid and *out_family holds the
 * address family that won, which the caller needs to size AcceptEx buffers. */
sq_status sq_net_listen(const wchar_t *host, const wchar_t *port, int backlog, SOCKET *out_listener, int *out_family);

/* Resolve the AcceptEx / GetAcceptExSockaddrs pointers against `s` (any valid
 * socket of the right provider). *out is fully populated on success. */
sq_status sq_net_load_ext(SOCKET s, sq_net_ext *out);

/* Close a socket if it is valid; tolerates INVALID_SOCKET. Logs but does not
 * surface a close failure (nothing actionable remains at that point). */
void sq_net_close(SOCKET s);

/* Format a connected/accepted peer's address as "ip:port" into buf. Always
 * NUL-terminates. Used only for logging, so it never fails the caller. */
void sq_net_peer_str(const struct sockaddr *addr, int addr_len, wchar_t *buf, size_t cap);

#endif /* SQ_NET_H */
