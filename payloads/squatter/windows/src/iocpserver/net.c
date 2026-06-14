#include "iocpserver/net.h"

#include "sqlog/sqlog.h"

sq_status sq_net_startup(void)
{
    WSADATA wsa = {0};
    int const rc = WSAStartup(MAKEWORD(2, 2), &wsa);

    if (rc != 0) {
        /* WSAStartup returns the error directly and does not set the per-thread
         * error, so log `rc`, not WSAGetLastError(). */
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)rc,
                     L"WSAStartup(2.2) failed");
        return SQ_ERR_SYSTEM;
    }
    if (LOBYTE(wsa.wVersion) != 2 || HIBYTE(wsa.wVersion) != 2) {
        SQLOG_ERROR(SQLOG_SUB_NET, L"Winsock 2.2 unavailable (got %u.%u)",
                     (unsigned)LOBYTE(wsa.wVersion),
                     (unsigned)HIBYTE(wsa.wVersion));
        (void)WSACleanup();
        return SQ_ERR_SYSTEM;
    }
    return SQ_OK;
}

void sq_net_cleanup(void)
{
    if (WSACleanup() != 0) {
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                     L"WSACleanup failed");
    }
}

sq_status sq_net_tcp_socket(int family, SOCKET *out)
{
    SOCKET s = INVALID_SOCKET;

    if (out == NULL) {
        return SQ_ERR_PARAM;
    }
    *out = INVALID_SOCKET;

    s = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                   WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                   L"WSASocketW(family=%d) failed", family);
        return SQ_ERR_SYSTEM;
    }
    *out = s;
    return SQ_OK;
}

void sq_net_close(SOCKET s)
{
    if (s == INVALID_SOCKET) {
        return;
    }
    if (closesocket(s) != 0) {
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                   L"closesocket(%I64u) failed", (ULONG64)s);
    }
}

static void init_addr_hints(ADDRINFOW *hints)
{
    ZeroMemory(hints, sizeof *hints);
    hints->ai_family = AF_UNSPEC;
    hints->ai_socktype = SOCK_STREAM;
    hints->ai_protocol = IPPROTO_TCP;
    hints->ai_flags = AI_PASSIVE;
}

static BOOL listen_candidate(ADDRINFOW *addr, int backlog, SOCKET *listener)
{
    DWORD const on = 1;

    if (sq_net_tcp_socket(addr->ai_family, listener) != SQ_OK) {
        return FALSE;
    }
    if (setsockopt(*listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
                   (int)sizeof on) != 0) {
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                     L"setsockopt(SO_REUSEADDR) failed");
        sq_net_close(*listener);
        *listener = INVALID_SOCKET;
        return FALSE;
    }
    if (bind(*listener, addr->ai_addr, (int)addr->ai_addrlen) == 0 &&
        listen(*listener, backlog) == 0) {
        return TRUE;
    }
    SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                 L"bind/listen on candidate failed");
    sq_net_close(*listener);
    *listener = INVALID_SOCKET;
    return FALSE;
}

static sq_status resolve_listen_addresses(const wchar_t *host,
                                          const wchar_t *port,
                                          ADDRINFOW **resolved)
{
    ADDRINFOW hints = {0};
    int gai = 0;

    init_addr_hints(&hints);
    gai = GetAddrInfoW(host, port, &hints, resolved);
    if (gai == 0) {
        return SQ_OK;
    }
    SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)gai,
                 L"getaddrinfo(%s:%s) failed", (host != NULL) ? host : L"*",
                 port);
    return SQ_ERR_ADDRESS;
}

static BOOL choose_listener(ADDRINFOW *resolved, int backlog,
                            SOCKET *out_listener, int *out_family)
{
    ADDRINFOW *cur = NULL;
    SOCKET listener = INVALID_SOCKET;

    for (cur = resolved; cur != NULL; cur = cur->ai_next) {
        if (listen_candidate(cur, backlog, &listener)) {
            *out_listener = listener;
            *out_family = cur->ai_family;
            return TRUE;
        }
    }
    return FALSE;
}

sq_status sq_net_listen(const wchar_t *host, const wchar_t *port, int backlog,
                        SOCKET *out_listener, int *out_family)
{
    ADDRINFOW *resolved = NULL;
    int effective_backlog = (backlog > 0) ? backlog : SOMAXCONN;
    sq_status st = SQ_OK;

    if (port == NULL || out_listener == NULL || out_family == NULL) {
        return SQ_ERR_PARAM;
    }
    *out_listener = INVALID_SOCKET;
    *out_family = AF_UNSPEC;

    st = resolve_listen_addresses(host, port, &resolved);
    if (st != SQ_OK) {
        return st;
    }
    (void)choose_listener(resolved, effective_backlog, out_listener,
                          out_family);
    FreeAddrInfoW(resolved);

    if (*out_listener == INVALID_SOCKET) {
        SQLOG_ERROR(SQLOG_SUB_NET, L"no usable listen address for %s:%s",
                     (host != NULL) ? host : L"*", port);
        return SQ_ERR_ADDRESS;
    }
    return SQ_OK;
}

sq_status sq_net_load_ext(SOCKET s, sq_net_ext *out)
{
    GUID accept_guid = WSAID_ACCEPTEX;
    GUID addrs_guid = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD got = 0;

    if (out == NULL || s == INVALID_SOCKET) {
        return SQ_ERR_PARAM;
    }
    ZeroMemory(out, sizeof *out);

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &accept_guid, (DWORD)sizeof accept_guid,
                 &out->accept_ex, (DWORD)sizeof out->accept_ex,
                 &got, NULL, NULL) != 0) {
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                   L"WSAIoctl(AcceptEx) failed");
        return SQ_ERR_SYSTEM;
    }
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &addrs_guid, (DWORD)sizeof addrs_guid,
                 &out->get_accept_ex_sockaddrs,
                 (DWORD)sizeof out->get_accept_ex_sockaddrs,
                 &got, NULL, NULL) != 0) {
        SQLOG_WINERR(SQLOG_SUB_NET, ERROR, (unsigned long)WSAGetLastError(),
                   L"WSAIoctl(GetAcceptExSockaddrs) failed");
        return SQ_ERR_SYSTEM;
    }
    if (out->accept_ex == NULL || out->get_accept_ex_sockaddrs == NULL) {
        SQLOG_ERROR(SQLOG_SUB_NET, L"extension pointers resolved to NULL");
        return SQ_ERR_SYSTEM;
    }
    return SQ_OK;
}

void sq_net_peer_str(const struct sockaddr *addr, int addr_len,
                     wchar_t *buf, size_t cap)
{
    wchar_t host[NI_MAXHOST] = {0};
    wchar_t serv[NI_MAXSERV] = {0};
    int rc = 0;

    if (buf == NULL || cap == 0) {
        return;
    }
    buf[0] = L'\0';
    if (addr == NULL || addr_len <= 0) {
        (void)lstrcpynW(buf, L"<unknown>", (int)cap);
        return;
    }

    rc = GetNameInfoW(addr, addr_len, host, (DWORD)(sizeof host / sizeof host[0]),
                      serv, (DWORD)(sizeof serv / sizeof serv[0]),
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        (void)lstrcpynW(buf, L"<unresolved>", (int)cap);
        return;
    }
    (void)wnsprintfW(buf, (int)cap, L"%s:%s", host, serv);
}
