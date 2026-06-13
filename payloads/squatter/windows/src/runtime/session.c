#include "runtime/session.h"

#include "wire/control_codec.h"
#include "wire/frame.h"
#include "wire/framing.h"

enum {
    SQ_SESSION_READ_BUF = 65536,
    SQ_STREAM_PIPE_BUF = 65536
};

typedef struct sq_stream {
    UINT64 id;
    sq_session *session;
    sq_module_fn fn;

    HANDLE session_end; /* server end: session reads/writes this              */
    HANDLE module_end;  /* client end: handed to the module; closed on return */
    HANDLE module_thread;
    HANDLE pump_thread;

    int argc;
    wchar_t **argv; /* owned; argv[argc] == NULL */

    struct sq_stream *next;
} sq_stream;

struct sq_session {
    sq_channel *channel;
    const sq_module_table *modules;
    CRITICAL_SECTION write_lock; /* serializes channel writes across pumps */
    sq_frame_reader *reader;
    sq_stream *streams; /* owned by the reader thread only */
    HANDLE reader_thread;
};

/* ------------------------------------------------------------------------- */
/* Small heap + string helpers                                               */
/* ------------------------------------------------------------------------- */

static void *xalloc(SIZE_T n)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n == 0) ? 1u : n);
}

static void xfree(void *p)
{
    if (p != NULL) {
        (void)HeapFree(GetProcessHeap(), 0, p);
    }
}

static wchar_t *utf8_to_wide(const char *utf8)
{
    int wlen = 0;
    wchar_t *w = NULL;

    wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0); /* incl. NUL */
    if (wlen <= 0) {
        wlen = 1;
    }
    w = xalloc((SIZE_T)wlen * sizeof *w);
    if (w == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w, wlen) <= 0) {
        w[0] = L'\0';
    }
    return w;
}

static wchar_t **build_argv(const char *module, const sqmux_OpenStream *open,
                            int *out_argc)
{
    int n = (int)open->args_count;
    int argc = 1 + n;
    wchar_t **argv = NULL;
    int i = 0;

    argv = xalloc((SIZE_T)(argc + 1) * sizeof *argv);
    if (argv == NULL) {
        *out_argc = 0;
        return NULL;
    }
    argv[0] = utf8_to_wide(module);
    for (i = 0; i < n; i++) {
        argv[1 + i] = utf8_to_wide(open->args[i]);
    }
    argv[argc] = NULL;
    *out_argc = argc;
    return argv;
}

static void free_argv(wchar_t **argv, int argc)
{
    int i = 0;

    if (argv == NULL) {
        return;
    }
    for (i = 0; i < argc; i++) {
        xfree(argv[i]);
    }
    xfree(argv);
}

/* ------------------------------------------------------------------------- */
/* Channel writes (locked) and frame emission                               */
/* ------------------------------------------------------------------------- */

static void session_write_frame(sq_session *s, UINT16 kind, UINT64 stream_id,
                                const BYTE *payload, UINT32 length)
{
    BYTE *frame = NULL;
    UINT32 frame_len = 0;

    if (!sq_frame_encode(kind, stream_id, payload, length, &frame, &frame_len)) {
        return;
    }
    EnterCriticalSection(&s->write_lock);
    (void)sq_channel_write_all(s->channel, frame, frame_len);
    LeaveCriticalSection(&s->write_lock);
    sq_frame_buffer_free(frame);
}

/* ------------------------------------------------------------------------- */
/* Per-stream threads                                                        */
/* ------------------------------------------------------------------------- */

/* Runs the module, then closes the module's pipe end so the pump sees EOF. */
static DWORD WINAPI module_trampoline(LPVOID param)
{
    sq_stream *st = (sq_stream *)param;

    (void)st->fn(st->module_end, st->argc, st->argv);
    if (st->module_end != INVALID_HANDLE_VALUE && st->module_end != NULL) {
        (void)CloseHandle(st->module_end);
        st->module_end = INVALID_HANDLE_VALUE;
    }
    return 0;
}

/* Reads whole messages the module writes and forwards them as DATA frames; on
 * EOF (module returned, or the session closed the pipe) it emits a CLOSE. */
static DWORD WINAPI pump_thread(LPVOID param)
{
    sq_stream *st = (sq_stream *)param;
    sq_session *s = st->session;

    for (;;) {
        BYTE buf[SQ_SESSION_READ_BUF];
        DWORD n = 0;

        if (ReadFile(st->session_end, buf, (DWORD)sizeof buf, &n, NULL) == FALSE) {
            break;
        }
        if (n == 0) {
            break;
        }
        session_write_frame(s, (UINT16)SQ_FRAME_DATA, st->id, buf, (UINT32)n);
    }
    session_write_frame(s, (UINT16)SQ_FRAME_CLOSE, st->id, NULL, 0);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Stream creation                                                           */
/* ------------------------------------------------------------------------- */

static BOOL make_message_pipe(sq_session *s, UINT64 id, HANDLE *server_end,
                              HANDLE *client_end)
{
    wchar_t name[160];
    HANDLE server = INVALID_HANDLE_VALUE;
    HANDLE client = INVALID_HANDLE_VALUE;
    DWORD read_mode = PIPE_READMODE_MESSAGE;

    /* Unique per (process, session, stream): the session pointer disambiguates
     * the same stream id used on different connections. */
    (void)wnsprintfW(name, (int)(sizeof name / sizeof name[0]),
                     L"\\\\.\\pipe\\sqmux-%lu-%p-%I64u",
                     (unsigned long)GetCurrentProcessId(), (void *)s,
                     (unsigned __int64)id);

    server = CreateNamedPipeW(
        name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, SQ_STREAM_PIPE_BUF, SQ_STREAM_PIPE_BUF, 0, NULL);
    if (server == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    client = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (client == INVALID_HANDLE_VALUE) {
        (void)CloseHandle(server);
        return FALSE;
    }
    if (SetNamedPipeHandleState(client, &read_mode, NULL, NULL) == FALSE) {
        (void)CloseHandle(server);
        (void)CloseHandle(client);
        return FALSE;
    }
    /* The CreateFile above already connected the client side. */
    if (ConnectNamedPipe(server, NULL) == FALSE) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            (void)CloseHandle(server);
            (void)CloseHandle(client);
            return FALSE;
        }
    }
    *server_end = server;
    *client_end = client;
    return TRUE;
}

static void handle_open(sq_session *s, UINT64 id, const BYTE *payload, UINT32 len)
{
    sqmux_OpenStream open;
    sq_module_fn fn = NULL;
    sq_stream *st = NULL;

    if (!sq_control_decode_open(payload, len, &open)) {
        session_write_frame(s, (UINT16)SQ_FRAME_CLOSE, id, NULL, 0);
        return;
    }
    fn = sq_module_lookup(s->modules, open.module);
    if (fn == NULL) {
        session_write_frame(s, (UINT16)SQ_FRAME_CLOSE, id, NULL, 0);
        return;
    }

    st = xalloc(sizeof *st);
    if (st == NULL) {
        session_write_frame(s, (UINT16)SQ_FRAME_CLOSE, id, NULL, 0);
        return;
    }
    st->id = id;
    st->session = s;
    st->fn = fn;
    st->session_end = INVALID_HANDLE_VALUE;
    st->module_end = INVALID_HANDLE_VALUE;

    if (!make_message_pipe(s, id, &st->session_end, &st->module_end)) {
        xfree(st);
        session_write_frame(s, (UINT16)SQ_FRAME_CLOSE, id, NULL, 0);
        return;
    }
    st->argv = build_argv(open.module, &open, &st->argc);

    /* Link first, so the stream is findable for DATA that races the threads. */
    st->next = s->streams;
    s->streams = st;

    st->module_thread = CreateThread(NULL, 0, module_trampoline, st, 0, NULL);
    st->pump_thread = CreateThread(NULL, 0, pump_thread, st, 0, NULL);
}

static sq_stream *find_stream(sq_session *s, UINT64 id)
{
    sq_stream *st = s->streams;

    while (st != NULL) {
        if (st->id == id) {
            return st;
        }
        st = st->next;
    }
    return NULL;
}

static void handle_data(sq_session *s, UINT64 id, const BYTE *payload, UINT32 len)
{
    sq_stream *st = find_stream(s, id);
    DWORD wrote = 0;

    if (st == NULL || st->session_end == INVALID_HANDLE_VALUE) {
        return;
    }
    /* Message-mode: this whole payload arrives at the module as one ReadFile. */
    (void)WriteFile(st->session_end, payload, len, &wrote, NULL);
}

static void handle_close(sq_session *s, UINT64 id)
{
    sq_stream *st = find_stream(s, id);

    if (st == NULL) {
        return;
    }
    /* Closing the session end makes the module's ReadFile return: it ends
     * gracefully, the trampoline closes the module end, the pump emits CLOSE. */
    if (st->session_end != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(st->session_end);
        st->session_end = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------------- */
/* Frame dispatch + reader loop                                              */
/* ------------------------------------------------------------------------- */

static int on_frame(void *ctx, UINT16 kind, UINT64 stream_id,
                    const BYTE *payload, UINT32 length)
{
    sq_session *s = (sq_session *)ctx;

    switch (kind) {
    case SQ_FRAME_OPEN:
        handle_open(s, stream_id, payload, length);
        break;
    case SQ_FRAME_DATA:
        handle_data(s, stream_id, payload, length);
        break;
    case SQ_FRAME_CLOSE:
        handle_close(s, stream_id);
        break;
    default:
        break;
    }
    return 0;
}

static DWORD WINAPI reader_main(LPVOID param)
{
    sq_session *s = (sq_session *)param;

    for (;;) {
        BYTE buf[SQ_SESSION_READ_BUF];
        int n = sq_channel_read_some(s->channel, buf, (UINT32)sizeof buf);

        if (n <= 0) {
            break; /* EOF or error: the connection is done */
        }
        if (sq_frame_reader_push(s->reader, buf, (UINT32)n, on_frame, s) != 0) {
            break; /* protocol error */
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

sq_session *sq_session_create(sq_channel *ch, const sq_module_table *modules)
{
    sq_session *s = NULL;

    if (ch == NULL || modules == NULL) {
        return NULL;
    }
    s = xalloc(sizeof *s);
    if (s == NULL) {
        return NULL;
    }
    s->channel = ch;
    s->modules = modules;
    s->streams = NULL;
    InitializeCriticalSection(&s->write_lock);

    s->reader = sq_frame_reader_new();
    if (s->reader == NULL) {
        DeleteCriticalSection(&s->write_lock);
        xfree(s);
        return NULL;
    }
    s->reader_thread = CreateThread(NULL, 0, reader_main, s, 0, NULL);
    if (s->reader_thread == NULL) {
        sq_frame_reader_free(s->reader);
        DeleteCriticalSection(&s->write_lock);
        xfree(s);
        return NULL;
    }
    return s;
}

void sq_session_destroy(sq_session *s)
{
    sq_stream *st = NULL;

    if (s == NULL) {
        return;
    }

    /* Stop the reader: closing the channel makes its blocking read return. */
    sq_channel_close(s->channel);
    if (s->reader_thread != NULL) {
        (void)WaitForSingleObject(s->reader_thread, INFINITE);
        (void)CloseHandle(s->reader_thread);
        s->reader_thread = NULL;
    }

    /* The reader is joined, so the stream list is now ours alone. Tear down
     * each stream: closing the session end unblocks both module and pump. */
    st = s->streams;
    s->streams = NULL;
    while (st != NULL) {
        sq_stream *next = st->next;

        if (st->session_end != INVALID_HANDLE_VALUE) {
            (void)CloseHandle(st->session_end);
            st->session_end = INVALID_HANDLE_VALUE;
        }
        if (st->module_thread != NULL) {
            (void)WaitForSingleObject(st->module_thread, INFINITE);
            (void)CloseHandle(st->module_thread);
        }
        if (st->pump_thread != NULL) {
            (void)WaitForSingleObject(st->pump_thread, INFINITE);
            (void)CloseHandle(st->pump_thread);
        }
        free_argv(st->argv, st->argc);
        xfree(st);
        st = next;
    }

    sq_frame_reader_free(s->reader);
    sq_channel_free(s->channel);
    DeleteCriticalSection(&s->write_lock);
    xfree(s);
}
