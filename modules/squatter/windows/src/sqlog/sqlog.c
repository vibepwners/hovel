#include "sqlog/sqlog.h"

/* Standalone WinAPI surface: this library needs windows.h + shlwapi only (no
 * winsock), so it pulls them in directly rather than via the server's shim. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <shlwapi.h>
#include <windows.h>

#include <stdarg.h>

/* This is a wide (UTF-16) facility: lines are built and formatted as wchar_t and
 * emitted through the wide WinAPI (OutputDebugStringW, WriteConsoleW,
 * FormatMessageW). Output destined for a pipe/file is converted to UTF-8 first;
 * the console gets the UTF-16 directly. */

/* ------------------------------------------------------------------------- */
/* State                                                                     */
/* ------------------------------------------------------------------------- */

typedef struct sink_state
{
        volatile LONG enabled;
        volatile LONG level;
} sink_state;

static struct
{
        CRITICAL_SECTION lock;
        volatile LONG global_level;
        volatile LONG sub_level[SQLOG_SUB__COUNT]; /* -1 == inherit global */
        sink_state sinks[SQLOG_SINK__COUNT];
        HANDLE file;        /* INVALID_HANDLE_VALUE if none                 */
        HANDLE console;     /* STD_ERROR_HANDLE, cached                     */
        WORD console_attrs; /* original attributes                          */
        int console_is_tty; /* a real console: use WriteConsoleW + colour   */
} g;

static volatile LONG g_init_state = 0;

/* Names kept narrow; the wide formatter prints them with %S. */
static const char *const k_level_names[] = {"TRACE", "VERBOSE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "OFF"};

static const char *const k_sub_names[] = {
#define SQLOG__SUB_NAME(suffix, name) name,
    SQLOG_SUBSYSTEM_TABLE(SQLOG__SUB_NAME)
#undef SQLOG__SUB_NAME
};

/* ------------------------------------------------------------------------- */
/* Init                                                                      */
/* ------------------------------------------------------------------------- */

static void init_state(void)
{
        int i = 0;
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        DWORD mode = 0;

        InitializeCriticalSection(&g.lock);
        g.global_level = (LONG)SQLOG_LEVEL_TRACE;
        for (i = 0; i < SQLOG_SUB__COUNT; i++)
        {
                g.sub_level[i] = -1;
        }
        for (i = 0; i < SQLOG_SINK__COUNT; i++)
        {
                g.sinks[i].enabled = 0;
                g.sinks[i].level = (LONG)SQLOG_LEVEL_TRACE;
        }
        g.sinks[SQLOG_SINK_ID_DEBUGGER].enabled = SQLOG_SINK_DEBUGGER ? 1 : 0;
        g.sinks[SQLOG_SINK_ID_CONSOLE].enabled = SQLOG_SINK_CONSOLE ? 1 : 0;
        g.sinks[SQLOG_SINK_ID_FILE].enabled = 0;
        g.sinks[SQLOG_SINK_ID_WINDOW].enabled = SQLOG_WINDOW ? 1 : 0;
        g.sinks[SQLOG_SINK_ID_WINDOW].level = (LONG)SQLOG_WINDOW_MIN_LEVEL;

        g.file = INVALID_HANDLE_VALUE;
        g.console = GetStdHandle(STD_ERROR_HANDLE);
        g.console_attrs = (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        g.console_is_tty = 0;
        ZeroMemory(&csbi, sizeof csbi);
        if (g.console != NULL && g.console != INVALID_HANDLE_VALUE && GetConsoleMode(g.console, &mode) != FALSE &&
            GetConsoleScreenBufferInfo(g.console, &csbi) != FALSE)
        {
                g.console_attrs = csbi.wAttributes;
                g.console_is_tty = 1;
        }
}

static void ensure_init(void)
{
        if (InterlockedCompareExchange(&g_init_state, 1, 0) == 0)
        {
                init_state();
                InterlockedExchange(&g_init_state, 2);
                return;
        }
        while (g_init_state != 2)
        {
                Sleep(1);
        }
}

void sqlog_init(void)
{
        ensure_init();
#if SQLOG_WINDOW
        sqlog_window_start();
#endif
}

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static int clamp_level(int level)
{
        if (level < SQLOG_LEVEL_TRACE)
        {
                return SQLOG_LEVEL_TRACE;
        }
        if (level > SQLOG_LEVEL_OFF)
        {
                return SQLOG_LEVEL_OFF;
        }
        return level;
}

const char *sqlog_level_name(int level)
{
        return k_level_names[clamp_level(level)];
}

const char *sqlog_subsystem_name(sqlog_subsystem sub)
{
        if ((int)sub < 0 || (int)sub >= SQLOG_SUB__COUNT)
        {
                return "?";
        }
        return k_sub_names[(int)sub];
}

/* Bounded, wide append via shlwapi's wvnsprintfW. */
static void append_va(wchar_t *buf, int cap, int *pos, const wchar_t *fmt, va_list ap)
{
        int remaining = 0;
        int written = 0;

        if (*pos >= cap - 1)
        {
                return;
        }
        remaining = cap - *pos;
        written = wvnsprintfW(buf + *pos, remaining, fmt, ap);
        if (written < 0 || written >= remaining)
        {
                *pos = cap - 1;
                buf[*pos] = L'\0';
                return;
        }
        *pos += written;
}

static void append_fmt(wchar_t *buf, int cap, int *pos, const wchar_t *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        append_va(buf, cap, pos, fmt, ap);
        va_end(ap);
}

/* Decode `err` into wide `buf` via FormatMessageW. Always NUL-terminates. */
static void format_sys_error(unsigned long err, wchar_t *buf, int cap)
{
        DWORD written = 0;

        if (cap <= 0)
        {
                return;
        }
        buf[0] = L'\0';
        written = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)err,
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (DWORD)cap, NULL);
        if (written == 0)
        {
                int pos = 0;
                append_fmt(buf, cap, &pos, L"system error %lu", err);
                return;
        }
        while (written > 0)
        {
                wchar_t const c = buf[written - 1];
                if (c == L'\r' || c == L'\n' || c == L'.' || c == L' ')
                {
                        buf[written - 1] = L'\0';
                        written--;
                }
                else
                {
                        break;
                }
        }
}

/* Build the standard prefix. Narrow fields (file/func/level/subsystem) print
 * with %S; numerics use precision for zero-pad (wsprintf has no '0' flag). */
static void build_prefix(wchar_t *buf, int cap, int *pos, int sub, int level, const char *file, int line,
                         const char *func)
{
        SYSTEMTIME now;

        GetLocalTime(&now);
        append_fmt(buf, cap, pos, L"%.2u:%.2u:%.2u.%.3u %-7S [%-8S] tid=%-5lu %S:%d %S: ", (unsigned)now.wHour,
                   (unsigned)now.wMinute, (unsigned)now.wSecond, (unsigned)now.wMilliseconds, sqlog_level_name(level),
                   sqlog_subsystem_name((sqlog_subsystem)sub), (unsigned long)GetCurrentThreadId(), file, line, func);
}

/* ------------------------------------------------------------------------- */
/* Console colour                                                            */
/* ------------------------------------------------------------------------- */

#if SQLOG_CONSOLE_COLOR
static WORD level_color(int level)
{
        WORD const intense = FOREGROUND_INTENSITY;
        switch (level)
        {
        case SQLOG_LEVEL_TRACE:
                return (WORD)FOREGROUND_INTENSITY;
        case SQLOG_LEVEL_VERBOSE:
                return (WORD)(FOREGROUND_BLUE | intense);
        case SQLOG_LEVEL_DEBUG:
                return (WORD)(FOREGROUND_BLUE | FOREGROUND_GREEN | intense);
        case SQLOG_LEVEL_INFO:
                return (WORD)(FOREGROUND_GREEN | intense);
        case SQLOG_LEVEL_WARN:
                return (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | intense);
        case SQLOG_LEVEL_ERROR:
                return (WORD)(FOREGROUND_RED | intense);
        case SQLOG_LEVEL_FATAL:
                return (WORD)(FOREGROUND_RED | FOREGROUND_BLUE | intense);
        default:
                return g.console_attrs;
        }
}
#endif

/* Write `wlen` UTF-16 chars to a byte stream as UTF-8. */
static void write_utf8(HANDLE h, const wchar_t *line, int wlen)
{
        char utf8[SQLOG_LINE_MAX * 3];
        int n = 0;
        DWORD wrote = 0;

        if (h == NULL || h == INVALID_HANDLE_VALUE || wlen <= 0)
        {
                return;
        }
        n = WideCharToMultiByte(CP_UTF8, 0, line, wlen, utf8, (int)sizeof utf8, NULL, NULL);
        if (n > 0)
        {
                (void)WriteFile(h, utf8, (DWORD)n, &wrote, NULL);
        }
}

static void write_console(int level, const wchar_t *line, int wlen)
{
        DWORD wrote = 0;

        if (g.console == NULL || g.console == INVALID_HANDLE_VALUE || wlen <= 0)
        {
                return;
        }
        if (g.console_is_tty == 0)
        {
                /* Redirected: emit UTF-8 bytes. */
                write_utf8(g.console, line, wlen);
                return;
        }
#if SQLOG_CONSOLE_COLOR
        (void)SetConsoleTextAttribute(g.console, level_color(level));
#else
        (void)level;
#endif
        (void)WriteConsoleW(g.console, line, (DWORD)wlen, &wrote, NULL);
#if SQLOG_CONSOLE_COLOR
        (void)SetConsoleTextAttribute(g.console, g.console_attrs);
#endif
}

/* ------------------------------------------------------------------------- */
/* Dispatch                                                                  */
/* ------------------------------------------------------------------------- */

static int effective_gate(int sub)
{
        LONG ov = -1;

        if (sub >= 0 && sub < SQLOG_SUB__COUNT)
        {
                ov = g.sub_level[sub];
        }
        return (ov >= 0) ? (int)ov : (int)g.global_level;
}

int sqlog_should(int sub, int level)
{
        ensure_init();
        return (level >= effective_gate(sub)) ? 1 : 0;
}

static void dispatch(int level, const wchar_t *line, int wlen)
{
        EnterCriticalSection(&g.lock);

        if (g.sinks[SQLOG_SINK_ID_DEBUGGER].enabled != 0 && level >= (int)g.sinks[SQLOG_SINK_ID_DEBUGGER].level)
        {
                OutputDebugStringW(line);
        }
        if (g.sinks[SQLOG_SINK_ID_CONSOLE].enabled != 0 && level >= (int)g.sinks[SQLOG_SINK_ID_CONSOLE].level)
        {
                write_console(level, line, wlen);
        }
        if (g.sinks[SQLOG_SINK_ID_FILE].enabled != 0 && g.file != INVALID_HANDLE_VALUE &&
            level >= (int)g.sinks[SQLOG_SINK_ID_FILE].level)
        {
                write_utf8(g.file, line, wlen);
        }

        LeaveCriticalSection(&g.lock);

        if (g.sinks[SQLOG_SINK_ID_WINDOW].enabled != 0)
        {
                sqlog_window_write(level, line);
        }
}

void sqlog_emit(int sub, int level, const char *file, int line, const char *func, const wchar_t *fmt, ...)
{
        wchar_t buf[SQLOG_LINE_MAX];
        int pos = 0;
        va_list ap;

        ensure_init();
        if (fmt == NULL)
        {
                fmt = L"(null log format)";
        }
        buf[0] = L'\0';
        build_prefix(buf, (int)(sizeof buf / sizeof buf[0]), &pos, sub, level, file, line, func);
        va_start(ap, fmt);
        append_va(buf, (int)(sizeof buf / sizeof buf[0]), &pos, fmt, ap);
        va_end(ap);
        append_fmt(buf, (int)(sizeof buf / sizeof buf[0]), &pos, L"\r\n");
        dispatch(level, buf, pos);
}

void sqlog_emit_sys(int sub, int level, unsigned long err, const char *file, int line, const char *func,
                    const wchar_t *fmt, ...)
{
        wchar_t buf[SQLOG_LINE_MAX];
        wchar_t detail[256];
        int pos = 0;
        va_list ap;

        ensure_init();
        if (fmt == NULL)
        {
                fmt = L"(null log format)";
        }
        buf[0] = L'\0';
        detail[0] = L'\0';
        format_sys_error(err, detail, (int)(sizeof detail / sizeof detail[0]));
        build_prefix(buf, (int)(sizeof buf / sizeof buf[0]), &pos, sub, level, file, line, func);
        va_start(ap, fmt);
        append_va(buf, (int)(sizeof buf / sizeof buf[0]), &pos, fmt, ap);
        va_end(ap);
        append_fmt(buf, (int)(sizeof buf / sizeof buf[0]), &pos, L": [%lu] %s\r\n", err, detail);
        dispatch(level, buf, pos);
}

/* ------------------------------------------------------------------------- */
/* Hex dump                                                                  */
/* ------------------------------------------------------------------------- */

void sqlog_hexdump(int sub, int level, const char *file, int line, const char *func, const wchar_t *label,
                   const void *data, size_t len)
{
        const unsigned char *p = (const unsigned char *)data;
        size_t off = 0;
        enum
        {
                ROW_CAP = 256
        };

        ensure_init();
        sqlog_emit(sub, level, file, line, func, L"hexdump %s (%u bytes)", (label != NULL) ? label : L"",
                   (unsigned)len);
        if (p == NULL)
        {
                return;
        }
        for (off = 0; off < len; off += 16)
        {
                wchar_t row[ROW_CAP];
                int pos = 0;
                size_t i = 0;

                row[0] = L'\0';
                append_fmt(row, ROW_CAP, &pos, L"  %.4x  ", (unsigned)off);
                for (i = 0; i < 16; i++)
                {
                        if (off + i < len)
                        {
                                append_fmt(row, ROW_CAP, &pos, L"%.2x ", (unsigned)p[off + i]);
                        }
                        else
                        {
                                append_fmt(row, ROW_CAP, &pos, L"   ");
                        }
                }
                append_fmt(row, ROW_CAP, &pos, L" ");
                for (i = 0; i < 16 && off + i < len; i++)
                {
                        unsigned char const c = p[off + i];
                        append_fmt(row, ROW_CAP, &pos, L"%c", (c >= 0x20 && c < 0x7F) ? (wchar_t)c : L'.');
                }
                append_fmt(row, ROW_CAP, &pos, L"\r\n");
                dispatch(level, row, pos);
        }
}

/* ------------------------------------------------------------------------- */
/* Rate-limit primitives                                                     */
/* ------------------------------------------------------------------------- */

int sqlog__claim_once(volatile long *flag)
{
        return (InterlockedCompareExchange(flag, 1, 0) == 0) ? 1 : 0;
}

int sqlog__tick_every(volatile long *counter, long n)
{
        long cur = InterlockedIncrement(counter);

        if (n <= 0)
        {
                return 1;
        }
        return (((cur - 1) % n) == 0) ? 1 : 0;
}

/* ------------------------------------------------------------------------- */
/* Scope tracing                                                             */
/* ------------------------------------------------------------------------- */

#if SQLOG_COMPILED(SQLOG_LEVEL_TRACE) && defined(__GNUC__)
void sqlog__scope_enter(const sqlog_scope *s)
{
        if (sqlog_should(s->sub, SQLOG_LEVEL_TRACE))
        {
                sqlog_emit(s->sub, SQLOG_LEVEL_TRACE, s->file, s->line, s->func, L"-> enter %S", s->func);
        }
}

void sqlog__scope_leave(sqlog_scope *s)
{
        if (sqlog_should(s->sub, SQLOG_LEVEL_TRACE))
        {
                sqlog_emit(s->sub, SQLOG_LEVEL_TRACE, s->file, s->line, s->func, L"<- leave %S", s->func);
        }
}
#endif

/* ------------------------------------------------------------------------- */
/* Runtime configuration                                                     */
/* ------------------------------------------------------------------------- */

void sqlog_set_level(int level)
{
        ensure_init();
        (void)InterlockedExchange(&g.global_level, (LONG)clamp_level(level));
}

int sqlog_get_level(void)
{
        ensure_init();
        return (int)g.global_level;
}

void sqlog_set_subsystem_level(sqlog_subsystem sub, int level)
{
        ensure_init();
        if ((int)sub < 0 || (int)sub >= SQLOG_SUB__COUNT)
        {
                return;
        }
        (void)InterlockedExchange(&g.sub_level[(int)sub], (level < 0) ? -1 : (LONG)clamp_level(level));
}

void sqlog_set_sink_enabled(sqlog_sink sink, int on)
{
        ensure_init();
        if ((int)sink < 0 || (int)sink >= SQLOG_SINK__COUNT)
        {
                return;
        }
        (void)InterlockedExchange(&g.sinks[(int)sink].enabled, on ? 1 : 0);
}

void sqlog_set_sink_level(sqlog_sink sink, int level)
{
        ensure_init();
        if ((int)sink < 0 || (int)sink >= SQLOG_SINK__COUNT)
        {
                return;
        }
        (void)InterlockedExchange(&g.sinks[(int)sink].level, (LONG)clamp_level(level));
        if (sink == SQLOG_SINK_ID_WINDOW)
        {
                sqlog_window_set_level(clamp_level(level));
        }
}

int sqlog_open_file(const char *path)
{
        HANDLE h = INVALID_HANDLE_VALUE;
        wchar_t wpath[1024];

        ensure_init();
        if (path == NULL)
        {
                return 0;
        }
        if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, (int)(sizeof wpath / sizeof wpath[0])) <= 0)
        {
                return 0;
        }
        h = CreateFileW(wpath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
                return 0;
        }
        EnterCriticalSection(&g.lock);
        if (g.file != INVALID_HANDLE_VALUE)
        {
                (void)CloseHandle(g.file);
        }
        g.file = h;
        g.sinks[SQLOG_SINK_ID_FILE].enabled = 1;
        LeaveCriticalSection(&g.lock);
        return 1;
}

void sqlog_shutdown(void)
{
        ensure_init();
        sqlog_window_stop();
        EnterCriticalSection(&g.lock);
        if (g.file != INVALID_HANDLE_VALUE)
        {
                (void)FlushFileBuffers(g.file);
                (void)CloseHandle(g.file);
                g.file = INVALID_HANDLE_VALUE;
                g.sinks[SQLOG_SINK_ID_FILE].enabled = 0;
        }
        LeaveCriticalSection(&g.lock);
}

/* ------------------------------------------------------------------------- */
/* Fatal                                                                     */
/* ------------------------------------------------------------------------- */

void sqlog_fatal_abort(void)
{
        OutputDebugStringW(L"sqlog: fatal, terminating\r\n");
        if (IsDebuggerPresent() != FALSE)
        {
                DebugBreak();
        }
        ExitProcess((UINT)3);
}
