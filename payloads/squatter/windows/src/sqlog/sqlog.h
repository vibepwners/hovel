/* sqlog.h -- an incredibly opinionated, WinAPI-only logging facility.
 *
 * Highlights:
 *   - CRT-free: formatting via shlwapi wnsprintf, output via WriteFile /
 *     OutputDebugString / a GUI window. No printf, no malloc.
 *   - Compiles out completely. SQLOG_ENABLED=0 (the default under NDEBUG) makes
 *     every macro vanish, arguments and all. SQLOG_COMPILE_LEVEL drops
 *     individual severities at compile time.
 *   - Heavy preprocessor: every call site injects __FILE__, __LINE__ and
 *     __func__ automatically; you never pass them by hand.
 *   - Subsystems via an X-macro registry (sqlog_subsystems.h).
 *   - Multiple sinks (debugger, colorized console, file, window), each with its
 *     own runtime level; plus a global level and per-subsystem overrides.
 *   - The usual industrial extras: ONCE / EVERY_N rate limiting, CHECK / DCHECK
 *     assertions, decoded Win32-error logging, and hex dumps.
 *
 * WIDE (UTF-16): this is a Unicode facility. Format strings are wide string
 * literals -- write L"...". Output goes through the wide WinAPI (WriteConsoleW,
 * OutputDebugStringW, FormatMessageW); pipe/file output is converted to UTF-8.
 *
 * FORMAT DIALECT: messages are formatted by the Win32 wvnsprintfW family, NOT C
 * printf. Use %d/%u/%x/%c with the l and I64 length modifiers; zero-pad via a
 * precision (%.2u). %s is a WIDE string, %S is a narrow (char*) string. No %z,
 * no %f. (This is why no format(printf) attribute is attached -- the compiler
 * must not check these against C printf rules.)
 */
#ifndef SQLOG_SQLOG_H
#define SQLOG_SQLOG_H

#include "sqlog/sqlog_config.h"
#include "sqlog/sqlog_subsystems.h"
#include "sqlog/sqlog_window.h"

#include <stddef.h> /* size_t -- a freestanding header, not the CRT */

/* ------------------------------------------------------------------------- */
/* Subsystems: enum + count, generated from the X-macro table.               */
/* ------------------------------------------------------------------------- */

typedef enum sqlog_subsystem {
#define SQLOG__SUB_ENUM(suffix, name) SQLOG_SUB_##suffix,
    SQLOG_SUBSYSTEM_TABLE(SQLOG__SUB_ENUM)
#undef SQLOG__SUB_ENUM
    SQLOG_SUB__COUNT /* not a subsystem; the table size */
} sqlog_subsystem;

/* ------------------------------------------------------------------------- */
/* Sinks (for the runtime enable/level API).                                 */
/* ------------------------------------------------------------------------- */

typedef enum sqlog_sink {
    SQLOG_SINK_ID_DEBUGGER = 0,
    SQLOG_SINK_ID_CONSOLE,
    SQLOG_SINK_ID_FILE,
    SQLOG_SINK_ID_WINDOW,
    SQLOG_SINK__COUNT
} sqlog_sink;

/* ------------------------------------------------------------------------- */
/* Lifecycle and runtime configuration.                                      */
/* ------------------------------------------------------------------------- */

/* Optional: establishes sinks/levels explicitly. Logging works without it
 * (lazy init), but call it once at startup if you want to set things up before
 * the first line. Idempotent. */
void sqlog_init(void);
void sqlog_shutdown(void); /* flushes/closes file + window sinks */

void sqlog_set_level(int level);     /* global runtime threshold (default TRACE) */
int  sqlog_get_level(void);

/* Per-subsystem override; pass SQLOG_LEVEL_OFF to silence one subsystem, or -1
 * to clear the override and inherit the global level. */
void sqlog_set_subsystem_level(sqlog_subsystem sub, int level);

void sqlog_set_sink_enabled(sqlog_sink sink, int on);
void sqlog_set_sink_level(sqlog_sink sink, int level);

/* Enable the file sink, writing (appending) to `path`. Returns 1 on success. */
int  sqlog_open_file(const char *path);

const char *sqlog_level_name(int level);          /* "INFO", clamped/totalized */
const char *sqlog_subsystem_name(sqlog_subsystem sub);

/* The runtime pre-check the macros use; also callable directly. Nonzero if a
 * line at (sub, level) would reach at least the gate (cheap, no formatting). */
int sqlog_should(int sub, int level);

/* The emit primitives. Call sites never invoke these directly -- the macros do,
 * injecting file/line/func. `fmt`/`label` are WIDE (L"..."); file/func come from
 * __FILE__/__func__ and stay narrow (printed with %S). */
void sqlog_emit(int sub, int level, const char *file, int line,
                const char *func, const wchar_t *fmt, ...);
void sqlog_emit_sys(int sub, int level, unsigned long err, const char *file,
                    int line, const char *func, const wchar_t *fmt, ...);
void sqlog_hexdump(int sub, int level, const char *file, int line,
                   const char *func, const wchar_t *label,
                   const void *data, size_t len);

/* Terminate the process after a FATAL/CHECK. Breaks into an attached debugger
 * first, then exits. Marked noreturn for the optimizer and the reader. */
#if defined(__GNUC__)
__attribute__((noreturn))
#endif
void sqlog_fatal_abort(void);

/* ------------------------------------------------------------------------- */
/* The core macro machinery.                                                 */
/* ------------------------------------------------------------------------- */

/* Active form: runtime-gate, then emit with injected context. The do/while(0)
 * makes it a single statement usable after a bare `if`. */
#define SQLOG__EMIT(sub, level, ...)                                           \
    do {                                                                       \
        if (sqlog_should((int)(sub), (level))) {                               \
            sqlog_emit((int)(sub), (level), __FILE__, __LINE__, __func__,      \
                       __VA_ARGS__);                                           \
        }                                                                      \
    } while (0)

/* Compiled-out form: expands to a statement, evaluates nothing. Arguments are
 * discarded by the preprocessor, so disabled sites cost exactly zero and never
 * run side effects. (Corollary: a variable used ONLY inside a disabled log is
 * unused -- mark such variables (void) at their declaration if needed.) */
#define SQLOG__VOID(...) ((void)0)

/* Per-level public macros. Each is independently compiled in or out by
 * SQLOG_COMPILED(level), so the gate is the preprocessor, not dead-code
 * elimination -- the strongest form of "compile it out". */
#if SQLOG_COMPILED(SQLOG_LEVEL_TRACE)
#  define SQLOG_TRACE(sub, ...) SQLOG__EMIT((sub), SQLOG_LEVEL_TRACE, __VA_ARGS__)
#else
#  define SQLOG_TRACE(sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

#if SQLOG_COMPILED(SQLOG_LEVEL_VERBOSE)
#  define SQLOG_VERBOSE(sub, ...) SQLOG__EMIT((sub), SQLOG_LEVEL_VERBOSE, __VA_ARGS__)
#else
#  define SQLOG_VERBOSE(sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

#if SQLOG_COMPILED(SQLOG_LEVEL_DEBUG)
#  define SQLOG_DEBUG(sub, ...) SQLOG__EMIT((sub), SQLOG_LEVEL_DEBUG, __VA_ARGS__)
#else
#  define SQLOG_DEBUG(sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

#if SQLOG_COMPILED(SQLOG_LEVEL_INFO)
#  define SQLOG_INFO(sub, ...) SQLOG__EMIT((sub), SQLOG_LEVEL_INFO, __VA_ARGS__)
#else
#  define SQLOG_INFO(sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

#if SQLOG_COMPILED(SQLOG_LEVEL_WARN)
#  define SQLOG_WARN(sub, ...) SQLOG__EMIT((sub), SQLOG_LEVEL_WARN, __VA_ARGS__)
#else
#  define SQLOG_WARN(sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

#if SQLOG_COMPILED(SQLOG_LEVEL_ERROR)
#  define SQLOG_ERROR(sub, ...) SQLOG__EMIT((sub), SQLOG_LEVEL_ERROR, __VA_ARGS__)
#else
#  define SQLOG_ERROR(sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

/* FATAL: log (if compiled in), then abort. The abort survives even when the
 * message is compiled out, because a fatal condition must still stop the
 * program (toggle with SQLOG_FATAL_ABORTS). */
#if SQLOG_FATAL_ABORTS
#  define SQLOG__FATAL_TAIL() sqlog_fatal_abort()
#else
#  define SQLOG__FATAL_TAIL() ((void)0)
#endif

#if SQLOG_COMPILED(SQLOG_LEVEL_FATAL)
#  define SQLOG_FATAL(sub, ...)                                                 \
    do {                                                                       \
        SQLOG__EMIT((sub), SQLOG_LEVEL_FATAL, __VA_ARGS__);                     \
        SQLOG__FATAL_TAIL();                                                    \
    } while (0)
#else
#  define SQLOG_FATAL(sub, ...)                                                 \
    do {                                                                       \
        SQLOG__VOID(__VA_ARGS__);                                              \
        SQLOG__FATAL_TAIL();                                                    \
    } while (0)
#endif

/* ------------------------------------------------------------------------- */
/* Win32-error and hexdump helpers (context injected, level-gated).          */
/* ------------------------------------------------------------------------- */

/* Throughout these helpers `sub` is a full SQLOG_SUB_* enumerator (matching the
 * level macros), while `level_name` is a bare severity word (TRACE..ERROR) that
 * is pasted onto SQLOG_LEVEL_ / SQLOG_ as needed. */

/* Log `fmt ...` at `level_name`, appending the decoded system error `err`.
 * Example: SQLOG_WINERR(SQLOG_SUB_NET, ERROR, WSAGetLastError(), "bind"). */
#define SQLOG_WINERR(sub, level_name, err, ...)                                \
    do {                                                                       \
        if (SQLOG_COMPILED(SQLOG_LEVEL_##level_name) &&                        \
            sqlog_should((int)(sub), SQLOG_LEVEL_##level_name)) {              \
            sqlog_emit_sys((int)(sub), SQLOG_LEVEL_##level_name,               \
                           (unsigned long)(err), __FILE__, __LINE__, __func__, \
                           __VA_ARGS__);                                       \
        }                                                                      \
    } while (0)

/* Hex+ASCII dump of a buffer at `level_name`. */
#define SQLOG_HEXDUMP(sub, level_name, label, data, len)                       \
    do {                                                                       \
        if (SQLOG_COMPILED(SQLOG_LEVEL_##level_name) &&                        \
            sqlog_should((int)(sub), SQLOG_LEVEL_##level_name)) {              \
            sqlog_hexdump((int)(sub), SQLOG_LEVEL_##level_name,                \
                          __FILE__, __LINE__, __func__, (label), (data),       \
                          (size_t)(len));                                      \
        }                                                                      \
    } while (0)

/* ------------------------------------------------------------------------- */
/* Rate limiting: ONCE and EVERY_N. `level_name` is a bare TRACE..ERROR.      */
/* ------------------------------------------------------------------------- */

/* Token-paste plumbing so static counter names are unique per call site. */
#define SQLOG__CAT2(a, b) a##b
#define SQLOG__CAT(a, b) SQLOG__CAT2(a, b)

/* Emit at most once for the lifetime of the process. The whole construct is
 * wrapped in `if (SQLOG_COMPILED(...))`, a compile-time constant, so when the
 * level is gated out the static counter and the interlocked op fold away. */
#define SQLOG_ONCE(level_name, sub, ...)                                       \
    do {                                                                       \
        if (SQLOG_COMPILED(SQLOG_LEVEL_##level_name)) {                        \
            static volatile long SQLOG__CAT(sqlog_once_, __LINE__) = 0;         \
            if (sqlog__claim_once(&SQLOG__CAT(sqlog_once_, __LINE__))) {        \
                SQLOG_##level_name((sub), __VA_ARGS__);                         \
            }                                                                  \
        }                                                                      \
    } while (0)

/* Emit on the 1st, (n+1)th, (2n+1)th ... occurrence. */
#define SQLOG_EVERY_N(level_name, sub, n, ...)                                  \
    do {                                                                       \
        if (SQLOG_COMPILED(SQLOG_LEVEL_##level_name)) {                        \
            static volatile long SQLOG__CAT(sqlog_count_, __LINE__) = 0;        \
            if (sqlog__tick_every(&SQLOG__CAT(sqlog_count_, __LINE__),          \
                                  (long)(n))) {                                 \
                SQLOG_##level_name((sub), __VA_ARGS__);                         \
            }                                                                  \
        }                                                                      \
    } while (0)

/* Interlocked helpers behind ONCE/EVERY_N (defined in sqlog.c). */
int sqlog__claim_once(volatile long *flag);
int sqlog__tick_every(volatile long *counter, long n);

/* ------------------------------------------------------------------------- */
/* Assertions: CHECK (always) and DCHECK (debug-only), glog-style.           */
/* ------------------------------------------------------------------------- */

/* Widen a (stringized) literal to a wide literal: SQLOG__WIDEN(#cond). */
#define SQLOG__WIDEN2(x) L##x
#define SQLOG__WIDEN(x) SQLOG__WIDEN2(x)

/* CHECK always evaluates `cond`. On failure it logs FATAL and aborts even in a
 * release build, so it is safe for invariants that must hold in production. */
#define SQLOG_CHECK(cond, sub, ...)                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            sqlog_emit((int)(sub), SQLOG_LEVEL_FATAL, __FILE__, __LINE__,       \
                       __func__, L"CHECK failed: " SQLOG__WIDEN(#cond));        \
            SQLOG_FATAL((sub), __VA_ARGS__);                                    \
        }                                                                      \
    } while (0)

/* DCHECK compiles to nothing when logging is disabled (NDEBUG by default), so
 * `cond` is not even evaluated -- the standard debug-only assertion. */
#if SQLOG_ENABLED
#  define SQLOG_DCHECK(cond, sub, ...) SQLOG_CHECK((cond), sub, __VA_ARGS__)
#else
#  define SQLOG_DCHECK(cond, sub, ...) SQLOG__VOID(__VA_ARGS__)
#endif

/* ------------------------------------------------------------------------- */
/* Scope tracing: logs "enter" now and "leave" at end of scope (GCC cleanup). */
/* ------------------------------------------------------------------------- */

#if SQLOG_COMPILED(SQLOG_LEVEL_TRACE) && defined(__GNUC__)

typedef struct sqlog_scope {
    int sub;
    const char *func;
    const char *file;
    int line;
} sqlog_scope;

void sqlog__scope_enter(const sqlog_scope *s);
void sqlog__scope_leave(sqlog_scope *s);

/* Place SQLOG_SCOPE(NET); at the top of a function body. */
#  define SQLOG_SCOPE(sub)                                                      \
    sqlog_scope SQLOG__CAT(sqlog_scope_, __LINE__)                              \
        __attribute__((cleanup(sqlog__scope_leave))) =                         \
        { (int)(SQLOG_SUB_##sub), __func__, __FILE__, __LINE__ };               \
    sqlog__scope_enter(&SQLOG__CAT(sqlog_scope_, __LINE__))

#else
#  define SQLOG_SCOPE(sub) ((void)0)
#endif

#endif /* SQLOG_SQLOG_H */
