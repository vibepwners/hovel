/* sqlog_config.h -- every compile-time knob, with defaults.
 *
 * Override any of these by defining it on the compiler command line (-D...) or
 * before including <sqlog/sqlog.h>. The #ifndef guards mean your value wins.
 *
 * Two ideas dominate:
 *   - SQLOG_ENABLED is the master kill switch. At 0, every log macro expands to
 *     nothing -- arguments are not even evaluated, no strings are emitted, no
 *     code is generated. This is how the entire facility vanishes in release.
 *   - SQLOG_COMPILE_LEVEL is the per-severity compile gate. Any level below it
 *     is compiled out the same way, individually. So a release build can keep
 *     ERROR/FATAL while discarding TRACE..WARN, purely at compile time.
 */
#ifndef SQLOG_CONFIG_H
#define SQLOG_CONFIG_H

/* --- Severity scale (ascending). Lower = finer/more verbose. ---------------
 * These are plain integers so they work in #if. SQLOG_LEVEL_OFF is a threshold
 * sentinel only; nothing is ever logged "at" OFF. */
#define SQLOG_LEVEL_TRACE 0   /* finest: call entry/exit, per-iteration spew   */
#define SQLOG_LEVEL_VERBOSE 1 /* detailed flow worth seeing when digging       */
#define SQLOG_LEVEL_DEBUG 2   /* developer diagnostics                         */
#define SQLOG_LEVEL_INFO 3    /* normal, expected milestones                   */
#define SQLOG_LEVEL_WARN 4    /* something is off but handled                  */
#define SQLOG_LEVEL_ERROR 5   /* an operation failed                           */
#define SQLOG_LEVEL_FATAL 6   /* unrecoverable; the process is going down      */
#define SQLOG_LEVEL_OFF 7     /* threshold meaning "log nothing"              */

/* --- Master switch ---------------------------------------------------------
 * Default: off in release (NDEBUG), on otherwise. Force either way with -D. */
#ifndef SQLOG_ENABLED
#if defined(NDEBUG)
#define SQLOG_ENABLED 0
#else
#define SQLOG_ENABLED 1
#endif
#endif

/* --- Per-severity compile gate --------------------------------------------- */
#ifndef SQLOG_COMPILE_LEVEL
#define SQLOG_COMPILE_LEVEL SQLOG_LEVEL_TRACE
#endif

/* A level is compiled in iff the master switch is on AND it meets the gate.
 * Both operands are integer constants, so this folds away in the preprocessor
 * and in constant-expression contexts alike. */
#define SQLOG_COMPILED(level) (SQLOG_ENABLED && ((level) >= (SQLOG_COMPILE_LEVEL)))

/* --- Whether FATAL still aborts when logging is compiled out ----------------
 * A fatal condition should stop the program regardless of whether the *message*
 * survives the build. Set to 0 only if you truly want FATAL to be inert. */
#ifndef SQLOG_FATAL_ABORTS
#define SQLOG_FATAL_ABORTS 1
#endif

/* --- Built-in sinks (compile-time presence) -------------------------------- */
#ifndef SQLOG_SINK_DEBUGGER /* OutputDebugString -> attached debugger  */
#define SQLOG_SINK_DEBUGGER 1
#endif
#ifndef SQLOG_SINK_CONSOLE /* WriteFile -> std handle, colorized       */
#define SQLOG_SINK_CONSOLE 1
#endif
#ifndef SQLOG_SINK_FILE /* WriteFile -> opened log file             */
#define SQLOG_SINK_FILE 1
#endif

/* --- Console colorization (SetConsoleTextAttribute per level) --------------- */
#ifndef SQLOG_CONSOLE_COLOR
#define SQLOG_CONSOLE_COLOR 1
#endif

/* --- Window logging --------------------------------------------------------
 * Presence is decided by two switches, per the requirement:
 *   1. GUI-mode detection: a GUI build is expected to define SQLOG_GUI (or the
 *      MSVC-style _WINDOWS). With MinGW there is no implicit GUI macro, so a
 *      /SUBSYSTEM:WINDOWS build should pass -DSQLOG_GUI=1 alongside -mwindows.
 *   2. The explicit control macro SQLOG_WINDOW, which, if defined, overrides the
 *      detection entirely (force the sink on in a console build, or off in a GUI
 *      build). */
#if !defined(SQLOG_WINDOW)
#if defined(SQLOG_GUI) || defined(_WINDOWS)
#define SQLOG_WINDOW 1
#else
#define SQLOG_WINDOW 0
#endif
#endif

/* The window sink's own compile-time default threshold. This is the knob the
 * requirement calls out: "log every statement" (set to SQLOG_LEVEL_TRACE),
 * "just errors" (SQLOG_LEVEL_ERROR), or "anything north of <level>". It is also
 * adjustable at runtime via sqlog_window_set_level(). */
#ifndef SQLOG_WINDOW_MIN_LEVEL
#define SQLOG_WINDOW_MIN_LEVEL SQLOG_LEVEL_INFO
#endif

/* --- Formatting buffer size (one line) ------------------------------------- */
#ifndef SQLOG_LINE_MAX
#define SQLOG_LINE_MAX 2048
#endif

#endif /* SQLOG_CONFIG_H */
