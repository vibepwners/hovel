/* sqlog_window.h -- the GUI "window logging" sink.
 *
 * A dedicated UI thread owns a top-level window with a read-only multiline edit
 * control; log lines are handed to it asynchronously (PostMessage), so loggers
 * never block on the UI. Whether any of this exists is decided at compile time
 * by SQLOG_WINDOW (see sqlog_config.h): when it is 0 the functions below are
 * inline no-ops, so call sites need no #if of their own.
 */
#ifndef SQLOG_WINDOW_H
#define SQLOG_WINDOW_H

#include "sqlog/sqlog_config.h"

#include <stddef.h> /* wchar_t (a typedef in C; not the CRT) */

#if SQLOG_WINDOW

/* Spin up the UI thread and create the window. Best-effort: on a session with no
 * window station (a service, a headless CI box) creation fails and the sink
 * quietly stays inactive -- it never takes the process down with it. */
void sqlog_window_start(void);

/* Tear the window down and join the UI thread. Idempotent. */
void sqlog_window_stop(void);

/* Per-sink runtime threshold: only lines at or above this level reach the
 * window. Compile-time default is SQLOG_WINDOW_MIN_LEVEL. */
void sqlog_window_set_level(int level);

/* Nonzero once the window exists and is accepting lines. */
int sqlog_window_active(void);

/* Append one already-formatted (wide) line (called by the core dispatch). */
void sqlog_window_write(int level, const wchar_t *line);

#else /* !SQLOG_WINDOW: inline no-ops, zero footprint */

static inline void sqlog_window_start(void) { }
static inline void sqlog_window_stop(void) { }
static inline void sqlog_window_set_level(int level) { (void)level; }
static inline int  sqlog_window_active(void) { return 0; }
static inline void sqlog_window_write(int level, const wchar_t *line)
{
    (void)level;
    (void)line;
}

#endif /* SQLOG_WINDOW */

#endif /* SQLOG_WINDOW_H */
