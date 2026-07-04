/* logdemo.c -- exercises the sqlog facility end to end.
 *
 * Built three ways by //examples (see BUILD.bazel):
 *   logdemo.exe          full debug build (all levels, console+debugger)
 *   logdemo_release.exe  -DNDEBUG: every log macro compiles out -> no log lines
 *   logdemo_window.exe   -DSQLOG_WINDOW=1: forces the GUI sink on (control macro)
 *
 * The banner lines are written with a direct WriteFile (NOT via sqlog) so that
 * even the fully-compiled-out release build still proves it ran -- it just
 * emits no log lines between the banners. */
#include "sqlog/sqlog.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <shlwapi.h>

static void banner(const wchar_t *text)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    char utf8[512];
    int n = 0;
    DWORD wrote = 0;

    if (h == NULL || h == INVALID_HANDLE_VALUE || text == NULL) {
        return;
    }
    n = WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, (int)sizeof utf8, NULL,
                            NULL);
    if (n > 1) { /* n includes the NUL terminator */
        (void)WriteFile(h, utf8, (DWORD)(n - 1), &wrote, NULL);
    }
}

/* A function that uses scope tracing: logs enter/leave automatically. */
static int do_work(int n)
{
    SQLOG_SCOPE(TEST);
    SQLOG_DEBUG(SQLOG_SUB_TEST, L"working on n=%d", n);
    return n * 2;
}

static void demo_levels(void)
{
    SQLOG_TRACE(SQLOG_SUB_TEST, L"trace: finest detail, value=%d", 1);
    SQLOG_VERBOSE(SQLOG_SUB_TEST, L"verbose: detailed flow");
    SQLOG_DEBUG(SQLOG_SUB_TEST, L"debug: developer diagnostics");
    SQLOG_INFO(SQLOG_SUB_TEST, L"info: a normal milestone");
    SQLOG_WARN(SQLOG_SUB_TEST, L"warn: something looks off");
    SQLOG_ERROR(SQLOG_SUB_TEST, L"error: an operation failed");
}

static void demo_filtering(void)
{
    sqlog_set_level(SQLOG_LEVEL_WARN);
    SQLOG_INFO(SQLOG_SUB_TEST, L"INFO at global=WARN -- should be HIDDEN");
    SQLOG_ERROR(SQLOG_SUB_TEST, L"ERROR at global=WARN -- should be SHOWN");
    sqlog_set_level(SQLOG_LEVEL_TRACE);

    /* Per-subsystem override: silence NET below ERROR, leave GENERAL alone. */
    sqlog_set_subsystem_level(SQLOG_SUB_NET, SQLOG_LEVEL_ERROR);
    SQLOG_DEBUG(SQLOG_SUB_NET, L"NET debug -- should be HIDDEN (override)");
    SQLOG_ERROR(SQLOG_SUB_NET, L"NET error -- should be SHOWN");
    SQLOG_DEBUG(SQLOG_SUB_GENERAL, L"GENERAL debug -- should be SHOWN");
    sqlog_set_subsystem_level(SQLOG_SUB_NET, -1); /* clear override */
}

static void demo_extras(void)
{
    unsigned char data[40];
    int i = 0;

    /* Decoded Win32 error logging. */
    SQLOG_WINERR(SQLOG_SUB_NET, ERROR, ERROR_FILE_NOT_FOUND,
                 L"open of config failed");

    /* Hex dump. */
    for (i = 0; i < (int)sizeof data; i++) {
        data[i] = (unsigned char)(i * 7);
    }
    SQLOG_HEXDUMP(SQLOG_SUB_TEST, DEBUG, L"sample buffer", data, sizeof data);
    (void)data; /* used only in the (possibly compiled-out) hexdump above */

    /* ONCE: prints a single time despite the loop. */
    for (i = 0; i < 3; i++) {
        SQLOG_ONCE(INFO, SQLOG_SUB_TEST, L"ONCE: i=%d (you should see this once)", i);
    }
    /* EVERY_N: fires on i = 0, 3, 6, 9. */
    for (i = 0; i < 10; i++) {
        SQLOG_EVERY_N(INFO, SQLOG_SUB_TEST, 3, L"EVERY_3: i=%d", i);
    }

    /* Scope tracing through a real call. We call do_work() into a local rather
     * than inside the log argument: a compiled-out log does not evaluate its
     * arguments, so do_work(21) passed directly would go uncalled in the release
     * build. This is the documented compile-out caveat in practice. */
    {
        int const r = do_work(21);
        SQLOG_INFO(SQLOG_SUB_TEST, L"do_work returned %d", r);
        (void)r; /* used only by the (possibly compiled-out) log above */
    }

    /* DCHECK that passes (no abort). */
    SQLOG_DCHECK(1 + 1 == 2, SQLOG_SUB_TEST, L"arithmetic still works");
}

int wmain(int argc, wchar_t **argv); /* -municode entry */

int wmain(int argc, wchar_t **argv)
{
    wchar_t cfg[256];
    int pos = 0;

    sqlog_init();

    banner(L">>> logdemo start\r\n");

    cfg[0] = L'\0';
    pos = wnsprintfW(cfg, (int)(sizeof cfg / sizeof cfg[0]),
                     L">>> build: SQLOG_ENABLED=%d COMPILE_LEVEL=%d WINDOW=%d\r\n",
                     (int)SQLOG_ENABLED, (int)SQLOG_COMPILE_LEVEL,
                     (int)SQLOG_WINDOW);
    (void)pos;
    banner(cfg);

    /* Trigger a real FATAL (and process abort) only on explicit request, so the
     * normal run can demonstrate everything else without dying. */
    if (argc > 1 && lstrcmpW(argv[1], L"fatal") == 0) {
        SQLOG_FATAL(SQLOG_SUB_TEST, L"explicit fatal requested; aborting");
        banner(L">>> UNREACHABLE after FATAL\r\n"); /* must not print */
        return 0;
    }

#if SQLOG_WINDOW
    sqlog_window_set_level(SQLOG_LEVEL_TRACE); /* show everything in the window */
    sqlog_window_start();
    banner(sqlog_window_active() ? L">>> window sink: ACTIVE\r\n"
                                 : L">>> window sink: inactive (no window station)\r\n");
#endif

    demo_levels();
    demo_filtering();
    demo_extras();

#if SQLOG_WINDOW
    /* Give the async UI thread a moment to drain, then tear it down. */
    Sleep(300);
    sqlog_window_stop();
#endif

    sqlog_shutdown();
    banner(L">>> logdemo end\r\n");
    return 0;
}
