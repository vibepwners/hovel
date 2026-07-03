#include "sqlog/sqlog_window.h"

/* Entire translation unit is empty unless the window sink is compiled in; the
 * inline no-op stubs in the header stand in for it otherwise. */
#if SQLOG_WINDOW

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>

#define WM_SQLOG_APPEND (WM_APP + 1)
#define WM_SQLOG_QUIT (WM_APP + 2)

#define SQLOG_WINDOW_CLASS L"SqLogWindowClass"
#define SQLOG_EDIT_TRIM_AT 60000 /* clear the edit control past this length */

/* All UTF-16: a Unicode window with a Unicode EDIT control. */
static volatile LONG w_level = (LONG)SQLOG_WINDOW_MIN_LEVEL;
static volatile LONG w_active = 0;
static HWND w_hwnd = NULL;
static HANDLE w_thread = NULL;
static HANDLE w_ready = NULL;
static HWND w_edit = NULL; /* UI-thread only */

static void edit_append(const wchar_t *text)
{
        int len = 0;

        if (w_edit == NULL || text == NULL)
        {
                return;
        }
        len = GetWindowTextLengthW(w_edit);
        if (len > SQLOG_EDIT_TRIM_AT)
        {
                SetWindowTextW(w_edit, L""); /* bounded memory: drop the backlog */
                len = 0;
        }
        (void)SendMessageW(w_edit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        (void)SendMessageW(w_edit, EM_REPLACESEL, (WPARAM)FALSE, (LPARAM)text);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
        switch (msg)
        {
        case WM_SIZE:
                if (w_edit != NULL)
                {
                        (void)MoveWindow(w_edit, 0, 0, LOWORD(lp), HIWORD(lp), TRUE);
                }
                return 0;
        case WM_SQLOG_APPEND: {
                wchar_t *line = (wchar_t *)lp;
                (void)wp;
                if (line != NULL)
                {
                        edit_append(line);
                        (void)HeapFree(GetProcessHeap(), 0, line);
                }
                return 0;
        }
        case WM_SQLOG_QUIT:
                (void)DestroyWindow(hwnd);
                return 0;
        case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        default:
                return DefWindowProcW(hwnd, msg, wp, lp);
        }
}

static int create_window(void)
{
        HINSTANCE inst = GetModuleHandleW(NULL);
        WNDCLASSEXW wc;
        HWND hwnd = NULL;

        ZeroMemory(&wc, sizeof wc);
        wc.cbSize = (UINT)sizeof wc;
        wc.lpfnWndProc = wndproc;
        wc.hInstance = inst;
        wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = SQLOG_WINDOW_CLASS;
        if (RegisterClassExW(&wc) == 0)
        {
                DWORD const err = GetLastError();
                if (err != ERROR_CLASS_ALREADY_EXISTS)
                {
                        return 0; /* no window station -> sink stays off */
                }
        }

        hwnd = CreateWindowExW(0, SQLOG_WINDOW_CLASS, L"sqlog", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT,
                               CW_USEDEFAULT, 900, 600, NULL, NULL, inst, NULL);
        if (hwnd == NULL)
        {
                return 0;
        }

        w_edit = CreateWindowExW(0, L"EDIT", NULL,
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY |
                                     ES_AUTOVSCROLL,
                                 0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)1, inst, NULL);
        if (w_edit == NULL)
        {
                (void)DestroyWindow(hwnd);
                return 0;
        }
        (void)SendMessageW(w_edit, EM_SETLIMITTEXT, (WPARAM)0x7FFFFFFE, 0);

        {
                RECT rc;
                if (GetClientRect(hwnd, &rc) != FALSE)
                {
                        (void)MoveWindow(w_edit, 0, 0, rc.right, rc.bottom, TRUE);
                }
        }
        w_hwnd = hwnd;
        return 1;
}

static DWORD WINAPI ui_thread(LPVOID param)
{
        int ok = 0;
        MSG msg;

        (void)param;
        ok = create_window();
        (void)InterlockedExchange(&w_active, ok ? 1 : 0);
        if (w_ready != NULL)
        {
                (void)SetEvent(w_ready);
        }
        if (ok == 0)
        {
                return 0;
        }

        ZeroMemory(&msg, sizeof msg);
        while (GetMessageW(&msg, NULL, 0, 0) > 0)
        {
                (void)TranslateMessage(&msg);
                (void)DispatchMessageW(&msg);
        }
        (void)InterlockedExchange(&w_active, 0);
        w_hwnd = NULL;
        return 0;
}

void sqlog_window_start(void)
{
        if (w_thread != NULL)
        {
                return;
        }
        w_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
        w_thread = CreateThread(NULL, 0, ui_thread, NULL, 0, NULL);
        if (w_thread == NULL)
        {
                if (w_ready != NULL)
                {
                        (void)CloseHandle(w_ready);
                        w_ready = NULL;
                }
                return;
        }
        if (w_ready != NULL)
        {
                (void)WaitForSingleObject(w_ready, 5000);
                (void)CloseHandle(w_ready);
                w_ready = NULL;
        }
}

void sqlog_window_stop(void)
{
        if (w_thread == NULL)
        {
                return;
        }
        if (w_hwnd != NULL)
        {
                (void)PostMessageW(w_hwnd, WM_SQLOG_QUIT, 0, 0);
        }
        (void)WaitForSingleObject(w_thread, 5000);
        (void)CloseHandle(w_thread);
        w_thread = NULL;
}

void sqlog_window_set_level(int level)
{
        (void)InterlockedExchange(&w_level, (LONG)level);
}

int sqlog_window_active(void)
{
        return (w_active != 0) ? 1 : 0;
}

void sqlog_window_write(int level, const wchar_t *line)
{
        wchar_t *copy = NULL;
        int n = 0;

        if (w_active == 0 || w_hwnd == NULL || line == NULL)
        {
                return;
        }
        if (level < (int)w_level)
        {
                return;
        }
        n = lstrlenW(line);
        copy = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(n + 1) * sizeof(wchar_t));
        if (copy == NULL)
        {
                return;
        }
        (void)lstrcpynW(copy, line, n + 1);
        if (PostMessageW(w_hwnd, WM_SQLOG_APPEND, (WPARAM)level, (LPARAM)copy) == FALSE)
        {
                (void)HeapFree(GetProcessHeap(), 0, copy);
        }
}

#endif /* SQLOG_WINDOW */
