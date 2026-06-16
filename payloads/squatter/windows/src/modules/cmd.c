#include "modules/cmd.h"

#include "base/win.h"
#include "modules/process_io.h"
#include "runtime/module_wire.h"
#include "wire/control_codec.h"

enum
{
        SQ_CMD_LINE_MAX = 8192,
        SQ_CMD_AUTO_INTERACTIVE_MS = 1000,
        SQ_CMD_SHUTDOWN_MS = 5000
};

static BOOL append_wide(wchar_t *dst, int *pos, int cap, const wchar_t *src)
{
        int i = 0;

        if (dst == NULL || pos == NULL || src == NULL || cap <= 0)
        {
                return FALSE;
        }
        while (src[i] != L'\0')
        {
                if (*pos >= cap - 1)
                {
                        dst[*pos] = L'\0';
                        return FALSE;
                }
                dst[*pos] = src[i];
                (*pos)++;
                i++;
        }
        dst[*pos] = L'\0';
        return TRUE;
}

static BOOL arg_equal(const wchar_t *a, const wchar_t *b)
{
        int i = 0;

        if (a == NULL || b == NULL)
        {
                return FALSE;
        }
        while (a[i] != L'\0' && b[i] != L'\0')
        {
                if (a[i] != b[i])
                {
                        return FALSE;
                }
                i++;
        }
        return a[i] == b[i];
}

static BOOL arg_is_interactive(const wchar_t *arg)
{
        return arg_equal(arg, L"--interactive") || arg_equal(arg, L"-i");
}

static BOOL arg_is_runtime_flag(const wchar_t *arg)
{
        return arg_is_interactive(arg) || arg_equal(arg, L"--debug");
}

static BOOL has_arg(int argc, wchar_t **argv, const wchar_t *want)
{
        int i = 0;

        for (i = 1; i < argc; i++)
        {
                if (arg_equal(argv[i], want))
                {
                        return TRUE;
                }
        }
        return FALSE;
}

static BOOL debug_requested(int argc, wchar_t **argv)
{
        return has_arg(argc, argv, L"--debug");
}

static int first_command_arg(int argc, wchar_t **argv)
{
        int i = 0;

        for (i = 1; i < argc; i++)
        {
                if (!arg_is_runtime_flag(argv[i]))
                {
                        return i;
                }
        }
        return 0;
}

static BOOL interactive_requested(int argc, wchar_t **argv)
{
        if (first_command_arg(argc, argv) == 0)
        {
                return TRUE;
        }
        return has_arg(argc, argv, L"--interactive") || has_arg(argc, argv, L"-i");
}

static BOOL append_command_args(int argc, wchar_t **argv, wchar_t *out, int *pos, int cap)
{
        int i = first_command_arg(argc, argv);
        BOOL need_space = FALSE;

        while (i > 0 && i < argc)
        {
                if (!arg_is_runtime_flag(argv[i]))
                {
                        if (need_space && !append_wide(out, pos, cap, L" "))
                        {
                                return FALSE;
                        }
                        if (!append_wide(out, pos, cap, argv[i] != NULL ? argv[i] : L""))
                        {
                                return FALSE;
                        }
                        need_space = TRUE;
                }
                i++;
        }
        return need_space;
}

static BOOL build_prefixed_command_line(int argc, wchar_t **argv, const wchar_t *prefix, wchar_t *out, int cap)
{
        int pos = 0;

        out[0] = L'\0';
        if (!append_wide(out, &pos, cap, prefix))
        {
                return FALSE;
        }
        return append_command_args(argc, argv, out, &pos, cap);
}

static BOOL build_command_line(int argc, wchar_t **argv, BOOL interactive, wchar_t *out, int cap)
{
        int pos = 0;

        if (out == NULL || cap <= 0)
        {
                return FALSE;
        }
        if (interactive && first_command_arg(argc, argv) == 0)
        {
                out[0] = L'\0';
                return append_wide(out, &pos, cap, L"cmd.exe /K");
        }
        if (interactive)
        {
                return build_prefixed_command_line(argc, argv, L"cmd.exe /K ", out, cap);
        }
        return build_prefixed_command_line(argc, argv, L"cmd.exe /C ", out, cap);
}

static void write_cmd_error(HANDLE output, DWORD code, const char *message)
{
        (void)sq_module_write_control(output, SQMUX_EVENT_ERROR, code, message);
}

int sq_cmd_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv)
{
        sq_process_spec spec;
        wchar_t command_line[SQ_CMD_LINE_MAX];
        BOOL interactive = interactive_requested(argc, argv);

        if (!build_command_line(argc, argv, interactive, command_line,
                                (int)(sizeof command_line / sizeof command_line[0])))
        {
                write_cmd_error(output, 0, "usage: cmd [--interactive] [--debug] <command...>");
                return 1;
        }

        ZeroMemory(&spec, sizeof spec);
        spec.command_line = command_line;
        spec.module_input = input;
        spec.module_output = output;
        spec.interactive = interactive;
        spec.debug = debug_requested(argc, argv);
        spec.auto_interactive_ms = SQ_CMD_AUTO_INTERACTIVE_MS;
        spec.shutdown_ms = SQ_CMD_SHUTDOWN_MS;
        return sq_process_run(&spec);
}
