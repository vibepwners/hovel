/* process_io.h -- generic child-process streaming for modules.
 *
 * A process module supplies a command line and the module packet pipes. The
 * helper owns the WinAPI plumbing: child stdin/stdout/stderr handles, overlapped
 * I/O, output draining, process wait, and lifecycle control events.
 */
#ifndef SQ_MODULES_PROCESS_IO_H
#define SQ_MODULES_PROCESS_IO_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        typedef struct sq_process_spec
        {
                const wchar_t *command_line;
                HANDLE module_input;
                HANDLE module_output;
                BOOL interactive;
                BOOL debug;
                DWORD auto_interactive_ms;
                DWORD shutdown_ms;
        } sq_process_spec;

        int sq_process_run(const sq_process_spec *spec);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_PROCESS_IO_H */
