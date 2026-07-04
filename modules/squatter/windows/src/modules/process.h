#ifndef SQ_MODULES_PROCESS_H
#define SQ_MODULES_PROCESS_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        int sq_process_list_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_process_run_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_process_run_as_user_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_process_kill_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_PROCESS_H */
