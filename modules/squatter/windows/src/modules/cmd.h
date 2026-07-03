#ifndef SQ_MODULES_CMD_H
#define SQ_MODULES_CMD_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        int sq_cmd_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_CMD_H */
