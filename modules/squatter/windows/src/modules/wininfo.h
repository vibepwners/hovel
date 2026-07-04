#ifndef SQ_MODULES_WININFO_H
#define SQ_MODULES_WININFO_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        int sq_wininfo_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_WININFO_H */
