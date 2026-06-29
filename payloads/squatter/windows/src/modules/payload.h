#ifndef SQ_MODULES_PAYLOAD_H
#define SQ_MODULES_PAYLOAD_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        int sq_payload_status_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_payload_cleanup_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_PAYLOAD_H */
