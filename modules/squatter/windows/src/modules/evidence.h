#ifndef SQ_MODULES_EVIDENCE_H
#define SQ_MODULES_EVIDENCE_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        int sq_file_stat_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_registry_query_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_eventlog_query_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_drive_list_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_share_list_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);
        int sq_acl_stat_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MODULES_EVIDENCE_H */
