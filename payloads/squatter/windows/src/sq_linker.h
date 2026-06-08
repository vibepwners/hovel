#ifndef SQUATTER_WINDOWS_SQ_LINKER_H_
#define SQUATTER_WINDOWS_SQ_LINKER_H_

#include <windows.h>

#include "squatter.h"

typedef HMODULE(WINAPI *sq_load_library_w)(LPCWSTR module_name);
typedef FARPROC(WINAPI *sq_get_proc_address)(HMODULE module, LPCSTR procedure_name);

struct sq_linker {
    HMODULE kernel32;
    sq_load_library_w LoadLibraryW;
    sq_get_proc_address GetProcAddress;
};

enum sq_status SqLinkerInitialize(struct sq_linker *linker);
enum sq_status SqLinkerResolve(
    struct sq_linker *linker,
    LPCWSTR module_name,
    LPCSTR procedure_name,
    FARPROC *procedure);

#endif
