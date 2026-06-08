#include "sq_linker.h"

struct sq_unicode_string {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct sq_peb_ldr_data {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct sq_ldr_data_table_entry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    struct sq_unicode_string FullDllName;
    struct sq_unicode_string BaseDllName;
};

struct sq_peb {
    BYTE Reserved1[12];
    struct sq_peb_ldr_data *Ldr;
};

static struct sq_peb *SqGetPeb(void) {
    struct sq_peb *peb;

    __asm__ __volatile__(
        "movl %%fs:0x30, %0"
        : "=r"(peb));

    return peb;
}

static WCHAR SqUpperW(WCHAR value) {
    if (value >= L'a' && value <= L'z') {
        return (WCHAR)(value - (L'a' - L'A'));
    }

    return value;
}

static int SqUnicodeStringEqualsLiteral(
    const struct sq_unicode_string *left,
    LPCWSTR right) {
    USHORT index;
    USHORT right_length;

    if (left == SQ_NULL || right == SQ_NULL || left->Buffer == SQ_NULL) {
        return 0;
    }

    for (right_length = 0; right[right_length] != L'\0'; right_length++) {
    }

    if (left->Length != right_length * (USHORT)sizeof(WCHAR)) {
        return 0;
    }

    for (index = 0; index < right_length; index++) {
        if (SqUpperW(left->Buffer[index]) != SqUpperW(right[index])) {
            return 0;
        }
    }

    return 1;
}

static enum sq_status SqFindLoadedModule(
    LPCWSTR module_name,
    HMODULE *module) {
    struct sq_peb *peb;
    LIST_ENTRY *head;
    LIST_ENTRY *entry;

    if (module_name == SQ_NULL || module == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    *module = SQ_NULL;
    peb = SqGetPeb();
    if (peb == SQ_NULL || peb->Ldr == SQ_NULL) {
        return SqStatusNotFound;
    }

    head = &peb->Ldr->InLoadOrderModuleList;
    for (entry = head->Flink; entry != head && entry != SQ_NULL; entry = entry->Flink) {
        struct sq_ldr_data_table_entry *module_entry;

        module_entry = (struct sq_ldr_data_table_entry *)entry;
        if (SqUnicodeStringEqualsLiteral(&module_entry->BaseDllName, module_name)) {
            *module = (HMODULE)module_entry->DllBase;
            return SqStatusSuccess;
        }
    }

    return SqStatusNotFound;
}

static int SqAsciiEquals(LPCSTR left, LPCSTR right) {
    if (left == SQ_NULL || right == SQ_NULL) {
        return 0;
    }

    while (*left != '\0' && *right != '\0') {
        if (*left != *right) {
            return 0;
        }
        left++;
        right++;
    }

    return *left == '\0' && *right == '\0';
}

static enum sq_status SqResolveExport(
    HMODULE module,
    LPCSTR procedure_name,
    FARPROC *procedure) {
    BYTE *image;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *directory;
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names;
    WORD *ordinals;
    DWORD *functions;
    DWORD index;

    if (module == SQ_NULL || procedure_name == SQ_NULL || procedure == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    *procedure = SQ_NULL;
    image = (BYTE *)module;
    dos = (IMAGE_DOS_HEADER *)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return SqStatusInvalidParameter;
    }

    nt = (IMAGE_NT_HEADERS *)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return SqStatusInvalidParameter;
    }

    directory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        return SqStatusNotFound;
    }

    exports = (IMAGE_EXPORT_DIRECTORY *)(image + directory->VirtualAddress);
    names = (DWORD *)(image + exports->AddressOfNames);
    ordinals = (WORD *)(image + exports->AddressOfNameOrdinals);
    functions = (DWORD *)(image + exports->AddressOfFunctions);

    for (index = 0; index < exports->NumberOfNames; index++) {
        LPCSTR current_name;

        current_name = (LPCSTR)(image + names[index]);
        if (SqAsciiEquals(current_name, procedure_name)) {
            WORD ordinal;
            DWORD function_rva;

            ordinal = ordinals[index];
            if (ordinal >= exports->NumberOfFunctions) {
                return SqStatusInvalidParameter;
            }

            function_rva = functions[ordinal];
            if (function_rva == 0) {
                return SqStatusNotFound;
            }

            *procedure = (FARPROC)(image + function_rva);
            return SqStatusSuccess;
        }
    }

    return SqStatusNotFound;
}

enum sq_status SqLinkerInitialize(struct sq_linker *linker) {
    enum sq_status status;
    FARPROC procedure;

    if (linker == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(linker, (sq_u32)sizeof(*linker));

    status = SqFindLoadedModule(L"kernel32.dll", &linker->kernel32);
    if (status != SqStatusSuccess) {
        return status;
    }

    status = SqResolveExport(linker->kernel32, "LoadLibraryW", &procedure);
    if (status != SqStatusSuccess) {
        return status;
    }
    linker->LoadLibraryW = (sq_load_library_w)procedure;

    status = SqResolveExport(linker->kernel32, "GetProcAddress", &procedure);
    if (status != SqStatusSuccess) {
        return status;
    }
    linker->GetProcAddress = (sq_get_proc_address)procedure;

    return SqStatusSuccess;
}

enum sq_status SqLinkerResolve(
    struct sq_linker *linker,
    LPCWSTR module_name,
    LPCSTR procedure_name,
    FARPROC *procedure) {
    HMODULE module;

    if (linker == SQ_NULL || module_name == SQ_NULL || procedure_name == SQ_NULL || procedure == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (linker->LoadLibraryW == SQ_NULL || linker->GetProcAddress == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    *procedure = SQ_NULL;
    module = linker->LoadLibraryW(module_name);
    if (module == SQ_NULL) {
        return SqStatusNotFound;
    }

    *procedure = linker->GetProcAddress(module, procedure_name);
    if (*procedure == SQ_NULL) {
        return SqStatusNotFound;
    }

    return SqStatusSuccess;
}
