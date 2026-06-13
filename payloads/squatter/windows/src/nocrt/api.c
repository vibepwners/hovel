#include "nocrt/api.h"

typedef struct _UNICODE_STRING_X {
	WORD Length;
	WORD MaximumLength;
	WCHAR *Buffer;
} UNICODE_STRING_X;

typedef struct _LIST_ENTRY_X {
	struct _LIST_ENTRY_X *Flink;
	struct _LIST_ENTRY_X *Blink;
} LIST_ENTRY_X;

typedef struct _PEB_LDR_DATA_X {
	DWORD Length;
	BOOL Initialized;
	void *SsHandle;
	LIST_ENTRY_X InLoadOrderModuleList;
	LIST_ENTRY_X InMemoryOrderModuleList;
	LIST_ENTRY_X InInitializationOrderModuleList;
} PEB_LDR_DATA_X;

typedef struct _LDR_DATA_TABLE_ENTRY_X {
	LIST_ENTRY_X InLoadOrderLinks;
	LIST_ENTRY_X InMemoryOrderLinks;
	LIST_ENTRY_X InInitializationOrderLinks;
	void *DllBase;
	void *EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING_X FullDllName;
	UNICODE_STRING_X BaseDllName;
} LDR_DATA_TABLE_ENTRY_X;

typedef struct _RTL_USER_PROCESS_PARAMETERS_X {
#ifdef _WIN64
	BYTE Reserved1[0x60];
#else
	BYTE Reserved1[0x38];
#endif
	UNICODE_STRING_X ImagePathName;
	UNICODE_STRING_X CommandLine;
} RTL_USER_PROCESS_PARAMETERS_X;

typedef struct _PEB_X {
#ifdef _WIN64
	BYTE Reserved1[0x18];
#else
	BYTE Reserved1[0x0c];
#endif
	PEB_LDR_DATA_X *Ldr;
	RTL_USER_PROCESS_PARAMETERS_X *ProcessParameters;
} PEB_X;

typedef struct _IMAGE_DOS_HEADER_X {
	WORD e_magic;
	WORD unused1[29];
	LONG e_lfanew;
} IMAGE_DOS_HEADER_X;

typedef struct _IMAGE_FILE_HEADER_X {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER_X;

typedef struct _IMAGE_DATA_DIRECTORY_X {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY_X;

typedef struct _IMAGE_OPTIONAL_HEADER32_X {
	WORD Magic;
#ifdef _WIN64
	BYTE ignored[110];
#else
	BYTE ignored[94];
#endif
	IMAGE_DATA_DIRECTORY_X DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32_X;

typedef struct _IMAGE_NT_HEADERS32_X {
	DWORD Signature;
	IMAGE_FILE_HEADER_X FileHeader;
	IMAGE_OPTIONAL_HEADER32_X OptionalHeader;
} IMAGE_NT_HEADERS32_X;

typedef struct _IMAGE_EXPORT_DIRECTORY_X {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions;
	DWORD NumberOfNames;
	DWORD AddressOfFunctions;
	DWORD AddressOfNames;
	DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_X;

typedef HMODULE (WINAPI *load_library_a_fn)(LPCSTR);

static PEB_X *peb(void)
{
	PEB_X *p = NULL;
#ifdef _WIN64
	__asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
#else
	__asm__ volatile("movl %%fs:0x30, %0" : "=r"(p));
#endif
	return p;
}

static int ascii_lower(int c)
{
	return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int ascii_equal(const char *a, const char *b)
{
	while (*a != '\0' && *b != '\0') {
		if (*a != *b) {
			return 0;
		}
		a++;
		b++;
	}
	return *a == *b;
}

static unsigned int ascii_len(const char *s)
{
	unsigned int n = 0;

	while (s[n] != '\0') {
		n++;
	}
	return n;
}

static int ascii_has_dll_suffix(const char *s)
{
	unsigned int n = ascii_len(s);

	if (n < 4) {
		return 0;
	}
	return ascii_lower((int)s[n - 4]) == '.' &&
	       ascii_lower((int)s[n - 3]) == 'd' &&
	       ascii_lower((int)s[n - 2]) == 'l' &&
	       ascii_lower((int)s[n - 1]) == 'l';
}

static int wide_ascii_dll_equal(const WCHAR *wide, WORD bytes, const char *ascii)
{
	unsigned int i = 0;
	unsigned int chars = (unsigned int)bytes / sizeof(WCHAR);

	for (i = 0; i < chars && ascii[i] != '\0'; i++) {
		if (ascii_lower((int)wide[i]) != ascii_lower((int)ascii[i])) {
			return 0;
		}
	}
	return i == chars && ascii[i] == '\0';
}

static void *find_loaded_module(const char *dll_name)
{
	PEB_X *p = peb();
	LIST_ENTRY_X *head = NULL;
	LIST_ENTRY_X *cur = NULL;

	if (p == NULL || p->Ldr == NULL) {
		return NULL;
	}
	head = &p->Ldr->InMemoryOrderModuleList;
	for (cur = head->Flink; cur != NULL && cur != head; cur = cur->Flink) {
		LDR_DATA_TABLE_ENTRY_X *entry =
			(LDR_DATA_TABLE_ENTRY_X *)((char *)cur - offsetof(LDR_DATA_TABLE_ENTRY_X, InMemoryOrderLinks));
		if (entry->BaseDllName.Buffer != NULL &&
		    wide_ascii_dll_equal(entry->BaseDllName.Buffer, entry->BaseDllName.Length, dll_name)) {
			return entry->DllBase;
		}
	}
	return NULL;
}

static void *resolve_forwarder(const char *forwarder)
{
	char dll[96];
	char api[128];
	unsigned int i = 0;
	unsigned int dot = 0;
	unsigned int dll_len = 0;
	unsigned int api_len = 0;

	while (forwarder[dot] != '\0' && forwarder[dot] != '.') {
		dot++;
	}
	if (forwarder[dot] != '.' || dot == 0) {
		return NULL;
	}
	for (i = 0; i < dot && i + 5 < sizeof dll; i++) {
		dll[i] = forwarder[i];
	}
	dll[i] = '\0';
	if (!ascii_has_dll_suffix(dll)) {
		dll_len = i;
		if (dll_len + 4 >= sizeof dll) {
			return NULL;
		}
		dll[dll_len++] = '.';
		dll[dll_len++] = 'd';
		dll[dll_len++] = 'l';
		dll[dll_len++] = 'l';
		dll[dll_len] = '\0';
	}
	for (i = dot + 1; forwarder[i] != '\0' && api_len + 1 < sizeof api; i++) {
		api[api_len++] = forwarder[i];
	}
	api[api_len] = '\0';
	if (api[0] == '\0' || api[0] == '#') {
		return NULL;
	}
	return sq_resolve_api(dll, api);
}

static void *export_from_module(void *module, const char *name)
{
	BYTE *base = (BYTE *)module;
	IMAGE_DOS_HEADER_X *dos = (IMAGE_DOS_HEADER_X *)base;
	IMAGE_NT_HEADERS32_X *nt = NULL;
	IMAGE_EXPORT_DIRECTORY_X *exp = NULL;
	DWORD *names = NULL;
	WORD *ordinals = NULL;
	DWORD *functions = NULL;
	DWORD i = 0;

	if (base == NULL || dos->e_magic != 0x5a4d) {
		return NULL;
	}
	nt = (IMAGE_NT_HEADERS32_X *)(base + dos->e_lfanew);
	if (nt->Signature != 0x00004550 || nt->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
		return NULL;
	}
	exp = (IMAGE_EXPORT_DIRECTORY_X *)(base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
	names = (DWORD *)(base + exp->AddressOfNames);
	ordinals = (WORD *)(base + exp->AddressOfNameOrdinals);
	functions = (DWORD *)(base + exp->AddressOfFunctions);
	for (i = 0; i < exp->NumberOfNames; i++) {
		const char *candidate = (const char *)(base + names[i]);
		if (ascii_equal(candidate, name)) {
			WORD ordinal = ordinals[i];
			DWORD function_rva = functions[ordinal];
			if (function_rva >= nt->OptionalHeader.DataDirectory[0].VirtualAddress &&
			    function_rva < nt->OptionalHeader.DataDirectory[0].VirtualAddress +
			                       nt->OptionalHeader.DataDirectory[0].Size) {
				return resolve_forwarder((const char *)(base + function_rva));
			}
			return base + function_rva;
		}
	}
	return NULL;
}

void *sq_try_resolve_api(const char *dll_name, const char *api_name)
{
	void *module = find_loaded_module(dll_name);
	void *addr = NULL;

	if (module == NULL) {
		void *kernel32 = find_loaded_module("kernel32.dll");
		union {
			void *addr;
			load_library_a_fn fn;
		} load_library_a = {0};
		load_library_a.addr = export_from_module(kernel32, "LoadLibraryA");
		if (load_library_a.fn != NULL) {
			module = load_library_a.fn(dll_name);
		}
	}
	addr = export_from_module(module, api_name);
	return addr;
}

void *sq_resolve_api(const char *dll_name, const char *api_name)
{
	void *addr = sq_try_resolve_api(dll_name, api_name);

	if (addr == NULL) {
		void *kernel32 = find_loaded_module("kernel32.dll");
		union {
			void *addr;
			void (WINAPI *fn)(UINT);
		} exit_process = {0};
		exit_process.addr = export_from_module(kernel32, "ExitProcess");
		if (exit_process.fn != NULL) {
			exit_process.fn(127);
		}
		for (;;) {
		}
	}
	return addr;
}
