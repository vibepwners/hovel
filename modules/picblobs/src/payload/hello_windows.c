/*
 * "Hello, world!" payload for Windows — minimal PIC blob using TEB walk.
 *
 * Resolves GetStdHandle, WriteFile, and ExitProcess from kernel32.dll
 * via PEB/TEB walk with DJB2 hash-based function resolution. No imports,
 * no IAT, no static linking to any Windows library.
 */

#include "picblobs/os/windows.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/resolve.h"

/* DJB2 hashes — precomputed at build time (REQ-006). */
#define HASH_KERNEL32_DLL 0x7040EE75   /* djb2("kernel32.dll") lowercase */
#define HASH_GET_STD_HANDLE 0xF178843C /* djb2("GetStdHandle") */
#define HASH_WRITE_FILE 0x663CECB0     /* djb2("WriteFile") */
#define HASH_EXIT_PROCESS 0xB769339E   /* djb2("ExitProcess") */

/* Windows constants. */
#define STD_OUTPUT_HANDLE ((unsigned long)-11)

/* Windows API function pointer types. */
typedef void *(PIC_WINAPI *fn_GetStdHandle)(unsigned long nStdHandle);
typedef int(PIC_WINAPI *fn_WriteFile)(void *hFile, const void *lpBuffer,
	unsigned long nNumberOfBytesToWrite,
	unsigned long *lpNumberOfBytesWritten, void *lpOverlapped);
typedef void(PIC_WINAPI *fn_ExitProcess)(unsigned int uExitCode);

PIC_RODATA
static const char msg[] = "Hello, world!\n";

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
static int write_stdout(fn_GetStdHandle pGetStdHandle, fn_WriteFile pWriteFile)
{
	void *stdout_handle = PIC_NULL;
	unsigned long written = 0;
	int write_status = 0;

	stdout_handle = pGetStdHandle(STD_OUTPUT_HANDLE);
	if (((void *)-1 == stdout_handle) || (PIC_NULL == stdout_handle)) {
		return 0;
	}

	write_status = pWriteFile(
		stdout_handle, msg, sizeof(msg) - 1U, &written, PIC_NULL);
	if (0 == write_status) {
		return 0;
	}

	if (written != (sizeof(msg) - 1U)) {
		return 0;
	}

	return 1;
}

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	/* Resolve kernel32.dll functions via TEB → PEB → export table. */
	fn_GetStdHandle pGetStdHandle = (fn_GetStdHandle)pic_resolve(
		HASH_KERNEL32_DLL, HASH_GET_STD_HANDLE);
	fn_WriteFile pWriteFile =
		(fn_WriteFile)pic_resolve(HASH_KERNEL32_DLL, HASH_WRITE_FILE);
	fn_ExitProcess pExitProcess = (fn_ExitProcess)pic_resolve(
		HASH_KERNEL32_DLL, HASH_EXIT_PROCESS);

	if (!pGetStdHandle || !pWriteFile || !pExitProcess) {
		fail_fast();
	}

	if (0 == write_stdout(pGetStdHandle, pWriteFile)) {
		exit_process(pExitProcess, 1);
	}

	exit_process(pExitProcess, 0);
}
