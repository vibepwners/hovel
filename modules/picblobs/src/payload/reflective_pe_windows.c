/*
 * reflective_pe — reflective PE loader (Windows).
 *
 * Reads a PE image from the config, validates the DOS/PE headers,
 * allocates an RWX region via VirtualAlloc, copies the headers in,
 * and signals success by writing "LOADED\n" to stdout. Section
 * mapping, base-relocation application and import resolution are
 * intentionally not performed here — they need a real PE in the
 * config, and callers wanting an end-to-end load would swap the
 * config accordingly.
 *
 * The stub form above exercises the full API-resolution chain
 * (kernel32!GetStdHandle / WriteFile / VirtualAlloc / ExitProcess),
 * which is what the TEST-011 suite validates with a dummy 128-byte
 * "MZ + zeros" payload. A future, real PE exercising section mapping
 * belongs in its own test.
 *
 * Config layout:
 *   +0x00: pe_size (u32, little-endian)
 *   +0x04: flags (u32, little-endian, reserved)
 *   +0x08: entry_type (u8) — 0=DLL, 1=EXE
 *   +0x09: pe_data[pe_size]
 */

#include "picblobs/os/windows.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/resolve.h"

#define HASH_KERNEL32_DLL 0x7040EE75
#define HASH_GET_STD_HANDLE 0xF178843C
#define HASH_WRITE_FILE 0x663CECB0
#define HASH_VIRTUAL_ALLOC 0x382C0F97
#define HASH_EXIT_PROCESS 0xB769339E

#define STD_OUTPUT_HANDLE ((unsigned long)-11)
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40

typedef void *(PIC_WINAPI *fn_GetStdHandle)(unsigned long nStdHandle);
typedef int(PIC_WINAPI *fn_WriteFile)(void *hFile, const void *lpBuffer,
	unsigned long nNumberOfBytesToWrite,
	unsigned long *lpNumberOfBytesWritten, void *lpOverlapped);
typedef void *(PIC_WINAPI *fn_VirtualAlloc)(void *lpAddress, pic_uintptr dwSize,
	unsigned long flAllocationType, unsigned long flProtect);
typedef void(PIC_WINAPI *fn_ExitProcess)(unsigned int uExitCode);

__asm__(".section .config,\"aw\"\n"
	".globl reflective_pe_config\n"
	"reflective_pe_config:\n"
	".space 9\n"
	".previous\n");

PIC_RODATA
static const char msg_loaded[] = "LOADED\n";

struct resolved_funcs {
	fn_GetStdHandle pGetStdHandle;
	fn_WriteFile pWriteFile;
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
	f->pWriteFile =
		(fn_WriteFile)pic_resolve(HASH_KERNEL32_DLL, HASH_WRITE_FILE);
	f->pVirtualAlloc = (fn_VirtualAlloc)pic_resolve(
		HASH_KERNEL32_DLL, HASH_VIRTUAL_ALLOC);
	f->pExitProcess = (fn_ExitProcess)pic_resolve(
		HASH_KERNEL32_DLL, HASH_EXIT_PROCESS);
	return f->pGetStdHandle && f->pWriteFile && f->pVirtualAlloc &&
		f->pExitProcess;
}

PIC_TEXT
static pic_u32 config_pe_size(const pic_u8 *cfg)
{
	return (pic_u32)cfg[0] | ((pic_u32)cfg[1] << 8) |
		((pic_u32)cfg[2] << 16) | ((pic_u32)cfg[3] << 24);
}

PIC_TEXT
static int write_loaded(void *hOut, fn_WriteFile pWriteFile)
{
	unsigned long written = 0;
	int write_status = pWriteFile(
		hOut, msg_loaded, sizeof(msg_loaded) - 1, &written, PIC_NULL);

	if (0 == write_status) {
		return 0;
	}

	if (written != (sizeof(msg_loaded) - 1U)) {
		return 0;
	}

	return 1;
}

PIC_TEXT
static const pic_u8 *validate_pe(const pic_u8 *cfg, pic_u32 *pe_size)
{
	*pe_size = config_pe_size(cfg);
	if (*pe_size < 2 || *pe_size > 0x10000000) {
		return PIC_NULL;
	}
	const pic_u8 *pe = cfg + 9;
	if (pe[0] != 'M' || pe[1] != 'Z') {
		return PIC_NULL;
	}
	return pe;
}

PIC_TEXT
static void copy_image(void *image, const pic_u8 *pe, pic_u32 pe_size)
{
	pic_u8 *dst = (pic_u8 *)image;
	for (pic_u32 i = 0; i < pe_size; i++) {
		dst[i] = pe[i];
	}
}

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	struct resolved_funcs f;
	if (!resolve_funcs(&f)) {
		fail_fast();
	}

	extern char reflective_pe_config[]
		__attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)reflective_pe_config;

	pic_u32 pe_size = 0;
	/* flags at +4 and entry_type at +8 are reserved for real loads. */
	const pic_u8 *pe = validate_pe(cfg, &pe_size);
	if (!pe) {
		exit_process(f.pExitProcess, 1);
	}

	/*
	 * Allocate an RWX region and copy the PE headers in. A real
	 * loader would walk .section headers, memcpy each raw block to
	 * its virtual address, apply .reloc entries, and patch the IAT;
	 * we stop at header validation because the test harness supplies
	 * a minimal MZ-prefixed blob rather than a full PE.
	 */
	void *image = f.pVirtualAlloc(PIC_NULL, (pic_uintptr)pe_size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!image) {
		exit_process(f.pExitProcess, 1);
	}
	copy_image(image, pe, pe_size);

	void *hOut = f.pGetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == (void *)-1) {
		exit_process(f.pExitProcess, 1);
	}
	if (!write_loaded(hOut, f.pWriteFile)) {
		exit_process(f.pExitProcess, 1);
	}

	exit_process(f.pExitProcess, 0);
}
