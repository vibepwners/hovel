/*
 * Windows test runner — mock TEB/PEB environment on Linux.
 *
 * This runner is a cross-compiled freestanding Linux binary that
 * constructs a synthetic Windows environment (fake TEB, PEB, module
 * list, export tables with DJB2-matched function names) and then
 * executes a Windows-targeting blob within it.
 *
 * Two mock DLLs are exposed to the blob via the LDR module list:
 *
 *   kernel32.dll
 *     - GetStdHandle, WriteFile, ReadFile
 *     - VirtualAlloc, CreateFileA, CloseHandle
 *     - ExitProcess
 *
 *   ws2_32.dll
 *     - WSAStartup, socket, connect, recv, closesocket
 *     - htons
 *
 * HANDLE values in this runner are just integer file descriptors cast
 * to void* — the mocks translate Windows-style API calls to the
 * equivalent Linux syscalls. INVALID_HANDLE_VALUE is represented as
 * (void*)-1 and SOCKET_ERROR is -1.
 *
 * Supports: x86_64, i686, aarch64.
 *
 * Usage: ./runner <blob.bin>
 */

#include "picblobs/net.h"
#include "picblobs/os/linux.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/connect.h"
#include "picblobs/sys/exit.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/lseek.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"
#include "picblobs/sys/socket.h"
#include "picblobs/sys/write.h"
#include "picblobs/syscall.h"
#include "picblobs/types.h"

#define RUNNER_ERROR 127

/*
 * PIC_WINAPI — mock functions must use the same calling convention
 * as the blobs that call them. On x86_64, blobs use ms_abi for
 * Windows API calls; on i686/aarch64 it's a no-op.
 */
#if defined(__x86_64__)
#define PIC_WINAPI __attribute__((ms_abi))
#else
#define PIC_WINAPI
#endif

/* ---------- Architecture-specific TEB base setup ---------- */

#if defined(__x86_64__)

#define __NR_arch_prctl 158
#define ARCH_SET_GS 0x1001

static long set_teb_base(void *teb)
{
	return pic_syscall2(__NR_arch_prctl, ARCH_SET_GS, (long)teb);
}

#elif defined(__i386__)

struct user_desc {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit : 1;
	unsigned int contents : 2;
	unsigned int read_exec_only : 1;
	unsigned int limit_in_pages : 1;
	unsigned int seg_not_present : 1;
	unsigned int useable : 1;
};

#define __NR_set_thread_area 243

static long set_teb_base(void *teb)
{
	struct user_desc desc;
	for (int i = 0; i < (int)sizeof(desc); i++) {
		((char *)&desc)[i] = 0;
	}
	desc.entry_number = (unsigned int)-1;
	desc.base_addr = (unsigned int)(unsigned long)teb;
	desc.limit = 0xfffff;
	desc.seg_32bit = 1;
	desc.limit_in_pages = 1;
	desc.useable = 1;

	long ret = pic_syscall1(__NR_set_thread_area, (long)&desc);
	if (ret < 0) {
		return ret;
	}

	unsigned short sel = (unsigned short)((desc.entry_number << 3) | 3);
	__asm__ volatile("mov %0, %%fs" : : "r"(sel));
	return 0;
}

#elif defined(__aarch64__)

static long set_teb_base(void *teb)
{
	__asm__ volatile("mov x18, %0" : : "r"(teb));
	return 0;
}

static void call_blob_with_teb(void *blob, void *teb)
{
	__asm__ volatile("mov x18, %0\n"
			 "blr %1\n"
		:
		: "r"(teb), "r"(blob)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		"x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
		"x30", "memory");
}

#else
#error "Windows runner: unsupported architecture"
#endif

#if !defined(__aarch64__)
static void call_blob_with_teb(void *blob, void *teb)
{
	(void)teb;
	((void (*)(void))blob)();
}
#endif

/* ---------- Mock Windows API implementations ---------- */

/*
 * Helper: a pic_u8 write-byte stream for building things like
 * UNICODE_STRING buffers without needing libc-style strcpy.
 */

/*
 * GetStdHandle returns pseudo-handles that our other mocks map back to
 * fds. Real Windows never returns NULL here, so using the fd value
 * directly (0 for stdin) would collide with the NULL-check convention
 * callers use. We bias by STD_HANDLE_BIAS so every standard handle is
 * non-zero, and mock_ReadFile / mock_WriteFile / mock_CloseHandle peel
 * the bias off again.
 */
#define STD_HANDLE_BIAS 0x80000000u
#define STD_HANDLE_MASK 0x7fffffffu

static int unwrap_handle(void *hFile)
{
	pic_uintptr v = (pic_uintptr)hFile;
	if (0U != (v & STD_HANDLE_BIAS)) {
		return (int)(v & STD_HANDLE_MASK);
	}
	return (int)v;
}

static void *mock_GetStdHandle(unsigned long nStdHandle)
{
	if (nStdHandle == (unsigned long)-10) {
		return (void *)(pic_uintptr)(STD_HANDLE_BIAS | 0u); /* stdin */
	}
	if (nStdHandle == (unsigned long)-11) {
		return (void *)(pic_uintptr)(STD_HANDLE_BIAS | 1u); /* stdout */
	}
	if (nStdHandle == (unsigned long)-12) {
		return (void *)(pic_uintptr)(STD_HANDLE_BIAS | 2u); /* stderr */
	}
	return (void *)-1; /* INVALID_HANDLE_VALUE */
}

static void *mock_VirtualAlloc(void *lpAddress, pic_uintptr dwSize,
	unsigned long flAllocationType, unsigned long flProtect)
{
	(void)lpAddress;
	(void)flAllocationType;

	int prot = PIC_PROT_READ | PIC_PROT_WRITE;
	/* PAGE_EXECUTE=0x10, PAGE_EXECUTE_READ=0x20,
	 * PAGE_EXECUTE_READWRITE=0x40 */
	if ((0x10UL == flProtect) || (0x20UL == flProtect) ||
		(0x40UL == flProtect)) {
		prot |= PIC_PROT_EXEC;
	}

	void *mem = pic_mmap(PIC_NULL, (pic_size_t)dwSize, prot,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)mem == -1) {
		return PIC_NULL;
	}
	return mem;
}

static int mock_WriteFile(void *hFile, const void *lpBuffer,
	unsigned long nNumberOfBytesToWrite,
	unsigned long *lpNumberOfBytesWritten, void *lpOverlapped)
{
	(void)lpOverlapped;
	long ret = pic_write(unwrap_handle(hFile), lpBuffer,
		(pic_size_t)nNumberOfBytesToWrite);
	if (ret < 0) {
		if (PIC_NULL != lpNumberOfBytesWritten) {
			*lpNumberOfBytesWritten = 0;
		}
		return 0;
	}
	if (PIC_NULL != lpNumberOfBytesWritten) {
		*lpNumberOfBytesWritten = (unsigned long)ret;
	}
	return 1;
}

static int mock_ReadFile(void *hFile, void *lpBuffer,
	unsigned long nNumberOfBytesToRead, unsigned long *lpNumberOfBytesRead,
	void *lpOverlapped)
{
	(void)lpOverlapped;
	long ret = pic_read(unwrap_handle(hFile), lpBuffer,
		(pic_size_t)nNumberOfBytesToRead);
	if (ret < 0) {
		if (PIC_NULL != lpNumberOfBytesRead) {
			*lpNumberOfBytesRead = 0;
		}
		return 0;
	}
	if (PIC_NULL != lpNumberOfBytesRead) {
		*lpNumberOfBytesRead = (unsigned long)ret;
	}
	return 1;
}

/*
 * CreateFileA — opens a file. We honor the three common desired-access
 * combinations that blobs need: GENERIC_READ, GENERIC_WRITE, and both.
 */
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define OPEN_EXISTING 3u

static void *mock_CreateFileA(const char *lpFileName,
	unsigned long dwDesiredAccess, unsigned long dwShareMode,
	void *lpSecurityAttributes, unsigned long dwCreationDisposition,
	unsigned long dwFlagsAndAttributes, void *hTemplateFile)
{
	(void)dwShareMode;
	(void)lpSecurityAttributes;
	(void)dwCreationDisposition;
	(void)dwFlagsAndAttributes;
	(void)hTemplateFile;

	int flags = PIC_O_RDONLY;
	if ((dwDesiredAccess & GENERIC_WRITE) &&
		(dwDesiredAccess & GENERIC_READ)) {
		flags = 2; /* O_RDWR */
	} else if (dwDesiredAccess & GENERIC_WRITE) {
		flags = 1; /* O_WRONLY */
	}

	long fd = pic_open(lpFileName, flags, 0);
	if (fd < 0) {
		return (void *)-1; /* INVALID_HANDLE_VALUE */
	}
	return (void *)(pic_uintptr)fd;
}

static int mock_CloseHandle(void *hObject)
{
	pic_uintptr v = (pic_uintptr)hObject;
	long close_status = 0;

	if (0U != (v & STD_HANDLE_BIAS)) {
		return 1; /* pseudo-handle — never close stdio fds */
	}
	int fd = (int)v;
	if (2 >= fd) {
		return 1;
	}
	close_status = pic_close(fd);
	if (0 == close_status) {
		return 1;
	}
	return 0;
}

static void mock_ExitProcess(unsigned int uExitCode)
{
	pic_exit_group((int)uExitCode);
}

/* ---------- Mock ws2_32.dll implementations ---------- */

static int mock_WSAStartup(unsigned short wVersionRequested, void *lpWSAData)
{
	(void)wVersionRequested;
	if (lpWSAData) {
		/*
		 * Zero out the first 400-odd bytes of WSADATA — blobs rarely
		 * read it but they may. 408 is the x86_64 struct size; smaller
		 * ABIs are fine since we only write the prefix.
		 */
		pic_u8 *p = (pic_u8 *)lpWSAData;
		for (int i = 0; i < 408; i++) {
			p[i] = 0;
		}
	}
	return 0;
}

static pic_uintptr mock_socket(int af, int type, int protocol)
{
	long fd = pic_socket(af, type, protocol);
	if (fd < 0) {
		return (pic_uintptr)-1; /* INVALID_SOCKET */
	}
	return (pic_uintptr)fd;
}

static int mock_connect(pic_uintptr s, const void *name, int namelen)
{
	long ret = pic_connect((int)s, name, (pic_size_t)namelen);
	return ret < 0 ? -1 : 0;
}

static int mock_recv(pic_uintptr s, void *buf, int len, int flags)
{
	(void)flags;
	long ret = pic_read((int)s, buf, (pic_size_t)len);
	return ret < 0 ? -1 : (int)ret;
}

static int mock_closesocket(pic_uintptr s)
{
	long ret = pic_close((int)s);
	return ret < 0 ? -1 : 0;
}

/*
 * htons is normally resolved through the import table but PIC blobs
 * just do the byte swap inline. Provide it anyway so any blob that
 * does go through resolution gets a correct implementation.
 */
static unsigned short mock_htons(unsigned short hostshort)
{
	return (unsigned short)((hostshort >> 8) | (hostshort << 8));
}

/* ---------- Mock PE image builder ---------- */

/*
 * Each mock PE is a single 4 KiB page with a minimal DOS header, PE/COFF
 * header, export directory, name strings, function table, ordinals, and
 * a block of per-export trampolines that jump to the mock implementations.
 *
 * The layout is identical for kernel32.dll and ws2_32.dll; only the
 * export names and trampoline targets differ.
 */

#define MOCK_PE_SIZE 4096
#define PE_SIG_OFFSET 0x80
#define OPT_HDR_OFFSET 0x98
#define EXPORT_DIR_OFF 0x200
#define NAME_STR_OFF 0x400
#define FUNC_TBL_OFF 0x600
#define NAME_TBL_OFF 0x700
#define ORD_TBL_OFF 0x800
#define TRAMP_OFF 0x900
#define MAX_EXPORTS 16

static void pe_write32(pic_u8 *base, int offset, pic_u32 val)
{
	base[offset + 0] = (pic_u8)(val);
	base[offset + 1] = (pic_u8)(val >> 8);
	base[offset + 2] = (pic_u8)(val >> 16);
	base[offset + 3] = (pic_u8)(val >> 24);
}

static void pe_write16(pic_u8 *base, int offset, pic_u16 val)
{
	base[offset + 0] = (pic_u8)(val);
	base[offset + 1] = (pic_u8)(val >> 8);
}

static int pe_write_str(pic_u8 *base, int offset, const char *str)
{
	int i = 0;
	while (str[i]) {
		base[offset + i] = (pic_u8)str[i];
		i++;
	}
	base[offset + i] = 0;
	return i + 1;
}

/*
 * Write an architecture-specific trampoline that jumps to `target`.
 * Returns the number of bytes written.
 */
static int write_trampoline(pic_u8 *dest, void *target)
{
#if defined(__x86_64__)
	/*
	 * MS ABI → SysV ABI thunk for mock functions.
	 *
	 * The blob calls through ms_abi function pointers (rcx, rdx, r8, r9,
	 * [rsp+0x28]). The mock functions use SysV ABI (rdi, rsi, rdx, rcx,
	 * r8). This thunk translates the first five args and preserves
	 * rdi/rsi, which are non-volatile in MS ABI but volatile in SysV.
	 *
	 *   push rdi
	 *   push rsi
	 *   mov rdi, rcx
	 *   mov rsi, rdx
	 *   mov rdx, r8
	 *   mov rcx, r9
	 *   mov r8, [rsp+0x38]   ; 0x28 shadow + 0x08 ret + 0x08 two pushes
	 *   movabs rax, imm64
	 *   call rax
	 *   pop rsi
	 *   pop rdi
	 *   ret
	 */
	pic_u64 addr = (pic_u64)(pic_uintptr)target;
	int i = 0;
	dest[i++] = 0x57;
	dest[i++] = 0x56;
	dest[i++] = 0x48;
	dest[i++] = 0x89;
	dest[i++] = 0xcf;
	dest[i++] = 0x48;
	dest[i++] = 0x89;
	dest[i++] = 0xd6;
	dest[i++] = 0x4c;
	dest[i++] = 0x89;
	dest[i++] = 0xc2;
	dest[i++] = 0x4c;
	dest[i++] = 0x89;
	dest[i++] = 0xc9;
	dest[i++] = 0x4c;
	dest[i++] = 0x8b;
	dest[i++] = 0x44;
	dest[i++] = 0x24;
	dest[i++] = 0x38;
	dest[i++] = 0x48;
	dest[i++] = 0xb8;
	dest[i++] = (pic_u8)(addr);
	dest[i++] = (pic_u8)(addr >> 8);
	dest[i++] = (pic_u8)(addr >> 16);
	dest[i++] = (pic_u8)(addr >> 24);
	dest[i++] = (pic_u8)(addr >> 32);
	dest[i++] = (pic_u8)(addr >> 40);
	dest[i++] = (pic_u8)(addr >> 48);
	dest[i++] = (pic_u8)(addr >> 56);
	dest[i++] = 0xff;
	dest[i++] = 0xd0;
	dest[i++] = 0x5e;
	dest[i++] = 0x5f;
	dest[i++] = 0xc3;
	return i; /* 34 bytes */

#elif defined(__i386__)
	pic_u32 addr = (pic_u32)(pic_uintptr)target;
	dest[0] = 0xb8;
	dest[1] = (pic_u8)(addr);
	dest[2] = (pic_u8)(addr >> 8);
	dest[3] = (pic_u8)(addr >> 16);
	dest[4] = (pic_u8)(addr >> 24);
	dest[5] = 0xff;
	dest[6] = 0xe0;
	return 7;

#elif defined(__aarch64__)
	/*
	 * Windows AArch64 keeps the TEB pointer in x18, but the host-side mock
	 * functions are compiled for the Linux AArch64 ABI where x18 is not
	 * preserved for us. Call through a small thunk so Windows payloads keep
	 * a stable TEB across imports.
	 *
	 *   stp x18, x30, [sp, #-16]!
	 *   ldr x9, target
	 *   blr x9
	 *   ldp x18, x30, [sp], #16
	 *   ret
	 *   nop
	 * target:
	 *   .quad imm64
	 */
	pic_u64 addr = (pic_u64)(pic_uintptr)target;
	dest[0] = 0xf2;
	dest[1] = 0x7b;
	dest[2] = 0xbf;
	dest[3] = 0xa9;
	dest[4] = 0xa9;
	dest[5] = 0x00;
	dest[6] = 0x00;
	dest[7] = 0x58;
	dest[8] = 0x20;
	dest[9] = 0x01;
	dest[10] = 0x3f;
	dest[11] = 0xd6;
	dest[12] = 0xf2;
	dest[13] = 0x7b;
	dest[14] = 0xc1;
	dest[15] = 0xa8;
	dest[16] = 0xc0;
	dest[17] = 0x03;
	dest[18] = 0x5f;
	dest[19] = 0xd6;
	dest[20] = 0x1f;
	dest[21] = 0x20;
	dest[22] = 0x03;
	dest[23] = 0xd5;
	dest[24] = (pic_u8)(addr);
	dest[25] = (pic_u8)(addr >> 8);
	dest[26] = (pic_u8)(addr >> 16);
	dest[27] = (pic_u8)(addr >> 24);
	dest[28] = (pic_u8)(addr >> 32);
	dest[29] = (pic_u8)(addr >> 40);
	dest[30] = (pic_u8)(addr >> 48);
	dest[31] = (pic_u8)(addr >> 56);
	return 32;

#endif
}

/* Max trampoline size across all architectures. */
#define TRAMP_STRIDE 48

/*
 * Export record used when constructing a mock PE.
 * Exports must be listed in strict alphabetical order — Windows's
 * binary search of the name table requires it, and our blobs use the
 * same scan semantics.
 */
struct mock_export {
	const char *name;
	void *func;
};

static pic_u8 *build_mock_pe(const struct mock_export *exports, int n_exports)
{
	pic_u8 *pe = (pic_u8 *)pic_mmap(PIC_NULL, MOCK_PE_SIZE,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)pe == -1) {
		return PIC_NULL;
	}

	for (int i = 0; i < MOCK_PE_SIZE; i++) {
		pe[i] = 0;
	}

	/* DOS header: e_lfanew at +0x3C. */
	pe_write32(pe, 0x3C, PE_SIG_OFFSET);

	/* PE signature "PE\0\0". */
	pe[PE_SIG_OFFSET + 0] = 'P';
	pe[PE_SIG_OFFSET + 1] = 'E';

	/* COFF header: SizeOfOptionalHeader at PE_SIG+4+16. */
	pe_write16(pe, PE_SIG_OFFSET + 4 + 16, 0xF0);

	/* Optional header magic + DataDirectory[0] (export) RVA + size. */
#if PIC_ARCH_IS_32BIT
	pe_write16(pe, OPT_HDR_OFFSET, 0x010B); /* PE32 */
	pe_write32(pe, OPT_HDR_OFFSET + 0x60, EXPORT_DIR_OFF);
	pe_write32(pe, OPT_HDR_OFFSET + 0x64, 40);
#else
	pe_write16(pe, OPT_HDR_OFFSET, 0x020B); /* PE32+ */
	pe_write32(pe, OPT_HDR_OFFSET + 0x70, EXPORT_DIR_OFF);
	pe_write32(pe, OPT_HDR_OFFSET + 0x74, 40);
#endif

	/* Name strings (alphabetically sorted — caller's responsibility). */
	int name_offs[MAX_EXPORTS];
	int name_off = NAME_STR_OFF;
	for (int i = 0; i < n_exports; i++) {
		name_offs[i] = name_off;
		name_off += pe_write_str(pe, name_off, exports[i].name);
	}

	/* Trampolines. */
	int tramp_off = TRAMP_OFF;
	for (int i = 0; i < n_exports; i++) {
		write_trampoline(pe + tramp_off, exports[i].func);
		tramp_off += TRAMP_STRIDE;
	}

	/* Export directory header. */
	pe_write32(pe, EXPORT_DIR_OFF + 0x18, (pic_u32)n_exports);
	pe_write32(pe, EXPORT_DIR_OFF + 0x1C, FUNC_TBL_OFF);
	pe_write32(pe, EXPORT_DIR_OFF + 0x20, NAME_TBL_OFF);
	pe_write32(pe, EXPORT_DIR_OFF + 0x24, ORD_TBL_OFF);

	/* AddressOfFunctions / AddressOfNames / AddressOfNameOrdinals. */
	for (int i = 0; i < n_exports; i++) {
		pe_write32(pe, FUNC_TBL_OFF + i * 4,
			(pic_u32)(TRAMP_OFF + i * TRAMP_STRIDE));
		pe_write32(pe, NAME_TBL_OFF + i * 4, (pic_u32)name_offs[i]);
		pe_write16(pe, ORD_TBL_OFF + i * 2, (pic_u16)i);
	}

	return pe;
}

/* ---------- Mock TEB/PEB/LDR structures ---------- */

/*
 * Layout (4 KiB region):
 *   +0x000  TEB
 *   +0x100  PEB
 *   +0x200  PEB_LDR_DATA
 *   +0x300  LDR_DATA_TABLE_ENTRY for kernel32
 *   +0x500  LDR_DATA_TABLE_ENTRY for ws2_32
 *   +0x700  UTF-16 "kernel32.dll"
 *   +0x780  UTF-16 "ws2_32.dll"
 */
#define MOCK_REGION_SIZE 4096

#define TEB_OFF 0x000
#define PEB_OFF 0x100
#define LDR_OFF 0x200
#define ENTRY_K32_OFF 0x300
#define ENTRY_WS2_OFF 0x500
#define NAME_K32_OFF 0x700
#define NAME_WS2_OFF 0x780

static pic_u16 write_utf16le(pic_u8 *dest, const char *str)
{
	pic_size_t i = 0;
	while (str[i]) {
		dest[i * 2] = (pic_u8)str[i];
		dest[i * 2 + 1] = 0;
		i++;
	}
	return (pic_u16)(i * 2);
}

static void write_ptr(pic_u8 *base, int offset, void *ptr)
{
#if PIC_ARCH_IS_32BIT
	pic_u32 val = (pic_u32)(pic_uintptr)ptr;
	base[offset + 0] = (pic_u8)(val);
	base[offset + 1] = (pic_u8)(val >> 8);
	base[offset + 2] = (pic_u8)(val >> 16);
	base[offset + 3] = (pic_u8)(val >> 24);
#else
	pic_u64 val = (pic_u64)(pic_uintptr)ptr;
	base[offset + 0] = (pic_u8)(val);
	base[offset + 1] = (pic_u8)(val >> 8);
	base[offset + 2] = (pic_u8)(val >> 16);
	base[offset + 3] = (pic_u8)(val >> 24);
	base[offset + 4] = (pic_u8)(val >> 32);
	base[offset + 5] = (pic_u8)(val >> 40);
	base[offset + 6] = (pic_u8)(val >> 48);
	base[offset + 7] = (pic_u8)(val >> 56);
#endif
}

/*
 * Write a LDR_DATA_TABLE_ENTRY at *entry* with DllBase=pe_base and a
 * BaseDllName UNICODE_STRING pointing at *name_buf* (utf-16 string of
 * *name_bytes* bytes). Returns nothing; caller wires up list links.
 */
static void write_ldr_entry(
	pic_u8 *entry, void *pe_base, pic_u8 *name_buf, pic_u16 name_bytes)
{
#if PIC_ARCH_IS_32BIT
	write_ptr(entry, 0x10, pe_base);
	pic_u8 *ustr = entry + 0x24;
#else
	write_ptr(entry, 0x20, pe_base);
	pic_u8 *ustr = entry + 0x48;
#endif
	ustr[0] = (pic_u8)(name_bytes);
	ustr[1] = (pic_u8)(name_bytes >> 8);
	ustr[2] = (pic_u8)(name_bytes + 2);
	ustr[3] = 0;
#if PIC_ARCH_IS_32BIT
	write_ptr(ustr, 0x04, name_buf);
#else
	write_ptr(ustr, 0x08, name_buf);
#endif
}

static pic_u8 *build_mock_env(pic_u8 *pe_kernel32, pic_u8 *pe_ws2_32)
{
	pic_u8 *region = (pic_u8 *)pic_mmap(PIC_NULL, MOCK_REGION_SIZE,
		PIC_PROT_READ | PIC_PROT_WRITE,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)region == -1) {
		return PIC_NULL;
	}

	for (int i = 0; i < MOCK_REGION_SIZE; i++) {
		region[i] = 0;
	}

	pic_u8 *teb = region + TEB_OFF;
	pic_u8 *peb = region + PEB_OFF;
	pic_u8 *ldr = region + LDR_OFF;
	pic_u8 *entry_k32 = region + ENTRY_K32_OFF;
	pic_u8 *entry_ws2 = region + ENTRY_WS2_OFF;
	pic_u8 *name_k32 = region + NAME_K32_OFF;
	pic_u8 *name_ws2 = region + NAME_WS2_OFF;

	pic_u16 k32_bytes = write_utf16le(name_k32, "kernel32.dll");
	pic_u16 ws2_bytes = write_utf16le(name_ws2, "ws2_32.dll");

#if PIC_ARCH_IS_32BIT
	write_ptr(teb, 0x18, teb); /* TEB self */
	write_ptr(teb, 0x30, peb); /* PEB */
	write_ptr(peb, 0x0C, ldr); /* Ldr */
	pic_u8 *list_head = ldr + 0x14;
#else
	write_ptr(teb, 0x30, teb);
	write_ptr(teb, 0x60, peb);
	write_ptr(peb, 0x18, ldr);
	pic_u8 *list_head = ldr + 0x20;
#endif

	/*
	 * Doubly-linked InMemoryOrderModuleList:
	 *   head <-> k32 <-> ws2 <-> head
	 */
	write_ptr(list_head, 0x00, entry_k32);
	write_ptr(list_head, sizeof(void *), entry_ws2);

	write_ptr(entry_k32, 0x00, entry_ws2);
	write_ptr(entry_k32, sizeof(void *), list_head);

	write_ptr(entry_ws2, 0x00, list_head);
	write_ptr(entry_ws2, sizeof(void *), entry_k32);

	write_ldr_entry(entry_k32, pe_kernel32, name_k32, k32_bytes);
	write_ldr_entry(entry_ws2, pe_ws2_32, name_ws2, ws2_bytes);

	return teb;
}

/* ---------- Blob loader ---------- */

static long file_size(int fd)
{
	long end = pic_lseek(fd, 0, PIC_SEEK_END);
	if (end < 0) {
		return -1;
	}
	if (pic_lseek(fd, 0, PIC_SEEK_SET) < 0) {
		return -1;
	}
	return end;
}

static long read_all(int fd, void *buf, pic_size_t count)
{
	pic_u8 *p = (pic_u8 *)buf;
	pic_size_t done = 0;
	while (done < count) {
		long n = pic_read(fd, p + done, count - done);
		if (n <= 0) {
			return -1;
		}
		done += (pic_size_t)n;
	}
	return (long)done;
}

/* ---------- _start and runner_main ---------- */

#if defined(__x86_64__)
#include "start/x86_64.h"
#elif defined(__i386__)
#include "start/i386.h"
#elif defined(__aarch64__)
#include "start/aarch64.h"
#else
#error "Windows runner: unsupported architecture for _start"
#endif

int runner_main(int argc, char **argv)
{
	if (argc < 2) {
		pic_exit_group(RUNNER_ERROR);
	}

	/*
	 * kernel32.dll exports — alphabetically sorted.
	 * The blob's pic_find_export uses hash lookup, but Windows stores
	 * exports sorted by name and some blob techniques rely on that.
	 * We keep the order strictly alphabetical for compatibility.
	 */
	static const struct mock_export k32_exports[] = {
		{"CloseHandle", (void *)mock_CloseHandle},
		{"CreateFileA", (void *)mock_CreateFileA},
		{"ExitProcess", (void *)mock_ExitProcess},
		{"GetStdHandle", (void *)mock_GetStdHandle},
		{"ReadFile", (void *)mock_ReadFile},
		{"VirtualAlloc", (void *)mock_VirtualAlloc},
		{"WriteFile", (void *)mock_WriteFile},
	};
	static const int k32_n = sizeof(k32_exports) / sizeof(k32_exports[0]);

	static const struct mock_export ws2_exports[] = {
		{"WSAStartup", (void *)mock_WSAStartup},
		{"closesocket", (void *)mock_closesocket},
		{"connect", (void *)mock_connect},
		{"htons", (void *)mock_htons},
		{"recv", (void *)mock_recv},
		{"socket", (void *)mock_socket},
	};
	static const int ws2_n = sizeof(ws2_exports) / sizeof(ws2_exports[0]);

	pic_u8 *pe_k32 = build_mock_pe(k32_exports, k32_n);
	if (!pe_k32) {
		pic_exit_group(RUNNER_ERROR);
	}

	pic_u8 *pe_ws2 = build_mock_pe(ws2_exports, ws2_n);
	if (!pe_ws2) {
		pic_exit_group(RUNNER_ERROR);
	}

	pic_u8 *teb = build_mock_env(pe_k32, pe_ws2);
	if (!teb) {
		pic_exit_group(RUNNER_ERROR);
	}

	long ret = set_teb_base(teb);
	if (ret < 0) {
		pic_exit_group(RUNNER_ERROR);
	}

	int fd = (int)pic_open(argv[1], PIC_O_RDONLY, 0);
	if (fd < 0) {
		pic_exit_group(RUNNER_ERROR);
	}

	long size = file_size(fd);
	if (size <= 0) {
		pic_close(fd);
		pic_exit_group(RUNNER_ERROR);
	}

	void *blob = pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)blob == -1) {
		pic_close(fd);
		pic_exit_group(RUNNER_ERROR);
	}

	if (read_all(fd, blob, (pic_size_t)size) < 0) {
		pic_close(fd);
		pic_exit_group(RUNNER_ERROR);
	}

	pic_close(fd);

	call_blob_with_teb(blob, teb);

	pic_exit_group(RUNNER_ERROR);
}
