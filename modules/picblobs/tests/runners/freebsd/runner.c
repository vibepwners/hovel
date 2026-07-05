/*
 * FreeBSD test runner — Linux-hosted FreeBSD syscall emulation.
 *
 * On x86_64 this runner executes the blob under ptrace and translates
 * FreeBSD syscall numbers/results at the syscall boundary. Other
 * architectures still use static syscall patching in the loaded code.
 *
 * This runner is hand-written (not generated) because it needs to
 * use Linux syscalls internally while translating FreeBSD numbers
 * in the loaded blob. See generate.py which skips this file.
 *
 * Supports: x86_64, i686, aarch64, armv5, armv7, s390x, mipsel32, mipsbe32.
 *
 * Usage: ./runner <blob.bin>
 */

#include "picblobs/os/linux.h"
#include "picblobs/sys/accept.h"
#include "picblobs/sys/bind.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/connect.h"
#include "picblobs/sys/exit.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/listen.h"
#include "picblobs/sys/lseek.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/sys/munmap.h"
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"
#include "picblobs/sys/setsockopt.h"
#include "picblobs/sys/socket.h"
#include "picblobs/sys/write.h"
#include "picblobs/syscall.h"
#include "picblobs/types.h"

#define RUNNER_ERROR 127
#define SIGTRAP 5
#define PTRACE_TRACEME 0
#define PTRACE_CONT 7
#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_SYSCALL 24
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_O_TRACESYSGOOD 0x00000001

#if defined(__x86_64__)
#define __NR_fork 57
#define __NR_wait4 61
#define __NR_ptrace 101

struct x86_64_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
};
#endif

struct nr_map {
	pic_u32 freebsd_nr;
	pic_u32 linux_nr;
};

static const struct nr_map syscall_table[] = {
	{1, __NR_exit},
	{3, __NR_read},
	{4, __NR_write},
#ifdef __NR_open
	{5, __NR_open},
#endif
	{6, __NR_close},
#ifdef __NR_lseek
	{478, __NR_lseek},
#endif
#ifdef __NR_llseek
	{478, __NR_llseek},
#endif
	{477, __NR_mmap},
	{74, __NR_mprotect},
	{73, __NR_munmap},
	{97, __NR_socket},
	{98, __NR_connect},
	{30, __NR_accept},
	{104, __NR_bind},
	{106, __NR_listen},
	{105, __NR_setsockopt},
	{431, __NR_exit_group},
};

#define NR_TABLE_SIZE (sizeof(syscall_table) / sizeof(syscall_table[0]))

static inline pic_u32 translate_nr(pic_u32 freebsd_nr)
{
	for (int i = 0; i < (int)NR_TABLE_SIZE; i++) {
		if (syscall_table[i].freebsd_nr == freebsd_nr) {
			return syscall_table[i].linux_nr;
		}
	}
	return freebsd_nr;
}

static inline void write32_le(pic_u8 *p, pic_u32 v)
{
	p[0] = (pic_u8)v;
	p[1] = (pic_u8)(v >> 8);
	p[2] = (pic_u8)(v >> 16);
	p[3] = (pic_u8)(v >> 24);
}
static inline pic_u32 read32_le(const pic_u8 *p)
{
	return (pic_u32)p[0] | ((pic_u32)p[1] << 8) | ((pic_u32)p[2] << 16) |
		((pic_u32)p[3] << 24);
}
/* Big-endian helpers — used only in the s390x/mips syscall-patch paths,
 * unused when this runner is built for a little-endian host. */
static inline __attribute__((unused)) void write32_be(pic_u8 *p, pic_u32 v)
{
	p[0] = (pic_u8)(v >> 24);
	p[1] = (pic_u8)(v >> 16);
	p[2] = (pic_u8)(v >> 8);
	p[3] = (pic_u8)v;
}
static inline __attribute__((unused)) pic_u32 read32_be(const pic_u8 *p)
{
	return ((pic_u32)p[0] << 24) | ((pic_u32)p[1] << 16) |
		((pic_u32)p[2] << 8) | (pic_u32)p[3];
}
static inline __attribute__((unused)) pic_u16 read16_be(const pic_u8 *p)
{
	return (pic_u16)(((pic_u16)p[0] << 8) | (pic_u16)p[1]);
}
static inline __attribute__((unused)) void write16_be(pic_u8 *p, pic_u16 v)
{
	p[0] = (pic_u8)(v >> 8);
	p[1] = (pic_u8)v;
}

#if defined(__x86_64__)
static pic_u8 *find_prev_mov_eax_imm(
	pic_u8 *code, pic_size_t start, pic_size_t limit)
{
	pic_size_t lo = (start > limit) ? (start - limit) : 0;
	for (pic_size_t i = start; i >= lo + 4; i--) {
		if (code[i - 4] == 0xb8) {
			return code + i - 4;
		}
		if (i == lo + 4) {
			break;
		}
	}
	return (pic_u8 *)0;
}

static pic_u32 translate_mmap_flags(pic_u32 freebsd_flags)
{
	pic_u32 linux_flags = 0;
	if (0U != (freebsd_flags & 0x0001U)) {
		linux_flags |= 0x01;
	}
	if (0U != (freebsd_flags & 0x0002U)) {
		linux_flags |= 0x02;
	}
	if (0U != (freebsd_flags & 0x0010U)) {
		linux_flags |= 0x10;
	}
	if (0U != (freebsd_flags & 0x1000U)) {
		linux_flags |= 0x20;
	}
	return linux_flags;
}

static long linux_ptrace(long req, long pid, long addr, long data)
{
	return pic_syscall4(__NR_ptrace, req, pid, addr, data);
}

static long linux_wait4(long pid, int *status)
{
	return pic_syscall4(__NR_wait4, pid, (long)status, 0, 0);
}

static int wait_stopped(int status) { return (status & 0xff) == 0x7f; }

static int stop_signal(int status) { return (status >> 8) & 0xff; }

static int exited(int status) { return (status & 0x7f) == 0; }

static int exit_status(int status) { return (status >> 8) & 0xff; }

static int signaled(int status)
{
	int sig = status & 0x7f;
	return sig != 0 && sig != 0x7f;
}

static int term_signal(int status) { return status & 0x7f; }

static void set_freebsd_result(struct x86_64_regs *regs)
{
	long ret = (long)regs->rax;
	if (ret < 0 && ret >= -4095) {
		regs->rax = (unsigned long)(-ret);
		regs->eflags |= 1UL;
	} else {
		regs->eflags &= ~1UL;
	}
}

static void translate_x86_64_entry(struct x86_64_regs *regs)
{
	pic_u32 freebsd_nr = (pic_u32)regs->orig_rax;
	pic_u32 linux_nr = translate_nr(freebsd_nr);
	if (freebsd_nr == 477) {
		regs->r10 = translate_mmap_flags((pic_u32)regs->r10);
	}
	regs->rax = linux_nr;
	regs->orig_rax = linux_nr;
}

static int wait_initial_trace_stop(long pid, int *status)
{
	if (linux_wait4(pid, status) < 0) {
		return 121;
	}
	if (0 == wait_stopped(*status)) {
		return 122;
	}
	if (linux_ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) <
		0) {
		return 123;
	}
	return 0;
}

static int wait_for_ptrace_stop(long pid, int *status)
{
	if (linux_ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
		return 124;
	}
	if (linux_wait4(pid, status) < 0) {
		return 125;
	}
	return 0;
}

static int wait_for_signal_resume(long pid, int sig, int *status)
{
	if (linux_ptrace(PTRACE_CONT, pid, 0, sig) < 0) {
		return 129;
	}
	if (linux_wait4(pid, status) < 0) {
		return 130;
	}
	return 0;
}

static int maybe_trace_exit(int status, int *done)
{
	*done = 1;
	if (exited(status)) {
		return exit_status(status);
	}
	if (signaled(status)) {
		return 128 + term_signal(status);
	}
	*done = 0;
	return 0;
}

static int handle_x86_64_syscall_stop(long pid, int *in_syscall)
{
	struct x86_64_regs regs = {0};

	if (linux_ptrace(PTRACE_GETREGS, pid, 0, (long)&regs) < 0) {
		return 127;
	}
	if (0 == *in_syscall) {
		translate_x86_64_entry(&regs);
	} else {
		set_freebsd_result(&regs);
	}
	if (linux_ptrace(PTRACE_SETREGS, pid, 0, (long)&regs) < 0) {
		return 128;
	}
	*in_syscall = !(*in_syscall);
	return 0;
}

static int handle_x86_64_signal_stop(long pid, int sig, int *status, int *done)
{
	int trace_status = 0;

	if (sig == SIGTRAP) {
		return 0;
	}

	trace_status = wait_for_signal_resume(pid, sig, status);
	if (0 != trace_status) {
		return trace_status;
	}

	return maybe_trace_exit(*status, done);
}

static int trace_child_x86_64(long pid)
{
	int status = 0;
	int in_syscall = 0;
	int done = 0;
	int trace_status = wait_initial_trace_stop(pid, &status);

	if (0 != trace_status) {
		return trace_status;
	}

	for (;;) {
		trace_status = wait_for_ptrace_stop(pid, &status);
		if (0 != trace_status) {
			return trace_status;
		}

		trace_status = maybe_trace_exit(status, &done);
		if (0 != done) {
			return trace_status;
		}
		if (0 == wait_stopped(status)) {
			return 126;
		}

		int sig = stop_signal(status);
		if (sig == (SIGTRAP | 0x80)) {
			trace_status =
				handle_x86_64_syscall_stop(pid, &in_syscall);
			if (0 != trace_status) {
				return trace_status;
			}
			continue;
		}
		trace_status =
			handle_x86_64_signal_stop(pid, sig, &status, &done);
		if (0 != done) {
			return trace_status;
		}
		if (0 != trace_status) {
			return trace_status;
		}
	}
}

static pic_u8 *find_prev_mov_r10d_imm(
	pic_u8 *code, pic_size_t start, pic_size_t limit)
{
	pic_size_t lo = (start > limit) ? (start - limit) : 0;
	for (pic_size_t i = start; i >= lo + 5; i--) {
		if (code[i - 5] == 0x41 && code[i - 4] == 0xba) {
			return code + i - 5;
		}
		if (i == lo + 5) {
			break;
		}
	}
	return (pic_u8 *)0;
}

static int bytes_match(const pic_u8 *code, pic_size_t offset,
	const pic_u8 *pattern, pic_size_t len)
{
	for (pic_size_t i = 0; i < len; i++) {
		if (code[offset + i] != pattern[i]) {
			return 0;
		}
	}
	return 1;
}

static void patch_x86_64_errno_normalization(
	pic_u8 *code, pic_size_t syscall_off, pic_size_t size)
{
	static const pic_u8 setc_seq[] = {0x40, 0x0f, 0x92};
	static const pic_u8 add_seq[] = {0x40, 0x84};
	static const pic_u8 jz_seq[] = {0x74, 0x03};
	static const pic_u8 neg_seq[] = {0x48, 0xf7, 0xd8};

	if (syscall_off + 14 > size) {
		return;
	}
	if (0 ==
		bytes_match(
			code, syscall_off + 2, setc_seq, sizeof(setc_seq))) {
		return;
	}
	if (0 == bytes_match(code, syscall_off + 6, add_seq, sizeof(add_seq))) {
		return;
	}
	if (0 == bytes_match(code, syscall_off + 9, jz_seq, sizeof(jz_seq))) {
		return;
	}
	if (0 ==
		bytes_match(code, syscall_off + 11, neg_seq, sizeof(neg_seq))) {
		return;
	}
	for (pic_size_t i = syscall_off + 2; i < syscall_off + 14; i++) {
		code[i] = 0x90;
	}
}

static void patch_syscalls_x86_64(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 1 < size; i++) {
		if (code[i] == 0x0f && code[i + 1] == 0x05) {
			pic_u8 *mov = find_prev_mov_eax_imm(code, i, 32);
			if (PIC_NULL == mov) {
				continue;
			}
			pic_u32 nr = read32_le(mov + 1);
			pic_u32 lnr = translate_nr(nr);
			if (nr == 477) {
				pic_u8 *mov_r10d =
					find_prev_mov_r10d_imm(code, i, 32);
				if (mov_r10d) {
					pic_u32 flags = read32_le(mov_r10d + 2);
					write32_le(mov_r10d + 2,
						translate_mmap_flags(flags));
				}
			}
			if (lnr != nr) {
				write32_le(mov + 1, lnr);
			}
			patch_x86_64_errno_normalization(code, i, size);
		}
	}
}
static void patch_syscalls(pic_u8 *code, pic_size_t size)
{
	patch_syscalls_x86_64(code, size);
}
#elif defined(__i386__)
static pic_u8 *find_prev_mov_eax_imm(
	pic_u8 *code, pic_size_t start, pic_size_t limit)
{
	pic_size_t lo = (start > limit) ? (start - limit) : 0;
	for (pic_size_t i = start; i >= lo + 4; i--) {
		if (code[i - 4] == 0xb8) {
			return code + i - 4;
		}
		if (i == lo + 4) {
			break;
		}
	}
	return (pic_u8 *)0;
}

static void patch_syscalls_i386(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 1 < size; i++) {
		if (code[i] == 0xcd && code[i + 1] == 0x80) {
			pic_u8 *mov = find_prev_mov_eax_imm(code, i, 48);
			if (!mov) {
				continue;
			}
			pic_u32 nr = read32_le(mov + 1);
			pic_u32 lnr = translate_nr(nr);
			if (lnr != nr) {
				write32_le(mov + 1, lnr);
			}
		}
	}
}
static void patch_syscalls(pic_u8 *code, pic_size_t size)
{
	patch_syscalls_i386(code, size);
}
#elif defined(__aarch64__)
static void patch_syscalls_aarch64(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 7 < size; i += 4) {
		pic_u32 insn = read32_le(code + i);
		pic_u32 next = read32_le(code + i + 4);
		if ((insn & 0xFFE0001F) == 0xD2800008 && next == 0xD4000001) {
			pic_u32 nr = (insn >> 5) & 0xFFFF;
			pic_u32 lnr = translate_nr(nr);
			if (lnr != nr) {
				insn = (insn & ~(0xFFFF << 5)) | (lnr << 5);
				write32_le(code + i, insn);
			}
		}
	}
}
static void patch_syscalls(pic_u8 *code, pic_size_t size)
{
	patch_syscalls_aarch64(code, size);
}
#elif defined(__arm__)
static void patch_syscalls_arm(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 3 < size; i += 2) {
		pic_u16 insn = (pic_u16)code[i] | ((pic_u16)code[i + 1] << 8);
		pic_u16 next =
			(pic_u16)code[i + 2] | ((pic_u16)code[i + 3] << 8);
		if ((insn & 0xFF00) == 0x2700 && next == 0xdf00) {
			pic_u32 nr = insn & 0xFF;
			pic_u32 lnr = translate_nr(nr);
			if (lnr != nr && lnr < 256) {
				code[i] = (pic_u8)lnr;
			}
		}
	}
}
static void patch_syscalls(pic_u8 *code, pic_size_t size)
{
	patch_syscalls_arm(code, size);
}
#elif defined(__s390x__)
static void patch_syscalls_s390x(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 5 < size; i += 2) {
		if (code[i] == 0xa7 && code[i + 1] == 0x19 &&
			code[i + 4] == 0x0a && code[i + 5] == 0x00) {
			pic_u16 nr = read16_be(code + i + 2);
			pic_u32 lnr = translate_nr(nr);
			if (lnr != nr && lnr < 0x8000) {
				write16_be(code + i + 2, (pic_u16)lnr);
			}
		}
	}
}
static void patch_syscalls(pic_u8 *code, pic_size_t size)
{
	patch_syscalls_s390x(code, size);
}
#elif defined(__mips__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static void patch_syscalls_mips_be(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 7 < size; i += 4) {
		pic_u32 insn = read32_be(code + i);
		pic_u32 next = read32_be(code + i + 4);
		if ((insn & 0xFFFF0000) == 0x24020000 && next == 0x0000000c) {
			pic_u32 nr = insn & 0xFFFF;
			pic_u32 lnr = translate_nr(nr);
			if (lnr != nr) {
				write32_be(code + i,
					(insn & 0xFFFF0000) | (lnr & 0xFFFF));
			}
		}
	}
}
#else
static void patch_syscalls_mips_le(pic_u8 *code, pic_size_t size)
{
	for (pic_size_t i = 0; i + 7 < size; i += 4) {
		pic_u32 insn = read32_le(code + i);
		pic_u32 next = read32_le(code + i + 4);
		if ((insn & 0xFFFF0000) == 0x24020000 && next == 0x0000000c) {
			pic_u32 nr = insn & 0xFFFF;
			pic_u32 lnr = translate_nr(nr);
			if (lnr != nr) {
				write32_le(code + i,
					(insn & 0xFFFF0000) | (lnr & 0xFFFF));
			}
		}
	}
}
#endif
static void patch_syscalls(pic_u8 *code, pic_size_t size)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	patch_syscalls_mips_be(code, size);
#else
	patch_syscalls_mips_le(code, size);
#endif
}
#endif

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

#if defined(__x86_64__)
#include "start/x86_64.h"
#elif defined(__i386__)
#include "start/i386.h"
#elif defined(__aarch64__)
#include "start/aarch64.h"
#elif defined(__arm__)
#include "start/arm.h"
#elif defined(__s390x__)
#include "start/s390x.h"
#elif defined(__mips__)
#include "start/mips.h"
#else
#error "FreeBSD runner: unsupported architecture for _start"
#endif

/*
 * Parse an unsigned hex/decimal literal from a NUL-terminated string.
 * Accepts "0x"/"0X" prefix for hex. Returns 0 on empty/invalid input.
 */
static int parse_digit(char c, int base)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (base == 16 && c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (base == 16 && c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static pic_size_t parse_size(const char *s)
{
	if (!s || !*s) {
		return 0;
	}
	pic_size_t v = 0;
	int base = 10;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		base = 16;
		s += 2;
	}
	for (; *s; s++) {
		int d = parse_digit(*s, base);
		if (0 > d) {
			return 0;
		}
		v = v * (pic_size_t)base + (pic_size_t)d;
	}
	return v;
}

static pic_u8 *load_blob_image(const char *path, long *size_out)
{
	int fd = (int)pic_open(path, PIC_O_RDONLY, 0);
	long size = 0;
	void *blob = PIC_NULL;

	if (fd < 0) {
		return PIC_NULL;
	}

	size = file_size(fd);
	if (size <= 0) {
		(void)pic_close(fd);
		return PIC_NULL;
	}

	blob = pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)blob == -1) {
		(void)pic_close(fd);
		return PIC_NULL;
	}

	if (read_all(fd, blob, (pic_size_t)size) < 0) {
		(void)pic_close(fd);
		return PIC_NULL;
	}

	(void)pic_close(fd);
	*size_out = size;
	return (pic_u8 *)blob;
}

static pic_size_t patch_limit_from_argv(int argc, char **argv, long size)
{
	pic_size_t patch_limit = (pic_size_t)size;

	if (argc >= 3) {
		pic_size_t t_end = parse_size(argv[2]);
		if ((t_end > 0) && (t_end <= (pic_size_t)size)) {
			patch_limit = t_end;
		}
	}

	return patch_limit;
}

#if defined(__x86_64__)
static void run_x86_64_blob(void *blob)
{
	long pid = pic_syscall0(__NR_fork);
	if (pid < 0) {
		pic_exit_group(RUNNER_ERROR);
	}
	if (pid == 0) {
		if (linux_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
			pic_exit_group(RUNNER_ERROR);
		}
		__asm__ volatile("int3");
		((void (*)(void))blob)();
		pic_exit_group(RUNNER_ERROR);
	}
	pic_exit_group(trace_child_x86_64(pid));
}
#endif

int runner_main(int argc, char **argv)
{
	long size = 0;
	pic_u8 *blob = PIC_NULL;
	pic_size_t patch_limit = 0;

	if (argc < 2) {
		pic_exit_group(RUNNER_ERROR);
	}

	blob = load_blob_image(argv[1], &size);
	if (PIC_NULL == blob) {
		pic_exit_group(RUNNER_ERROR);
	}

	/* Optional argv[2]: hex text_end — scope syscall patching to the
	 * code region so .rodata/.data/.config can't cause false matches. */
	patch_limit = patch_limit_from_argv(argc, argv, size);

#if defined(__x86_64__)
	run_x86_64_blob(blob);
#endif

	patch_syscalls(blob, patch_limit);

#ifdef __thumb__
	((void (*)(void))((pic_uintptr)blob | 1))();
#else
	((void (*)(void))blob)();
#endif
	pic_exit_group(RUNNER_ERROR);
}
