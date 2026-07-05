/*
 * ul_exec — Userland exec: execute an ELF binary without execve().
 *
 * Implements the grugq's userland exec technique with a self-relocation
 * twist: the blob first copies itself (code + config) to a safe high
 * address, jumps there, then has free reign over the entire address
 * space to load the target ELF — including non-PIE binaries at their
 * fixed load addresses (e.g. 0x08048000 on i686).
 *
 * Steps:
 *   0. Self-relocate blob to a high address, jump there
 *   1. Parse the ELF from the config buffer
 *   2. Load PT_LOAD segments (MAP_FIXED for ET_EXEC, kernel-chosen for ET_DYN)
 *   3. If dynamically linked, load the interpreter from disk
 *   4. Build a proper stack (argc, argv, envp, auxv)
 *   5. Jump to the entry point
 *
 * Config layout (packed little-endian):
 *   u32 elf_size
 *   u32 argc
 *   u32 argv_size      (total bytes of null-separated argv strings)
 *   u32 envp_count
 *   u32 envp_size      (total bytes of null-separated envp strings)
 *   u8  elf_data[elf_size]
 *   u8  argv_data[argv_size]
 *   u8  envp_data[envp_size]
 *
 * Unix-like targets. Supports static and dynamically linked ELFs on all
 * staged architectures, including the FreeBSD x86_64 userland-exec path.
 */

#include "picblobs/arch.h"
#include "picblobs/cache.h"
#include "picblobs/log.h"
#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/lseek.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/sys/munmap.h"
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"
#include "picblobs/sys/write.h"
#include "picblobs/types.h"

/* ----------------------------------------------------------------
 * ELF definitions
 * ---------------------------------------------------------------- */

/* ELF magic: "\x7fELF" — byte-order dependent when read as u32. */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ELF_MAGIC 0x7f454c46
#else
#define ELF_MAGIC 0x464c457f
#endif

#define ET_EXEC 2
#define ET_DYN 3

#define PT_NULL 0
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14

#if !defined(PICBLOBS_OS_FREEBSD)
#define AT_RANDOM 25
#define AT_HWCAP 16
#define AT_HWCAP2 26
#define AT_CLKTCK 17
#define AT_SECURE 23
#endif

#if PIC_ARCH_IS_32BIT

typedef pic_u32 Elf_Addr;
typedef pic_u32 Elf_Off;
typedef pic_u16 Elf_Half;
typedef pic_u32 Elf_Word;

typedef struct {
	unsigned char e_ident[16];
	Elf_Half e_type;
	Elf_Half e_machine;
	Elf_Word e_version;
	Elf_Addr e_entry;
	Elf_Off e_phoff;
	Elf_Off e_shoff;
	Elf_Word e_flags;
	Elf_Half e_ehsize;
	Elf_Half e_phentsize;
	Elf_Half e_phnum;
	Elf_Half e_shentsize;
	Elf_Half e_shnum;
	Elf_Half e_shstrndx;
} Elf_Ehdr;

typedef struct {
	Elf_Word p_type;
	Elf_Off p_offset;
	Elf_Addr p_vaddr;
	Elf_Addr p_paddr;
	Elf_Word p_filesz;
	Elf_Word p_memsz;
	Elf_Word p_flags;
	Elf_Word p_align;
} Elf_Phdr;

#else

typedef pic_u64 Elf_Addr;
typedef pic_u64 Elf_Off;
typedef pic_u16 Elf_Half;
typedef pic_u32 Elf_Word;
typedef pic_u64 Elf_Xword;

typedef struct {
	unsigned char e_ident[16];
	Elf_Half e_type;
	Elf_Half e_machine;
	Elf_Word e_version;
	Elf_Addr e_entry;
	Elf_Off e_phoff;
	Elf_Off e_shoff;
	Elf_Word e_flags;
	Elf_Half e_ehsize;
	Elf_Half e_phentsize;
	Elf_Half e_phnum;
	Elf_Half e_shentsize;
	Elf_Half e_shnum;
	Elf_Half e_shstrndx;
} Elf_Ehdr;

typedef struct {
	Elf_Word p_type;
	Elf_Word p_flags;
	Elf_Off p_offset;
	Elf_Addr p_vaddr;
	Elf_Addr p_paddr;
	Elf_Xword p_filesz;
	Elf_Xword p_memsz;
	Elf_Xword p_align;
} Elf_Phdr;

#endif

/* ----------------------------------------------------------------
 * Config structure
 * ---------------------------------------------------------------- */

struct ul_exec_config {
	pic_u32 elf_size;
	pic_u32 argc;
	pic_u32 argv_size;
	pic_u32 envp_count;
	pic_u32 envp_size;
};

/*
 * ASM config anchor — prevents the compiler from seeing the initial
 * zeros and optimizing away our runtime reads.
 */
__asm__(".section .config,\"aw\"\n"
	".globl ul_exec_config\n"
	"ul_exec_config:\n"
	".space 20\n"
	".previous\n");

/* ----------------------------------------------------------------
 * Utility functions
 * ---------------------------------------------------------------- */

#define PAGE_SIZE 4096UL
#define PAGE_ALIGN_DOWN(x) ((pic_uintptr)(x) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (((pic_uintptr)(x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

/*
 * Safe high address hint for the blob's self-remap.
 * Far from the typical ET_EXEC ranges on all arches.
 */
#if PIC_ARCH_IS_32BIT
#define SAFE_ADDR_HINT ((void *)0x70000000UL)
#else
#define SAFE_ADDR_HINT ((void *)0x700000000000ULL)
#endif

PIC_TEXT
static void pic_memcpy(void *dst, const void *src, pic_size_t n)
{
	pic_u8 *d = (pic_u8 *)dst;
	const pic_u8 *s = (const pic_u8 *)src;
	while (n--) {
		*d++ = *s++;
	}
}

PIC_TEXT
static void pic_memset(void *dst, int c, pic_size_t n)
{
	pic_u8 *d = (pic_u8 *)dst;
	while (n--) {
		*d++ = (pic_u8)c;
	}
}

PIC_TEXT
static pic_size_t pic_strlen(const char *s)
{
	pic_size_t n = 0;
	while (s[n]) {
		n++;
	}
	return n;
}

PIC_TEXT
static void debug_log_aux_entry(const char *name, pic_uintptr value)
{
	PIC_LOG("ul_exec: aux %s=%x\n", name, (unsigned long)value);
}

PIC_TEXT
static int pf_to_prot(Elf_Word flags)
{
	int prot = 0;
	if (flags & PF_R) {
		prot |= PIC_PROT_READ;
	}
	if (flags & PF_W) {
		prot |= PIC_PROT_WRITE;
	}
	if (flags & PF_X) {
		prot |= PIC_PROT_EXEC;
	}
	return prot;
}

PIC_TEXT
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

/* ----------------------------------------------------------------
 * Step 0 — self-remap.
 *
 * The blob + config occupies [blob_start, blob_start + total_size).
 * We mmap a new RWX region at a safe high address, copy everything
 * there, then jump to phase2 in the new copy. The old mapping can
 * then be freely clobbered by the target ELF.
 *
 * We pass the config pointer (adjusted to the new location) through
 * the architecture's first argument register / stack.
 * ---------------------------------------------------------------- */

/* Forward declaration — phase2 is the real ul_exec logic. */
PIC_TEXT
__attribute__((noreturn)) static void phase2(const struct ul_exec_config *cfg);

#if defined(__powerpc__) && !defined(__powerpc64__)
__asm__(".section .text.pic_code,\"ax\"\n"
	".globl pic_ul_exec_powerpc_enter\n"
	"pic_ul_exec_powerpc_enter:\n"
	"mr 12, 3\n"
	"mr 30, 5\n"
	"mr 3, 4\n"
	"mtctr 12\n"
	"bctr\n"
	".previous\n");

PIC_TEXT
__attribute__((noreturn)) void pic_ul_exec_powerpc_enter(
	pic_uintptr entry, pic_uintptr arg, pic_uintptr pic_base);
#endif

PIC_TEXT
__attribute__((noreturn)) static void self_remap(pic_uintptr blob_start,
	pic_size_t total_size, const struct ul_exec_config *cfg)
{
	pic_size_t alloc_size = PAGE_ALIGN_UP(total_size);

	/* Map a new RWX region at a safe high address. */
	pic_u8 *new_base = (pic_u8 *)pic_mmap(SAFE_ADDR_HINT, alloc_size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)new_base == -1) {
		pic_exit_group(110);
	}

	/* Copy the entire blob + config to the new location. */
	pic_memcpy(new_base, (const void *)blob_start, total_size);
	pic_sync_icache((void *)new_base, total_size);

	/* Calculate the delta and relocated pointers. */
	pic_uintptr delta = (pic_uintptr)new_base - blob_start;
	const struct ul_exec_config *new_cfg =
		(const struct ul_exec_config *)((pic_uintptr)cfg + delta);
	pic_uintptr phase2_addr = (pic_uintptr)&phase2 + delta;
	extern char __got_start[] __attribute__((visibility("hidden")));
	extern char __got_end[] __attribute__((visibility("hidden")));
	pic_uintptr got_off = (pic_uintptr)__got_start - blob_start;
	pic_uintptr got_end_off = (pic_uintptr)__got_end - blob_start;

	PIC_LOG("ul_exec: remap %x -> %x (delta=%x, size=%x)\n",
		(long)blob_start, (long)new_base, (long)delta,
		(long)total_size);

	/*
	 * Patch the GOT in the new copy. On 32-bit PIC (i686, ARM, MIPS)
	 * all data/function references go through the GOT. After memcpy,
	 * the GOT entries still point to the old location. Add delta to
	 * each non-zero GOT entry to fix them up.
	 *
	 * __got_start / __got_end are linker-defined symbols bounding the
	 * GOT. They're available on all arches (empty range if no GOT).
	 */
	{
		pic_uintptr *got = (pic_uintptr *)(new_base + got_off);
		pic_uintptr *got_e = (pic_uintptr *)(new_base + got_end_off);
		while (got < got_e) {
			if (*got) {
				*got += delta;
			}
			got++;
		}
	}

	/*
	 * Jump to phase2 in the new copy.
	 * We use an indirect call through a register to jump to the
	 * relocated function. This works because phase2's code is
	 * now at phase2_addr in the new mapping.
	 */
#if defined(__powerpc__) && !defined(__powerpc64__)
	pic_ul_exec_powerpc_enter(phase2_addr, (pic_uintptr)new_cfg,
		(pic_uintptr)new_base + got_off + 32768u);
#else
	typedef void (*phase2_fn)(const struct ul_exec_config *);
	phase2_fn fn = (phase2_fn)phase2_addr;
	fn(new_cfg);
#endif

	__builtin_unreachable();
}

/* ----------------------------------------------------------------
 * ELF loader
 * ---------------------------------------------------------------- */

PIC_TEXT
static int find_load_range(const Elf_Ehdr *ehdr, const Elf_Phdr *phdr,
	pic_uintptr *out_vaddr_min, pic_uintptr *out_vaddr_max)
{
	pic_uintptr vaddr_min = (pic_uintptr)-1;
	pic_uintptr vaddr_max = 0;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD) {
			continue;
		}
		pic_uintptr lo = (pic_uintptr)phdr[i].p_vaddr;
		pic_uintptr hi = lo + phdr[i].p_memsz;
		if (lo < vaddr_min) {
			vaddr_min = lo;
		}
		if (hi > vaddr_max) {
			vaddr_max = hi;
		}
	}

	if (vaddr_min == (pic_uintptr)-1) {
		return 0;
	}

	*out_vaddr_min = vaddr_min;
	*out_vaddr_max = vaddr_max;
	return 1;
}

PIC_TEXT
static pic_uintptr reserve_pie_range(
	pic_uintptr vaddr_min, pic_uintptr vaddr_max)
{
	pic_uintptr total =
		PAGE_ALIGN_UP(vaddr_max) - PAGE_ALIGN_DOWN(vaddr_min);
	void *region = pic_mmap(PIC_NULL, total, PIC_PROT_NONE,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)region == -1) {
		return (pic_uintptr)-1;
	}
	return (pic_uintptr)region - PAGE_ALIGN_DOWN(vaddr_min);
}

PIC_TEXT
static int map_load_segment(const pic_u8 *elf_data, pic_size_t elf_size,
	const Elf_Phdr *segment, pic_uintptr base)
{
	pic_uintptr seg_addr = base + segment->p_vaddr;
	pic_uintptr map_start = PAGE_ALIGN_DOWN(seg_addr);
	pic_uintptr map_end = PAGE_ALIGN_UP(seg_addr + segment->p_memsz);
	pic_size_t map_size = map_end - map_start;

	void *p = pic_mmap((void *)map_start, map_size,
		PIC_PROT_READ | PIC_PROT_WRITE,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS | PIC_MAP_FIXED, -1, 0);
	if ((long)p == -1) {
		return 0;
	}

	if (segment->p_filesz > 0) {
		if (segment->p_offset + segment->p_filesz > elf_size) {
			return 0;
		}
		pic_memcpy((void *)seg_addr, elf_data + segment->p_offset,
			segment->p_filesz);
	}

	if (segment->p_memsz > segment->p_filesz) {
		pic_memset((void *)(seg_addr + segment->p_filesz), 0,
			segment->p_memsz - segment->p_filesz);
	}
	if (segment->p_flags & PF_X) {
		pic_sync_icache((void *)seg_addr, segment->p_memsz);
	}

	if (pic_mprotect((void *)map_start, map_size,
		    pf_to_prot(segment->p_flags)) < 0) {
		(void)pic_munmap((void *)map_start, map_size);
		return 0;
	}
	return 1;
}

PIC_TEXT
static int validate_elf_image(const Elf_Ehdr *ehdr, pic_size_t elf_size)
{
	pic_size_t phdr_end = 0;

	if (elf_size < sizeof(Elf_Ehdr)) {
		return 0;
	}

	if (*(const pic_u32 *)ehdr->e_ident != ELF_MAGIC) {
		return 0;
	}

	if ((ET_EXEC != ehdr->e_type) && (ET_DYN != ehdr->e_type)) {
		return 0;
	}

	if (ehdr->e_phnum > 512) {
		return 0;
	}

	phdr_end = (pic_size_t)ehdr->e_phoff +
		(pic_size_t)ehdr->e_phnum * (pic_size_t)ehdr->e_phentsize;
	if (((pic_size_t)ehdr->e_phoff > elf_size) || (phdr_end > elf_size)) {
		return 0;
	}

	return 1;
}

PIC_TEXT
static void set_phdr_addr(const Elf_Ehdr *ehdr, const Elf_Phdr *phdr,
	pic_uintptr base, pic_uintptr vaddr_min, Elf_Addr *out_phdr_addr)
{
	*out_phdr_addr = 0;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_PHDR) {
			*out_phdr_addr = base + phdr[i].p_vaddr;
			break;
		}
	}
	if (*out_phdr_addr == 0) {
		*out_phdr_addr = base + vaddr_min + ehdr->e_phoff;
	}
}

PIC_TEXT
static pic_uintptr load_elf_from_memory(const pic_u8 *elf_data,
	pic_size_t elf_size, const Elf_Ehdr *ehdr, Elf_Addr *out_phdr_addr)
{
	const Elf_Phdr *phdr = PIC_NULL;
	pic_uintptr base = 0;
	pic_uintptr vaddr_min = 0;
	pic_uintptr vaddr_max = 0;

	if (0 == validate_elf_image(ehdr, elf_size)) {
		return (pic_uintptr)-1;
	}

	phdr = (const Elf_Phdr *)(elf_data + ehdr->e_phoff);

	if (0 == find_load_range(ehdr, phdr, &vaddr_min, &vaddr_max)) {
		return (pic_uintptr)-1;
	}

	if (ehdr->e_type == ET_DYN) {
		base = reserve_pie_range(vaddr_min, vaddr_max);
		if (base == (pic_uintptr)-1) {
			return (pic_uintptr)-1;
		}
	}

	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD) {
			continue;
		}
		if (!map_load_segment(elf_data, elf_size, &phdr[i], base)) {
			return (pic_uintptr)-1;
		}
	}

	if (out_phdr_addr) {
		set_phdr_addr(ehdr, phdr, base, vaddr_min, out_phdr_addr);
	}

	return base;
}

/* ----------------------------------------------------------------
 * Load interpreter from disk
 * ---------------------------------------------------------------- */

PIC_TEXT
static pic_uintptr load_interp(const char *path, Elf_Addr *out_entry)
{
	int fd = (int)pic_open(path, PIC_O_RDONLY, 0);
	if (fd < 0) {
		return (pic_uintptr)-1;
	}

	long fsize = pic_lseek(fd, 0, PIC_SEEK_END);
	if (fsize <= 0) {
		pic_close(fd);
		return (pic_uintptr)-1;
	}
	if (pic_lseek(fd, 0, PIC_SEEK_SET) < 0) {
		pic_close(fd);
		return (pic_uintptr)-1;
	}

	void *buf = pic_mmap(PIC_NULL, (pic_size_t)fsize,
		PIC_PROT_READ | PIC_PROT_WRITE,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)buf == -1) {
		pic_close(fd);
		return (pic_uintptr)-1;
	}

	if (read_all(fd, buf, (pic_size_t)fsize) < 0) {
		pic_munmap(buf, (pic_size_t)fsize);
		pic_close(fd);
		return (pic_uintptr)-1;
	}
	pic_close(fd);

	const Elf_Ehdr *ie = (const Elf_Ehdr *)buf;
	if (0 == validate_elf_image(ie, (pic_size_t)fsize)) {
		(void)pic_munmap(buf, (pic_size_t)fsize);
		return (pic_uintptr)-1;
	}
	*out_entry = ie->e_entry;

	pic_uintptr ibase = load_elf_from_memory(
		(const pic_u8 *)buf, (pic_size_t)fsize, ie, PIC_NULL);

	pic_munmap(buf, (pic_size_t)fsize);
	return ibase;
}

/* ----------------------------------------------------------------
 * Stack builder
 * ---------------------------------------------------------------- */

PIC_TEXT
static pic_uintptr alloc_stack(pic_size_t stack_size)
{
	void *stack_base =
		pic_mmap(PIC_NULL, stack_size, PIC_PROT_READ | PIC_PROT_WRITE,
			PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)stack_base == -1) {
		pic_exit_group(120);
	}

	return (pic_uintptr)stack_base;
}

PIC_TEXT
static pic_uintptr copy_string_block(
	pic_uintptr top, const char *src, pic_u32 size)
{
	top -= size;
	if (size > 0U) {
		pic_memcpy((void *)top, src, size);
	}
	return top;
}

PIC_TEXT
static int auxv_entry_count(void)
{
#if !defined(PICBLOBS_OS_FREEBSD)
	return 15;
#else
	return 7;
#endif
}

PIC_TEXT
static pic_uintptr align_initial_stack_top(
	pic_uintptr top, pic_u32 argc, pic_u32 envp_count)
{
	pic_size_t slots = 1 + argc + 1 + envp_count + 1 +
		((pic_size_t)(auxv_entry_count() + 1) * 2U);

	top &= ~((pic_uintptr)sizeof(pic_uintptr) - 1U);
	top -= slots * sizeof(pic_uintptr);
#if defined(PICBLOBS_OS_FREEBSD) && defined(__x86_64__)
	top = (top & ~(pic_uintptr)0xf) - sizeof(pic_uintptr);
#else
	top &= ~(pic_uintptr)0xf;
#endif
	return top;
}

PIC_TEXT
static pic_uintptr *push_string_vector(
	pic_uintptr *sp, pic_u32 count, pic_uintptr strings_base)
{
	const char *p = (const char *)strings_base;

	for (pic_u32 i = 0; i < count; i++) {
		*sp++ = (pic_uintptr)p;
		p += pic_strlen(p) + 1U;
	}
	*sp++ = 0;

	return sp;
}

PIC_TEXT
static void fill_at_random(pic_uintptr random_addr)
{
#if !defined(PICBLOBS_OS_FREEBSD)
	pic_u8 *rnd = (pic_u8 *)random_addr;

	for (int i = 0; i < 16; i++) {
		rnd[i] = (pic_u8)(0x42 + i);
	}
#else
	(void)random_addr;
#endif
}

PIC_TEXT
static pic_uintptr reserve_random_block(
	pic_uintptr top, pic_uintptr *random_addr)
{
#if !defined(PICBLOBS_OS_FREEBSD)
	top -= 16U;
	*random_addr = top;
	fill_at_random(*random_addr);
#else
	*random_addr = 0;
#endif
	return top;
}

PIC_TEXT
static pic_uintptr *push_auxv_entry(
	pic_uintptr *sp, pic_uintptr tag, pic_uintptr value, const char *name)
{
	*sp++ = tag;
	*sp++ = value;
	debug_log_aux_entry(name, value);
	return sp;
}

PIC_TEXT
static pic_uintptr *push_linux_auxv(pic_uintptr *sp, pic_uintptr random_addr)
{
#if !defined(PICBLOBS_OS_FREEBSD)
	sp = push_auxv_entry(sp, AT_UID, 0, "AT_UID");
	sp = push_auxv_entry(sp, AT_EUID, 0, "AT_EUID");
	sp = push_auxv_entry(sp, AT_GID, 0, "AT_GID");
	sp = push_auxv_entry(sp, AT_EGID, 0, "AT_EGID");
	sp = push_auxv_entry(sp, AT_SECURE, 0, "AT_SECURE");
	sp = push_auxv_entry(sp, AT_RANDOM, random_addr, "AT_RANDOM");
	sp = push_auxv_entry(sp, AT_HWCAP, 0, "AT_HWCAP");
	sp = push_auxv_entry(sp, AT_CLKTCK, 100, "AT_CLKTCK");
#else
	(void)random_addr;
#endif
	return sp;
}

PIC_TEXT
static pic_uintptr *push_auxv_entries(pic_uintptr *sp, Elf_Addr entry,
	Elf_Addr phdr_addr, Elf_Half phnum, Elf_Half phentsize,
	pic_uintptr interp_base, pic_uintptr random_addr)
{
	sp = push_auxv_entry(sp, AT_PHDR, phdr_addr, "AT_PHDR");
	sp = push_auxv_entry(sp, AT_PHENT, phentsize, "AT_PHENT");
	sp = push_auxv_entry(sp, AT_PHNUM, phnum, "AT_PHNUM");
	sp = push_auxv_entry(sp, AT_PAGESZ, PAGE_SIZE, "AT_PAGESZ");
	sp = push_auxv_entry(sp, AT_BASE, interp_base, "AT_BASE");
	sp = push_auxv_entry(sp, AT_FLAGS, 0, "AT_FLAGS");
	sp = push_auxv_entry(sp, AT_ENTRY, entry, "AT_ENTRY");
	sp = push_linux_auxv(sp, random_addr);
	*sp++ = AT_NULL;
	*sp++ = 0;
	return sp;
}

PIC_TEXT
static pic_uintptr build_stack(pic_u32 argc, const char *argv_data,
	pic_u32 argv_size, pic_u32 envp_count, const char *envp_data,
	pic_u32 envp_size, Elf_Addr entry, Elf_Addr phdr_addr, Elf_Half phnum,
	Elf_Half phentsize, pic_uintptr interp_base)
{
	pic_size_t stack_size = (pic_size_t)2 * 1024 * 1024;
	pic_uintptr stack_base = alloc_stack(stack_size);
	pic_uintptr top = (pic_uintptr)stack_base + stack_size;
	pic_uintptr random_addr = 0;
	pic_uintptr envp_str = 0;
	pic_uintptr argv_str = 0;
	pic_uintptr *sp = PIC_NULL;

	top = reserve_random_block(top, &random_addr);
	envp_str = copy_string_block(top, envp_data, envp_size);
	top = envp_str;
	argv_str = copy_string_block(top, argv_data, argv_size);
	top = align_initial_stack_top(argv_str, argc, envp_count);

	sp = (pic_uintptr *)top;
	*sp++ = (pic_uintptr)argc;
	sp = push_string_vector(sp, argc, argv_str);
	sp = push_string_vector(sp, envp_count, envp_str);
	/* Final write to the stack; the returned (advanced) sp is unused — the
	 * trampoline jumps with `top`, the initial stack pointer. */
	push_auxv_entries(sp, entry, phdr_addr, phnum, phentsize, interp_base,
		random_addr);

	PIC_LOG("ul_exec: stack argc=%d envc=%d top=%x final_sp=%x\n",
		(long)argc, (long)envp_count,
		(unsigned long)(stack_base + stack_size), (unsigned long)top);

	return top;
}

/* ----------------------------------------------------------------
 * Jump to loaded ELF
 * ---------------------------------------------------------------- */

/*
 * Jump trampoline: set the stack pointer and branch to the ELF entry.
 *
 * Critical: we must load BOTH values into known registers BEFORE
 * touching sp, because the compiler may place an operand in the
 * stack pointer register if we use generic "r" constraints.
 */
PIC_TEXT
#if defined(__x86_64__)
__attribute__((noreturn)) static void jump_to_entry_x86_64_freebsd(
	pic_uintptr entry, pic_uintptr sp)
{
	__asm__ volatile("mov %[e], %%r11\n"
			 "mov %[s], %%r10\n"
			 "mov %%r10, %%rdi\n"
			 "mov %%r10, %%rsp\n"
			 "xor %%rdx, %%rdx\n"
			 "xor %%rax, %%rax\n"
			 "jmp *%%r11\n"
		:
		: [s] "r"(sp), [e] "r"(entry)
		: "r10", "r11", "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__x86_64__)
__attribute__((noreturn)) static void jump_to_entry_x86_64_linux(
	pic_uintptr entry, pic_uintptr sp)
{
	__asm__ volatile("mov %[e], %%r11\n"
			 "mov %[s], %%r10\n"
			 "mov %%r10, %%rsp\n"
			 "xor %%rdx, %%rdx\n"
			 "xor %%rax, %%rax\n"
			 "jmp *%%r11\n"
		:
		: [s] "r"(sp), [e] "r"(entry)
		: "r10", "r11", "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__i386__)
__attribute__((noreturn)) static void jump_to_entry_i386(
	pic_uintptr entry, pic_uintptr sp)
{
	__asm__ volatile("mov %[s], %%ecx\n"
			 "mov %[e], %%eax\n"
			 "mov %%ecx, %%esp\n"
			 "xor %%edx, %%edx\n"
			 "jmp *%%eax\n"
		:
		: [s] "g"((unsigned)sp), [e] "g"((unsigned)entry)
		: "eax", "ecx", "edx", "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__aarch64__)
__attribute__((noreturn)) static void jump_to_entry_aarch64(
	pic_uintptr entry, pic_uintptr sp)
{
	register pic_uintptr x2 __asm__("x2") = entry;
	register pic_uintptr x3 __asm__("x3") = sp;
	__asm__ volatile("mov sp, %[s]\n"
			 "mov x0, #0\n"
			 "br %[e]\n"
		:
		: [s] "r"(x3), [e] "r"(x2)
		: "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__arm__)
__attribute__((noreturn)) static void jump_to_entry_arm(
	pic_uintptr entry, pic_uintptr sp)
{
	register unsigned r2 __asm__("r2") = (unsigned)entry;
	register unsigned r3 __asm__("r3") = (unsigned)sp;
	__asm__ volatile("mov sp, %[s]\n"
			 "mov r0, #0\n"
			 "bx %[e]\n"
		:
		: [s] "r"(r3), [e] "r"(r2)
		: "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__mips__)
__attribute__((noreturn)) static void jump_to_entry_mips(
	pic_uintptr entry, pic_uintptr sp)
{
	__asm__ volatile("move $t0, %[s]\n"
			 "move $t9, %[e]\n"
			 "move $sp, $t0\n"
			 "jr $t9\n"
			 "  nop\n"
		:
		: [s] "r"((unsigned)sp), [e] "r"((unsigned)entry)
		: "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__s390x__)
__attribute__((noreturn)) static void jump_to_entry_s390x(
	pic_uintptr entry, pic_uintptr sp)
{
	register pic_uintptr _e __asm__("r1") = entry;
	register pic_uintptr _s __asm__("r3") = sp;
	__asm__ volatile("lgr %%r15, %%r3\n"
			 "xgr %%r2, %%r2\n"
			 "br %%r1\n"
		:
		: "r"(_e), "r"(_s)
		: "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__sparc__)
__attribute__((noreturn)) static void jump_to_entry_sparc(
	pic_uintptr entry, pic_uintptr sp)
{
	register pic_uintptr _e __asm__("o1") = entry;
	register pic_uintptr _s __asm__("o2") = sp;
	__asm__ volatile("mov %%o2, %%sp\n"
			 "clr %%o0\n"
			 "jmp %%o1\n"
			 " nop\n"
		:
		: "r"(_e), "r"(_s)
		: "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__riscv)
__attribute__((noreturn)) static void jump_to_entry_riscv(
	pic_uintptr entry, pic_uintptr sp)
{
	register pic_uintptr _e __asm__("a1") = entry;
	register pic_uintptr _s __asm__("a2") = sp;
	__asm__ volatile("mv sp, %1\n"
			 "li a0, 0\n"
			 "jr %0\n"
		:
		: "r"(_e), "r"(_s)
		: "memory");
	__builtin_unreachable();
}
#endif

PIC_TEXT
#if defined(__powerpc__)
__attribute__((noreturn)) static void jump_to_entry_powerpc(
	pic_uintptr entry, pic_uintptr sp)
{
	register pic_uintptr _e __asm__("r12") = entry;
	register pic_uintptr _s __asm__("r11") = sp;
	__asm__ volatile("mr 1, %[s]\n"
			 "li 3, 0\n"
			 "mtctr %[e]\n"
			 "bctr\n"
		:
		: [s] "r"(_s), [e] "r"(_e)
		: "memory");
	__builtin_unreachable();
}
#endif

#if defined(__x86_64__)
#if defined(PICBLOBS_OS_FREEBSD)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_x86_64_freebsd(entry, sp)
#else
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_x86_64_linux(entry, sp)
#endif

#elif defined(__i386__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_i386(entry, sp)

#elif defined(__aarch64__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_aarch64(entry, sp)

#elif defined(__arm__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_arm(entry, sp)

#elif defined(__mips__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_mips(entry, sp)

#elif defined(__s390x__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_s390x(entry, sp)

#elif defined(__sparc__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_sparc(entry, sp)

#elif defined(__riscv)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_riscv(entry, sp)

#elif defined(__powerpc__)
#define PIC_JUMP_TO_ENTRY(entry, sp) jump_to_entry_powerpc(entry, sp)

#else
#error "unsupported architecture"
#endif

PIC_TEXT
__attribute__((noreturn)) static void jump_to_entry(
	pic_uintptr entry, pic_uintptr sp)
{
	PIC_JUMP_TO_ENTRY(entry, sp);
}

/* ----------------------------------------------------------------
 * Phase 2 — the real ul_exec, runs from the safe high mapping.
 *
 * At this point the blob is executing from a high address and the
 * entire original address space is available for the target ELF.
 * ---------------------------------------------------------------- */

PIC_TEXT
static const Elf_Phdr *find_interp_phdr(
	const pic_u8 *elf_data, pic_u32 elf_size, const Elf_Ehdr *ehdr)
{
	const Elf_Phdr *phdr = (const Elf_Phdr *)(elf_data + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_INTERP) {
			return &phdr[i];
		}
	}
	return PIC_NULL;
}

PIC_TEXT
static const char *interp_path_from_phdr(
	const pic_u8 *elf_data, pic_u32 elf_size, const Elf_Phdr *interp_phdr)
{
	if (!interp_phdr) {
		return PIC_NULL;
	}
	if (interp_phdr->p_offset + interp_phdr->p_filesz > elf_size) {
		return PIC_NULL;
	}

	const char *s = (const char *)(elf_data + interp_phdr->p_offset);
	for (Elf_Off j = 0; j < interp_phdr->p_filesz; j++) {
		if (s[j] == '\0') {
			return s;
		}
	}
	return PIC_NULL;
}

PIC_TEXT
static void maybe_clean_exec_range(const Elf_Ehdr *ehdr, const Elf_Phdr *phdr)
{
	if (ehdr->e_type != ET_EXEC) {
		return;
	}

#if defined(__powerpc__) && !defined(__powerpc64__)
	/*
	 * MAP_FIXED replaces overlapping mappings on Linux already.
	 * Under qemu-ppc user mode, eagerly unmapping the target range
	 * can tear down emulation state before the replacement mapping.
	 */
#else
	pic_uintptr vmin = 0;
	pic_uintptr vmax = 0;
	if (find_load_range(ehdr, phdr, &vmin, &vmax)) {
		vmin = PAGE_ALIGN_DOWN(vmin);
		vmax = PAGE_ALIGN_UP(vmax);
		PIC_LOG("ul_exec: cleaning %x - %x\n", (long)vmin, (long)vmax);
		pic_munmap((void *)vmin, vmax - vmin);
	}
#endif
}

PIC_TEXT
static void validate_elf_config(
	const struct ul_exec_config *cfg, const Elf_Ehdr *ehdr)
{
	if (0 == validate_elf_image(ehdr, cfg->elf_size)) {
		pic_exit_group(100);
	}
}

PIC_TEXT
__attribute__((noreturn)) static void phase2(const struct ul_exec_config *cfg)
{
	const pic_u8 *elf_data = (const pic_u8 *)(cfg + 1);
	const char *argv_data = (const char *)(elf_data + cfg->elf_size);
	const char *envp_data = argv_data + cfg->argv_size;
	const Elf_Ehdr *ehdr = (const Elf_Ehdr *)elf_data;
	const Elf_Phdr *phdr = 0;
	const char *interp_path = 0;
	Elf_Addr phdr_addr = 0;
	pic_uintptr elf_base = 0;
	Elf_Addr entry = 0;
	pic_uintptr interp_base = 0;
	pic_uintptr interp_entry = 0;
	pic_uintptr sp = 0;
	pic_uintptr target = 0;

	validate_elf_config(cfg, ehdr);

	PIC_LOG("ul_exec: elf_size=%d type=%d entry=%x phnum=%d\n",
		(long)cfg->elf_size, (long)ehdr->e_type, (long)ehdr->e_entry,
		(long)ehdr->e_phnum);

	phdr = (const Elf_Phdr *)(elf_data + ehdr->e_phoff);
	interp_path = interp_path_from_phdr(elf_data, cfg->elf_size,
		find_interp_phdr(elf_data, cfg->elf_size, ehdr));
	maybe_clean_exec_range(ehdr, phdr);

	elf_base =
		load_elf_from_memory(elf_data, cfg->elf_size, ehdr, &phdr_addr);
	if (elf_base == (pic_uintptr)-1) {
		pic_exit_group(103);
	}

	entry = elf_base + ehdr->e_entry;
	PIC_LOG("ul_exec: loaded base=%x entry=%x\n", (long)elf_base,
		(long)entry);

	if (interp_path) {
		Elf_Addr ie_entry = 0;
		interp_base = load_interp(interp_path, &ie_entry);
		if (interp_base == (pic_uintptr)-1) {
			pic_exit_group(106);
		}
		interp_entry = interp_base + ie_entry;
		PIC_LOG("ul_exec: interp base=%x entry=%x\n", (long)interp_base,
			(long)interp_entry);
	}

	sp = build_stack(cfg->argc, argv_data, cfg->argv_size, cfg->envp_count,
		envp_data, cfg->envp_size, entry, phdr_addr, ehdr->e_phnum,
		ehdr->e_phentsize, interp_base);

	target = interp_entry ? interp_entry : entry;

	PIC_LOG("ul_exec: jumping to %x (sp=%x)\n", (long)target, (long)sp);

	jump_to_entry(target, sp);
}

/* ----------------------------------------------------------------
 * Entry point — phase 1: self-remap then hand off to phase 2.
 * ---------------------------------------------------------------- */

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	extern char ul_exec_config[] __attribute__((visibility("hidden")));
	extern char __blob_start[] __attribute__((visibility("hidden")));
	const struct ul_exec_config *cfg =
		(const struct ul_exec_config *)(void *)ul_exec_config;

	/*
	 * Compute total size of the blob binary in memory.
	 * The blob starts at __blob_start (offset 0) and the config
	 * data (including variable-length elf+argv+envp) follows at
	 * ul_exec_config.  Total = config_start + config_header +
	 * elf_size + argv_size + envp_size.
	 */
	pic_uintptr blob_base = (pic_uintptr)__blob_start;
	pic_uintptr cfg_start = (pic_uintptr)ul_exec_config;
	pic_size_t total_size = (cfg_start - blob_base) +
		sizeof(struct ul_exec_config) + cfg->elf_size + cfg->argv_size +
		cfg->envp_size;

	/* Remap ourselves to a safe high address, then phase2 takes over. */
#if defined(__powerpc__) && !defined(__powerpc64__)
	(void)blob_base;
	(void)cfg_start;
	(void)total_size;
	phase2(cfg);
#else
	self_remap(blob_base, total_size, cfg);
#endif
}
