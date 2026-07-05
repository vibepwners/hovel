/*
 * alloc_jump payload for unix (Linux, FreeBSD).
 *
 * Allocates RWX memory via mmap, copies the inner payload from the
 * config trailing data, and transfers execution to it. Mirrors the
 * Windows variant (alloc_jump_windows.c) but uses raw syscalls
 * instead of kernel32.dll resolution.
 *
 * Config layout:
 *   +0x00: payload_size (u32, little-endian)
 *   +0x04: payload_data (payload_size bytes)
 */

#include "picblobs/cache.h"
#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/types.h"

/* Config struct (fixed header only). */
struct alloc_jump_config {
	pic_u32 payload_size;
	/* followed by payload_data[payload_size] */
};

/*
 * ASM config anchor — keeps the compiler from constant-folding the
 * initial zeros away before runtime patching.
 */
__asm__(".section .config,\"aw\"\n"
	".globl alloc_jump_config\n"
	"alloc_jump_config:\n"
	".space 4\n"
	".previous\n");

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	extern char alloc_jump_config[] __attribute__((visibility("hidden")));
	const pic_u8 *cfg_bytes = (const pic_u8 *)alloc_jump_config;

	/* Read the LE-packed size explicitly so the blob doesn't depend on
	 * the host CPU's byte order (mipsbe32 and s390x would otherwise
	 * interpret the little-endian config field backwards). */
	pic_u32 size = (pic_u32)cfg_bytes[0] | ((pic_u32)cfg_bytes[1] << 8) |
		((pic_u32)cfg_bytes[2] << 16) | ((pic_u32)cfg_bytes[3] << 24);
	if (size == 0 || size > 0x10000000) {
		pic_exit_group(1);
	}

	void *mem = pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)mem == -1) {
		pic_exit_group(1);
	}

	/*
	 * Inline byte copy. Using pic_memcpy() would emit a function call on
	 * some architectures (notably MIPS), which clobbers caller-saved
	 * registers — if the target-address temporary lives in such a
	 * register, the post-memcpy indirect call dispatches through
	 * garbage. Keeping the copy inline lets gcc schedule the loop
	 * without a cross-call dependency and preserves ``mem`` in a
	 * register that is live across the jump.
	 */
	const pic_u8 *src = cfg_bytes + sizeof(struct alloc_jump_config);
	pic_u8 *dst = (pic_u8 *)mem;
	for (pic_u32 i = 0; i < size; i++) {
		dst[i] = src[i];
	}
	pic_sync_icache(mem, (pic_size_t)size);

	/* Jump to payload; on ARM Thumb, set the LSB. */
#if defined(__thumb__)
	((void (*)(void))((pic_uintptr)mem | 1))();
#else
	((void (*)(void))mem)();
#endif

	pic_exit_group(0);
}
