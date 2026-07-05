/*
 * stager_pipe — named pipe (FIFO) stager.
 *
 * Opens a FIFO path from the config, reads a length-prefixed payload,
 * allocates RWX memory, and jumps to it.
 *
 * Config layout:
 *   +0x00: path_len (u16, little-endian)
 *   +0x02: path (path_len bytes, NOT null-terminated in config —
 *          but C open() needs a NUL; we copy to a local buffer and
 *          NUL-terminate)
 *
 * Wire protocol on the FIFO:
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
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"
#include "picblobs/types.h"

/* Enough for typical test paths; bounded to avoid blowing the small
 * stack QEMU user-mode provides on 32-bit archs. */
#define PATH_MAX_LEN 256

/*
 * ASM config anchor. 2-byte length, then up to PATH_MAX_LEN path bytes.
 */
__asm__(".section .config,\"aw\"\n"
	".globl stager_pipe_config\n"
	"stager_pipe_config:\n"
	".space 2\n"
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

PIC_TEXT
static int load_path(const pic_u8 *cfg, char path[PATH_MAX_LEN])
{
	pic_u16 path_len = (pic_u16)cfg[0] | ((pic_u16)cfg[1] << 8);
	if (path_len == 0 || path_len >= PATH_MAX_LEN) {
		return 0;
	}
	for (pic_u16 i = 0; i < path_len; i++) {
		path[i] = (char)cfg[2 + i];
	}
	path[path_len] = '\0';
	return 1;
}

PIC_TEXT
static pic_u32 read_payload_size(int fd)
{
	pic_u8 size_buf[4] = {0};
	if (read_all(fd, size_buf, 4) < 0) {
		return 0;
	}
	return (pic_u32)size_buf[0] | ((pic_u32)size_buf[1] << 8) |
		((pic_u32)size_buf[2] << 16) | ((pic_u32)size_buf[3] << 24);
}

PIC_TEXT
static void *alloc_payload(pic_u32 size)
{
	return pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
}

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	extern char stager_pipe_config[] __attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)stager_pipe_config;

	/* Copy path into a NUL-terminated buffer on the stack. */
	char path[PATH_MAX_LEN];
	if (!load_path(cfg, path)) {
		pic_exit_group(1);
	}

	int fd = (int)pic_open(path, PIC_O_RDONLY, 0);
	if (fd < 0) {
		pic_exit_group(1);
	}

	pic_u32 size = read_payload_size(fd);
	if (size == 0 || size > 0x10000000) {
		pic_close(fd);
		pic_exit_group(1);
	}

	void *mem = alloc_payload(size);
	if ((long)mem == -1) {
		pic_close(fd);
		pic_exit_group(1);
	}

	if (read_all(fd, mem, (pic_size_t)size) < 0) {
		pic_close(fd);
		pic_exit_group(1);
	}
	pic_close(fd);
	pic_sync_icache(mem, (pic_size_t)size);

#if defined(__thumb__)
	((void (*)(void))((pic_uintptr)mem | 1))();
#else
	((void (*)(void))mem)();
#endif

	pic_exit_group(0);
}
