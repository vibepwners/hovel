/*
 * stager_mmap — memory-mapped file stager.
 *
 * Opens a file from a path in the config, reads ``size`` bytes
 * starting at ``offset`` into an anonymous RWX region, and jumps.
 * We don't use a file-backed mmap for the executable region because
 * many kernels refuse PROT_EXEC on files from noexec-mounted tmpdirs
 * (exactly what pytest uses). Anonymous RWX + pic_read sidesteps it.
 *
 * Config layout (wire byte order is little-endian on all targets):
 *   +0x00: path_len (u16)
 *   +0x02: path (path_len bytes, not NUL-terminated)
 *   +0x02+path_len:      offset (u64, low 32 bits used)
 *   +0x0a+path_len:      size   (u64, low 32 bits used)
 *
 * Offset and size are serialized as 64 bits for future-proofing but
 * only the low 32 bits are honored here — PIC blobs don't realistically
 * stage payloads larger than 256 MiB and 32-bit archs would truncate a
 * 64-bit offset anyway.
 */

#include "picblobs/cache.h"
#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/lseek.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"
#include "picblobs/types.h"

/* Enough for typical test / staging paths. PIC blobs run on a small
 * stack (QEMU user-mode caps us well below a host page), so keep this
 * modest to avoid stack overflow on 32-bit archs. */
#define PATH_MAX_LEN 256

__asm__(".section .config,\"aw\"\n"
	".globl stager_mmap_config\n"
	"stager_mmap_config:\n"
	".space 2\n"
	".previous\n");

static inline __attribute__((always_inline)) pic_u32 read_u32_le(
	const pic_u8 *p)
{
	return (pic_u32)p[0] | ((pic_u32)p[1] << 8) | ((pic_u32)p[2] << 16) |
		((pic_u32)p[3] << 24);
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
static int seek_payload(int fd, pic_u32 offset)
{
	if (offset == 0) {
		return 1;
	}
	return pic_lseek(fd, (long)offset, PIC_SEEK_SET) >= 0;
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

	extern char stager_mmap_config[] __attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)stager_mmap_config;

	char path[PATH_MAX_LEN];
	if (!load_path(cfg, path)) {
		pic_exit_group(1);
	}

	pic_u16 path_len = (pic_u16)cfg[0] | ((pic_u16)cfg[1] << 8);
	pic_u32 offset = read_u32_le(cfg + 2 + path_len);
	pic_u32 size = read_u32_le(cfg + 2 + path_len + 8);
	if (size == 0 || size > 0x10000000) {
		pic_exit_group(1);
	}

	int fd = (int)pic_open(path, PIC_O_RDONLY, 0);
	if (fd < 0) {
		pic_exit_group(1);
	}

	/* Skip bytes before the target segment. On 32-bit MIPS pic_lseek wraps
	 * llseek which takes hi/lo args — we only support offsets that fit in a
	 * signed long here, which is plenty for this stager's use cases. */
	if (!seek_payload(fd, offset)) {
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
