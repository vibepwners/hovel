/*
 * runner_hosted.c — Linux test runner for PIC blobs in hosted mode.
 *
 * Like runner.c, but passes a pic_platform vtable to the blob instead
 * of relying on the blob doing raw syscalls. The vtable functions are
 * backed by the same Linux syscalls, proving the abstraction works.
 *
 * This runner is used to test the PIC_PLATFORM_HOSTED code path
 * without needing real Mbed OS hardware.
 */

#include "picblobs/os/linux.h"
#include "picblobs/platform.h"
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
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"
#include "picblobs/sys/setsockopt.h"
#include "picblobs/sys/socket.h"
#include "picblobs/sys/write.h"

#define RUNNER_ERROR 127

/* ---- Vtable callbacks (thin wrappers around Linux syscalls) ---- */

static long vt_write(int fd, const void *buf, pic_size_t count)
{
	return pic_write(fd, buf, count);
}

static long vt_read(int fd, void *buf, pic_size_t count)
{
	return pic_read(fd, buf, count);
}

static long vt_close(int fd) { return pic_close(fd); }

static long vt_socket(int domain, int type, int protocol)
{
	return pic_socket(domain, type, protocol);
}

static long vt_bind(int fd, const void *addr, pic_size_t addrlen)
{
	return pic_bind(fd, addr, addrlen);
}

static long vt_listen(int fd, int backlog) { return pic_listen(fd, backlog); }

static long vt_accept(int fd, void *addr, void *addrlen)
{
	return pic_accept(fd, addr, addrlen);
}

static long vt_connect(int fd, const void *addr, pic_size_t addrlen)
{
	return pic_connect(fd, addr, addrlen);
}

static long vt_setsockopt(
	int fd, int level, int optname, const void *optval, pic_size_t optlen)
{
	return pic_setsockopt(fd, level, optname, optval, optlen);
}

static void vt_randombytes(unsigned char *buf, unsigned long long len)
{
	static const char path[] = "/dev/urandom";
	int fd = (int)pic_open(path, PIC_O_RDONLY, 0);
	if (fd < 0) {
		pic_exit_group(90);
	}
	while (len > 0) {
		long n = pic_read(fd, buf, (pic_size_t)len);
		if (n <= 0) {
			pic_close(fd);
			pic_exit_group(91);
		}
		buf += n;
		len -= (unsigned long long)n;
	}
	pic_close(fd);
}

static void vt_exit_group(int code) { pic_exit_group(code); }

/* ---- Runner ---- */

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

/* Per-architecture _start — same as runner.c. */
#if defined(__arm__)
#include "start/arm.h"
#elif defined(__x86_64__)
#include "start/x86_64.h"
#elif defined(__aarch64__)
#include "start/aarch64.h"
#elif defined(__i386__)
#include "start/i386.h"
#elif defined(__mips__)
#include "start/mips.h"
#elif defined(__s390x__)
#include "start/s390x.h"
#else
#error "Unsupported architecture"
#endif

int runner_main(int argc, char **argv)
{
	if (argc < 2) {
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

	void *mem = pic_mmap(PIC_NULL, (pic_size_t)size,
		PIC_PROT_READ | PIC_PROT_WRITE | PIC_PROT_EXEC,
		PIC_MAP_PRIVATE | PIC_MAP_ANONYMOUS, -1, 0);
	if ((long)mem == -1) {
		pic_close(fd);
		pic_exit_group(RUNNER_ERROR);
	}

	if (read_all(fd, mem, (pic_size_t)size) < 0) {
		pic_close(fd);
		pic_exit_group(RUNNER_ERROR);
	}
	pic_close(fd);

	/* Build vtable. */
	struct pic_platform plat;
	plat.write = vt_write;
	plat.read = vt_read;
	plat.close = vt_close;
	plat.socket = vt_socket;
	plat.bind = vt_bind;
	plat.listen = vt_listen;
	plat.accept = vt_accept;
	plat.connect = vt_connect;
	plat.setsockopt = vt_setsockopt;
	plat.randombytes = vt_randombytes;
	plat.exit_group = vt_exit_group;

	/* Call blob with vtable. Thumb bit set for Thumb mode. */
	typedef void (*blob_entry_t)(const struct pic_platform *);
#ifdef __thumb__
	blob_entry_t entry = (blob_entry_t)((pic_uintptr)mem | 1);
#else
	blob_entry_t entry = (blob_entry_t)mem;
#endif
	entry(&plat);

	pic_exit_group(RUNNER_ERROR);
}
