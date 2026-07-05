/*
 * picblobs/platform.h — hosted platform vtable for PIC blobs.
 *
 * When PIC_PLATFORM_HOSTED is defined, blobs call into the host
 * environment via function pointers instead of raw syscalls.
 * This enables running blobs on RTOSes (e.g., Mbed OS) or other
 * non-Linux environments.
 *
 * The host (runner) populates a pic_platform struct and passes
 * it to the blob's _start(). The blob stores the pointer and
 * all pic_* wrappers call through it.
 */

#ifndef PICBLOBS_PLATFORM_H
#define PICBLOBS_PLATFORM_H

#include "picblobs/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pic_platform {
	/* I/O */
	long (*write)(int fd, const void *buf, pic_size_t count);
	long (*read)(int fd, void *buf, pic_size_t count);
	long (*close)(int fd);

	/* Networking */
	long (*socket)(int domain, int type, int protocol);
	long (*bind)(int fd, const void *addr, pic_size_t addrlen);
	long (*listen)(int fd, int backlog);
	long (*accept)(int fd, void *addr, void *addrlen);
	long (*connect)(int fd, const void *addr, pic_size_t addrlen);
	long (*setsockopt)(int fd, int level, int optname, const void *optval,
		pic_size_t optlen);

	/* Crypto */
	void (*randombytes)(unsigned char *buf, unsigned long long len);

	/* Lifecycle */
	void (*exit_group)(int code);
};

#ifdef __cplusplus
}
#endif

/*
 * Global platform pointer — set once by _start(), used by all
 * pic_* wrappers in hosted mode. Safe because blobs are single-TU
 * and this header is guarded.
 */
static const struct pic_platform *__pic_plat __attribute__((unused));

#define PIC_PLATFORM_INIT(p) (__pic_plat = (p))

#endif /* PICBLOBS_PLATFORM_H */
