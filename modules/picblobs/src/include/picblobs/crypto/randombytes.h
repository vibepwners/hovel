/*
 * picblobs/crypto/randombytes.h — cryptographic random bytes via /dev/urandom.
 *
 * Provides the randombytes() function required by TweetNaCl.
 * Uses open("/dev/urandom") + read() syscalls — no libc needed.
 *
 * Include AFTER picblobs OS and syscall headers.
 */

#ifndef PICBLOBS_CRYPTO_RANDOMBYTES_H
#define PICBLOBS_CRYPTO_RANDOMBYTES_H

#define RANDOMBYTES_DEFINED 1

#ifdef PIC_PLATFORM_HOSTED
#include "picblobs/platform.h"

static void randombytes(unsigned char *x, unsigned long long xlen)
{
	__pic_plat->randombytes(x, xlen);
}

#else /* !PIC_PLATFORM_HOSTED */

#include "picblobs/sys/close.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/open.h"
#include "picblobs/sys/read.h"

static void randombytes(unsigned char *x, unsigned long long xlen)
{
	static const char path[] = "/dev/urandom";
	int fd = 0;
	long n = 0;

	fd = (int)pic_open(path, PIC_O_RDONLY, 0);
	if (fd < 0) {
		pic_exit_group(90);
	}

	while (xlen > 0) {
		n = pic_read(fd, x, (pic_size_t)xlen);
		if (n <= 0) {
			pic_close(fd);
			pic_exit_group(91);
		}
		x += n;
		xlen -= (unsigned long long)n;
	}

	pic_close(fd);
}

#endif /* !PIC_PLATFORM_HOSTED */

#endif /* PICBLOBS_CRYPTO_RANDOMBYTES_H */
