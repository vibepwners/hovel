#ifndef MBED_TRNG_API_H
#define MBED_TRNG_API_H

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define DEVICE_TRNG 1

typedef struct trng_s {
	int unused;
} trng_t;

static inline void trng_init(trng_t *obj) { (void)obj; }

static inline void trng_free(trng_t *obj) { (void)obj; }

static inline int trng_get_bytes(
	trng_t *obj, uint8_t *output, size_t length, size_t *output_length)
{
	(void)obj;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	ssize_t n = read(fd, output, length);
	close(fd);
	if (output_length) {
		*output_length = n > 0 ? (size_t)n : 0;
	}
	return n > 0 ? 0 : -1;
}

#endif /* MBED_TRNG_API_H */
