/*
 * picblobs/mem.h — freestanding memory operations.
 *
 * Provides both pic_* wrappers (for direct use) and actual memcpy/memset
 * symbol definitions. The latter are necessary because GCC may emit calls
 * to memcpy/memset even with -fno-builtin (via loop distribution or when
 * lowering __builtin_memset for non-trivial sizes). Without real symbols,
 * these calls go through PLT → segfault in PIC blobs.
 */

#ifndef PICBLOBS_MEM_H
#define PICBLOBS_MEM_H

#include "picblobs/types.h"

/*
 * Actual memcpy/memset/memcmp symbols — the linker resolves GCC's
 * internal calls to these instead of going through PLT.
 * Marked used+noinline so GCC doesn't optimize them away or re-expand
 * them into themselves (infinite recursion).
 */
__attribute__((used, noinline)) static void *memcpy(
	void *dst, const void *src, pic_size_t n)
{
	pic_u8 *d = (pic_u8 *)dst;
	const pic_u8 *s = (const pic_u8 *)src;
	while (n--) {
		*d++ = *s++;
	}
	return dst;
}

__attribute__((used, noinline)) static void *memset(
	void *dst, int c, pic_size_t n)
{
	pic_u8 *d = (pic_u8 *)dst;
	while (n--) {
		*d++ = (pic_u8)c;
	}
	return dst;
}

__attribute__((used, noinline)) static int memcmp(
	const void *a, const void *b, pic_size_t n)
{
	const pic_u8 *pa = (const pic_u8 *)a;
	const pic_u8 *pb = (const pic_u8 *)b;
	while (n--) {
		if (*pa != *pb) {
			return *pa - *pb;
		}
		pa++;
		pb++;
	}
	return 0;
}

/* Convenience wrappers with pic_ prefix. */
static inline void *pic_memcpy(void *dst, const void *src, pic_size_t n)
{
	return memcpy(dst, src, n);
}

static inline void *pic_memset(void *dst, int c, pic_size_t n)
{
	return memset(dst, c, n);
}

static inline int pic_memcmp(const void *a, const void *b, pic_size_t n)
{
	return memcmp(a, b, n);
}

#endif /* PICBLOBS_MEM_H */
