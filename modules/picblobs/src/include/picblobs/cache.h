/* picblobs/cache.h — instruction-cache synchronization helpers. */

#ifndef PICBLOBS_CACHE_H
#define PICBLOBS_CACHE_H

#include "picblobs/types.h"

#define PIC_CACHE_INLINE static inline __attribute__((always_inline))

PIC_CACHE_INLINE void pic_sync_icache_aarch64(void *addr, pic_size_t len)
{
#if defined(__aarch64__)
	pic_uintptr start = (pic_uintptr)addr;
	pic_uintptr end = start + len;
	unsigned long ctr;
	pic_uintptr dline;
	pic_uintptr iline;

	__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
	dline = (pic_uintptr)4U << ((ctr >> 16U) & 0xfU);
	iline = (pic_uintptr)4U << (ctr & 0xfU);

	for (pic_uintptr p = start & ~(dline - 1U); p < end; p += dline) {
		__asm__ volatile("dc cvau, %0" : : "r"(p) : "memory");
	}
	__asm__ volatile("dsb ish" ::: "memory");
	for (pic_uintptr p = start & ~(iline - 1U); p < end; p += iline) {
		__asm__ volatile("ic ivau, %0" : : "r"(p) : "memory");
	}
	__asm__ volatile("dsb ish\n\tisb" ::: "memory");
#else
	(void)addr;
	(void)len;
#endif
}

PIC_CACHE_INLINE void pic_sync_icache_arm(void *addr, pic_size_t len)
{
#if defined(__arm__)
	register long r7 __asm__("r7") = 0x0f0002L;
	register long r0 __asm__("r0") = (long)addr;
	register long r1 __asm__("r1") = (long)((pic_uintptr)addr + len);
	register long r2 __asm__("r2") = 0;
	__asm__ volatile("svc #0"
		: "+r"(r0)
		: "r"(r7), "r"(r1), "r"(r2)
		: "memory");
#else
	(void)addr;
	(void)len;
#endif
}

PIC_CACHE_INLINE void pic_sync_icache_mips(void *addr, pic_size_t len)
{
#if defined(__mips__)
	register long v0 __asm__("$2") = 4147L;
	register long r4 __asm__("$4") = (long)addr;
	register long r5 __asm__("$5") = (long)len;
	register long r6 __asm__("$6") = 3L;
	__asm__ volatile(".set noreorder\n\t"
			 "syscall\n\t"
			 ".set reorder\n\t"
		: "+r"(v0)
		: "r"(r4), "r"(r5), "r"(r6)
		: "memory", "$3", "$7", "$8", "$9", "$10", "$11", "$12", "$13",
		"$14", "$15", "$24", "$25");
#else
	(void)addr;
	(void)len;
#endif
}

PIC_CACHE_INLINE void pic_sync_icache(void *addr, pic_size_t len)
{
	if (len == 0) {
		return;
	}
#if defined(__aarch64__)
	pic_sync_icache_aarch64(addr, len);
#elif defined(__arm__)
	pic_sync_icache_arm(addr, len);
#elif defined(__mips__)
	pic_sync_icache_mips(addr, len);
#elif defined(__riscv)
	(void)addr;
	__asm__ volatile("fence.i" ::: "memory");
#else
	(void)addr;
	__asm__ volatile("" ::: "memory");
#endif
}

#undef PIC_CACHE_INLINE

#endif /* PICBLOBS_CACHE_H */
