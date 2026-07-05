/*
 * picblobs/win/teb.h — TEB access for Windows PIC blobs (REQ-005).
 *
 * On Windows x86_64, the TEB is accessed via the gs segment register.
 * gs:[0x30] is the TEB self-pointer, and the PEB pointer is at TEB+0x60.
 *
 * This is the one piece of architecture-specific assembly required
 * for Windows targets beyond the syscall primitive.
 */

#ifndef PICBLOBS_WIN_TEB_H
#define PICBLOBS_WIN_TEB_H

#include "picblobs/arch.h"
#include "picblobs/section.h"
#include "picblobs/types.h"

#if defined(__x86_64__)

/* Read the TEB base address from gs:[0x30] (64-bit Windows). */
PIC_TEXT
static inline void *pic_get_teb(void)
{
	void *teb = 0;
	__asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
	return teb;
}

#elif defined(__i386__)

/* Read the TEB base address from fs:[0x18] (32-bit Windows). */
PIC_TEXT
static inline void *pic_get_teb(void)
{
	void *teb;
	__asm__ volatile("mov %%fs:0x18, %0" : "=r"(teb));
	return teb;
}

#elif defined(__aarch64__)

/*
 * On Windows ARM64, the TEB is accessed via the x18 register
 * (the platform register, reserved by AAPCS and not used by GCC).
 */
PIC_TEXT
static inline void *pic_get_teb(void)
{
	void *teb;
	__asm__ volatile("mov %0, x18" : "=r"(teb));
	return teb;
}

#else
#error "pic_get_teb: unsupported architecture"
#endif

/*
 * Get PEB pointer from TEB.
 *   64-bit (x86_64, aarch64): TEB+0x60
 *   32-bit (i686):            TEB+0x30
 */
PIC_TEXT
static inline void *pic_get_peb(void *teb)
{
#if PIC_ARCH_IS_32BIT
	return *(void **)((pic_u8 *)teb + 0x30);
#else
	return *(void **)((pic_u8 *)teb + 0x60);
#endif
}

#endif /* PICBLOBS_WIN_TEB_H */
