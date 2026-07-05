/*
 * picblobs/reloc.h — self-relocation for PIC blobs.
 *
 * On MIPS32 and PowerPC32, PIC code needs architecture-specific startup
 * relocation before any global data access works correctly.
 *
 * On x86_64, aarch64, ARM, i686, s390x, SPARC: no-op
 * (PC-relative addressing or no runtime relocations in the blob format).
 */

#ifndef PICBLOBS_RELOC_H
#define PICBLOBS_RELOC_H

#include "picblobs/arch.h"

#if PIC_ARCH_NEEDS_GOT_RELOC

/*
 * MIPS self-relocation. Called from the user's entry function after the
 * MIPS trampoline established $gp and saved the runtime blob base in $s0.
 */
#if defined(__mips__)
#define PIC_SELF_RELOCATE()                                                    \
	do {                                                                   \
		unsigned long _got_s, _got_e, _delta;                          \
		/* $gp is set correctly by .cpload $t9 (trampoline set $t9).   \
		 */                                                            \
		/* Load __got_start and __got_end from GOT (link-time values). \
		 */                                                            \
		__asm__ volatile("lw %0, %%got(__got_start)($gp)\n\t"          \
				 "lw %1, %%got(__got_end)($gp)\n\t"            \
			: "=r"(_got_s), "=r"(_got_e));                         \
		/* $s0 = runtime base (delta), set by the MIPS trampoline. */  \
		/* link-time base = 0, so delta = runtime base. */             \
		__asm__ volatile("move %0, $s0" : "=r"(_delta));               \
		if (_delta != 0) {                                             \
			unsigned long *p = (unsigned long *)(_got_s + _delta); \
			unsigned long *e = (unsigned long *)(_got_e + _delta); \
			while (p < e) {                                        \
				*p += _delta;                                  \
				p++;                                           \
			}                                                      \
		}                                                              \
	} while (0)

#elif defined(__powerpc__)

/*
 * PowerPC32 self-relocation. GCC materializes the PIC base in r30 and
 * addresses globals through the GOT using link-time blob-relative
 * pointers. We patch each non-zero GOT slot by adding the runtime base.
 */
#define PIC_SELF_RELOCATE()                                                    \
	do {                                                                   \
		unsigned long _r30;                                            \
		unsigned long _got_s_link;                                     \
		unsigned long _got_e_link;                                     \
		__asm__ volatile("mr %0, 30" : "=r"(_r30));                    \
		__asm__ volatile("lis %0, __got_start@ha\n\t"                  \
				 "addi %0, %0, __got_start@l\n\t"              \
				 "lis %1, __got_end@ha\n\t"                    \
				 "addi %1, %1, __got_end@l"                    \
			: "=&r"(_got_s_link), "=&r"(_got_e_link));             \
		unsigned long _delta = (_r30 - 32768ul) - _got_s_link;         \
		if (_delta != 0) {                                             \
			unsigned long *p =                                     \
				(unsigned long *)(_delta + _got_s_link);       \
			unsigned long *e =                                     \
				(unsigned long *)(_delta + _got_e_link);       \
			while (p < e) {                                        \
				if (*p) {                                      \
					*p += _delta;                          \
				}                                              \
				p++;                                           \
			}                                                      \
		}                                                              \
	} while (0)

#else

#define PIC_SELF_RELOCATE() ((void)0)

#endif
#else

#define PIC_SELF_RELOCATE() ((void)0)

#endif

#endif /* PICBLOBS_RELOC_H */
