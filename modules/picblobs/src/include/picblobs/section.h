/*
 * picblobs/section.h — section placement macros for PIC blobs.
 *
 * Usage:
 *
 *   PIC_ENTRY
 *   void _start(void) { ... }
 *
 *   PIC_TEXT
 *   static void do_work(void) { ... }
 *
 *   PIC_RODATA
 *   static const char banner[] = "hello";
 */

#ifndef PICBLOBS_SECTION_H
#define PICBLOBS_SECTION_H

#include "picblobs/arch.h"

/*
 * On MIPS, PIC code needs $t9 set to the function address for .cpload
 * to compute $gp correctly. Since nobody sets $t9 when jumping to a
 * blob, PIC_ENTRY emits an asm trampoline at the very start that
 * discovers PC via bal and sets $t9 before the real entry function.
 *
 * The user writes:
 *   PIC_ENTRY void _start(void) { PIC_SELF_RELOCATE(); ... }
 *
 * On MIPS, this becomes:
 *   _pic_trampoline (asm, byte 0): bal → set $t9 → jalr _start
 *   _start (C, with working .cpload $t9): PIC_SELF_RELOCATE → user code
 *
 * On all other arches, PIC_ENTRY just places _start at byte 0 directly.
 */

#if PIC_ARCH_NEEDS_TRAMPOLINE

/*
 * MIPS trampoline: placed in .text.pic_trampoline (before .text.pic_entry
 * in the linker script). Uses bal to get PC, computes the address of the
 * user's _start, sets $t9, and calls it.
 *
 * Layout after linking:
 *   offset 0: _pic_trampoline (this asm)
 *   offset N: _start (user's PIC_ENTRY function)
 *
 * The trampoline knows the offset of _start from itself because the
 * linker resolves the `la $t9, _start` instruction.
 */
__asm__(".section .text.pic_trampoline, \"ax\", @progbits\n"
	".globl _pic_trampoline\n"
	".ent _pic_trampoline\n"
	".set noreorder\n"
	"_pic_trampoline:\n"
	"  bal    1f\n" /* $ra = runtime address of 1f */
	"  nop\n"
	"1:\n"
	"  .cpload $ra\n" /* $gp = $ra + _gp_disp (runtime GP) */
	"  lw     $t9, %got(_start)($gp)\n" /* link-time _start from GOT */
	"  subu   $t0, $ra, $t9\n" /* $t0 = runtime 1f - linktime _start */
	"                           \n"
	"  /* But we need: $t9 = runtime _start.                      */\n"
	"  /* runtime 1f = $ra. link-time 1f is a known constant.     */\n"
	"  /* delta = $ra - linktime_1f.                               */\n"
	"  /* But linktime_1f needs %hi/%lo which aren't allowed in   */\n"
	"  /* -shared. Use GOT instead:                                */\n"
	"  /* GOT[_start] = linktime _start. We already loaded it.    */\n"
	"  /* We know: runtime _start = linktime _start + delta.      */\n"
	"  /* And delta = runtime_base = runtime_trampoline - 0.      */\n"
	"  /* runtime_trampoline = $ra - 8 (bal is 2 insns back).     */\n"
	"  addiu  $t1, $ra, -8\n"  /* $t1 = runtime _pic_trampoline = runtime
				      base (base=0 in LD) */
	"  addu   $t9, $t9, $t1\n" /* $t9 = linktime _start + delta = runtime
				      _start */
	"  move   $s0, $t1\n"	   /* $s0 = runtime base (delta) for
				      PIC_SELF_RELOCATE */
	"  jalr   $t9\n"	   /* call _start with correct $t9 */
	"  nop\n"
	"  /* _start should not return, but if it does: */\n"
	"  li     $v0, 4246\n" /* exit_group */
	"  move   $a0, $zero\n"
	"  syscall\n"
	".set reorder\n"
	".end _pic_trampoline\n");

/* On MIPS, PIC_ENTRY goes to .text.pic_entry (after trampoline). */
#define PIC_ENTRY __attribute__((section(".text.pic_entry"), used))

#else

/* Entry point — always first in the blob. One per blob. */
#define PIC_ENTRY __attribute__((section(".text.pic_entry"), used))

#endif

/* General code — placed after the entry point. */
#define PIC_TEXT __attribute__((section(".text.pic_code"), used))

/* Read-only data — placed after all code. */
#define PIC_RODATA __attribute__((section(".rodata.pic"), used))

/* Writable initialized data. */
#define PIC_DATA __attribute__((section(".data.pic"), used))

/* Zero-initialized data. */
#define PIC_BSS __attribute__((section(".bss.pic"), used))

/* Config struct — appended by Python API at runtime. */
#define PIC_CONFIG __attribute__((section(".config"), used))

#endif /* PICBLOBS_SECTION_H */
