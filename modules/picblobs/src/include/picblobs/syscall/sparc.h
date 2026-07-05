/*
 * pic_raw_syscall — SPARC v8 Linux (ta 0x10).
 *
 * Syscall number in %g1, arguments in %o0-%o5, return value in %o0.
 * Linux reports failure via the carry bit with %o0 holding a positive
 * errno; we negate it to match the convention used by the other ports.
 */

static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long g1 __asm__("g1") = n;
	register long o0 __asm__("o0") = a0;
	register long o1 __asm__("o1") = a1;
	register long o2 __asm__("o2") = a2;
	register long o3 __asm__("o3") = a3;
	register long o4 __asm__("o4") = a4;
	register long o5 __asm__("o5") = a5;

	__asm__ volatile("ta 0x10\n\t"
			 "bcc 1f\n\t"
			 " nop\n\t"
			 "sub %%g0, %0, %0\n"
			 "1:"
		: "+r"(o0)
		: "r"(g1), "r"(o1), "r"(o2), "r"(o3), "r"(o4), "r"(o5)
		: "memory", "cc");
	return o0;
}
