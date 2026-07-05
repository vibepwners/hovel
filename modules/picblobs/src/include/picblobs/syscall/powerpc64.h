/*
 * pic_raw_syscall — PowerPC 64-bit Linux (sc).
 *
 * Syscall number in r0, arguments in r3-r8, return value in r3.
 * Linux reports failure via cr0.SO with r3 holding a positive errno;
 * negate it to match the convention used by the other ports.
 */

static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a0;
	register long r4 __asm__("r4") = a1;
	register long r5 __asm__("r5") = a2;
	register long r6 __asm__("r6") = a3;
	register long r7 __asm__("r7") = a4;
	register long r8 __asm__("r8") = a5;
	register long cr __asm__("r9");

	__asm__ volatile("sc\n\t"
			 "mfcr %0"
		: "=&r"(cr), "+r"(r3)
		: "r"(r0), "r"(r4), "r"(r5), "r"(r6), "r"(r7), "r"(r8)
		: "memory", "cr0", "ctr", "lr");

	if (cr & (1L << 28)) {
		return -r3;
	}
	return r3;
}
