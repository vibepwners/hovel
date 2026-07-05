/* pic_raw_syscall — aarch64 (svc #0). */

#if defined(PICBLOBS_OS_FREEBSD)
/*
 * FreeBSD aarch64 signals syscall error via the C (carry) flag of NZCV,
 * with x0=errno on error. Linux returns -errno directly. We read NZCV
 * after svc and negate the result on error to normalize to Linux form.
 */
static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x4 __asm__("x4") = a4;
	register long x5 __asm__("x5") = a5;
	unsigned long nzcv = 0;
	__asm__ volatile("svc #0\n\t"
			 "mrs %[nzcv], nzcv"
		: "=r"(x0), [nzcv] "=r"(nzcv)
		: "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory");
	return (nzcv & (1UL << 29)) ? -x0 : x0;
}
#else
static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x4 __asm__("x4") = a4;
	register long x5 __asm__("x5") = a5;
	__asm__ volatile("svc #0"
		: "=r"(x0)
		: "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory");
	return x0;
}
#endif
