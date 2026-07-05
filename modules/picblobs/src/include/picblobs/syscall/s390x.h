/*
 * pic_raw_syscall — s390x (svc 0).
 *
 * s390x syscall ABI: syscall number in r1, arguments in r2-r7,
 * return value in r2.
 */

static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long r1 __asm__("r1") = n;
	register long r2 __asm__("r2") = a0;
	register long r3 __asm__("r3") = a1;
	register long r4 __asm__("r4") = a2;
	register long r5 __asm__("r5") = a3;
	register long r6 __asm__("r6") = a4;
	register long r7 __asm__("r7") = a5;
	__asm__ volatile("svc 0"
		: "+d"(r2)
		: "d"(r1), "d"(r3), "d"(r4), "d"(r5), "d"(r6), "d"(r7)
		: "memory", "cc");
	return r2;
}
