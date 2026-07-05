/*
 * pic_raw_syscall — i386 (int 0x80).
 *
 * Linux i386 ABI: ebx=a0, ecx=a1, edx=a2, esi=a3, edi=a4, ebp=a5.
 * FreeBSD i386 ABI: args on stack; on error, CF=1 and eax=errno.
 */

#if defined(PICBLOBS_OS_FREEBSD)
/*
 * FreeBSD i386 uses stack-passed args (System V) and signals errors
 * via CF. We push args 0..5, make the syscall, then capture CF to
 * negate the errno into the Linux-compatible convention callers expect.
 */
static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	long ret = 0;
	unsigned char cf = 0;
	__asm__ volatile("push %[a5]\n\t"
			 "push %[a4]\n\t"
			 "push %[a3]\n\t"
			 "push %[a2]\n\t"
			 "push %[a1]\n\t"
			 "push %[a0]\n\t"
			 "push $0\n\t"
			 "int $0x80\n\t"
			 "setc %[cf]\n\t"
			 "add $28, %%esp"
		: "=a"(ret), [cf] "=qm"(cf)
		: "a"(n), [a0] "r"(a0), [a1] "r"(a1), [a2] "r"(a2),
		[a3] "r"(a3), [a4] "m"(a4), [a5] "m"(a5)
		: "memory");
	return cf ? -ret : ret;
}
#else
static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	long ret = 0;
	__asm__ volatile("push %%ebp\n\t"
			 "push %%edi\n\t"
			 "mov %[a4], %%edi\n\t"
			 "mov %[a5], %%ebp\n\t"
			 "int $0x80\n\t"
			 "pop %%edi\n\t"
			 "pop %%ebp"
		: "=a"(ret)
		: "a"(n), "b"(a0), "c"(a1), "d"(a2),
		"S"(a3), [a4] "m"(a4), [a5] "m"(a5)
		: "memory");
	return ret;
}
#endif
