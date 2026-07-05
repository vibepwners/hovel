/*
 * pic_raw_syscall — RISC-V Linux (ecall).
 *
 * Syscall number in a7, arguments in a0-a5, return value in a0.
 * Linux returns -errno directly in a0 on failure.
 */

static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long a7 __asm__("a7") = n;
	register long a0_reg __asm__("a0") = a0;
	register long a1_reg __asm__("a1") = a1;
	register long a2_reg __asm__("a2") = a2;
	register long a3_reg __asm__("a3") = a3;
	register long a4_reg __asm__("a4") = a4;
	register long a5_reg __asm__("a5") = a5;

	__asm__ volatile("ecall"
		: "+r"(a0_reg)
		: "r"(a7), "r"(a1_reg), "r"(a2_reg), "r"(a3_reg), "r"(a4_reg),
		"r"(a5_reg)
		: "memory");

	return a0_reg;
}
