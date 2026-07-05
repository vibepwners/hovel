/*
 * pic_raw_syscall — MIPS o32 ABI.
 *
 * $a0-$a3 ($4-$7) carry the first 4 args, args 5-6 go on the stack
 * at sp+16 and sp+20 (the caller must reserve a 4-word argument save
 * area at sp+0..sp+15 even for reg args). Syscall number in $v0 ($2).
 */

static inline long pic_raw_syscall(
	long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long v0 __asm__("$2") = n;
	register long r4 __asm__("$4") = a0;
	register long r5 __asm__("$5") = a1;
	register long r6 __asm__("$6") = a2;
	register long r7 __asm__("$7") = a3;
	/*
	 * MIPS Linux syscall convention: on return, $a3 ($7) = 1 if error
	 * and $v0 ($2) = positive errno. On success, $a3 = 0 and $v0 = result.
	 * We negate $v0 on error to match the Linux convention (negative errno)
	 * expected by all callers.
	 */
	__asm__ volatile(".set noreorder\n\t"
			 "addiu $sp, $sp, -32\n\t"
			 "sw    %[arg5], 16($sp)\n\t"
			 "sw    %[arg6], 20($sp)\n\t"
			 "syscall\n\t"
			 "addiu $sp, $sp, 32\n\t"
			 "beqz  $7, 1f\n\t"
			 "nop\n\t"
			 "subu  %[v0], $0, %[v0]\n\t"
			 "1:\n\t"
			 ".set reorder\n\t"
		: [v0] "+r"(v0), "+r"(r7)
		: "r"(r4), "r"(r5), "r"(r6), [arg5] "r"(a4), [arg6] "r"(a5)
		: "memory", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14",
		"$15", "$24", "$25");
	return v0;
}
