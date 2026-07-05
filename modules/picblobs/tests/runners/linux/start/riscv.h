/* _start — RISC-V 64-bit: extract argc/argv from kernel stack, call
 * runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  ld a0, 0(sp)\n"
	"  addi a1, sp, 8\n"
	"  call runner_main\n"
	"  li a7, 93\n"
	"  ecall\n");
