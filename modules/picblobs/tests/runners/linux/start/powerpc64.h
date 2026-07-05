/* _start — PowerPC 64-bit LE: extract argc/argv from kernel stack, call
 * runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  ld 3, 0(1)\n"
	"  addi 4, 1, 8\n"
	"  stdu 1, -32(1)\n"
	"  bl runner_main\n"
	"  li 0, 234\n"
	"  sc\n");
