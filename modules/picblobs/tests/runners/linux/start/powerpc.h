/* _start — PowerPC 32-bit: extract argc/argv from kernel stack, call
 * runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  lwz 3, 0(1)\n"    /* argc */
	"  addi 4, 1, 4\n"   /* argv */
	"  stwu 1, -16(1)\n" /* ABI minimum stack frame */
	"  bl runner_main\n"
	"  li 0, 234\n"
	"  sc\n");
