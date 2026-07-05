/* _start — aarch64: extract argc/argv from kernel stack, call runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  ldr x0, [sp]\n"
	"  add x1, sp, #8\n"
	"  bl runner_main\n"
	"  mov x8, #94\n"
	"  svc #0\n");
