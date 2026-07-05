/* _start — SPARC v8: extract argc/argv from kernel stack, call runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  mov %g0, %fp\n"
	"  sub %sp, 24, %sp\n"
	"  ld [%sp + 88], %o0\n"
	"  add %sp, 92, %o1\n"
	"  call runner_main\n"
	"   nop\n"
	"  mov 188, %g1\n"
	"  ta 0x10\n");
