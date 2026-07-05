/* _start — s390x: extract argc/argv from kernel stack, call runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  lg   %r2, 0(%r15)\n" /* argc */
	"  la   %r3, 8(%r15)\n" /* argv */
	"  aghi %r15, -160\n"	/* allocate stack frame (s390x ABI minimum) */
	"  brasl %r14, runner_main\n"
	"  lghi %r1, 248\n" /* __NR_exit_group */
	"  svc  0\n");
