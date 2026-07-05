/* _start — ARM: extract argc/argv from kernel stack, call runner_main.
 *
 * Uses .arm/.thumb to match the compilation mode. When built with -mthumb,
 * the ELF entry gets bit 0 set via .thumb_func so the kernel/QEMU starts
 * in the correct mode. In ARM mode, .arm is the default. */
#ifdef __thumb__
__asm__(".section .text._start,\"ax\",%progbits\n"
	".thumb\n"
	".globl _start\n"
	".thumb_func\n"
	"_start:\n"
	"  ldr r0, [sp]\n"
	"  add r1, sp, #4\n"
	"  bl runner_main\n"
	"  mov r7, #248\n"
	"  svc #0\n");
#else
__asm__(".section .text._start,\"ax\",%progbits\n"
	".arm\n"
	".globl _start\n"
	"_start:\n"
	"  ldr r0, [sp]\n"
	"  add r1, sp, #4\n"
	"  bl runner_main\n"
	"  mov r7, #248\n"
	"  svc #0\n");
#endif
