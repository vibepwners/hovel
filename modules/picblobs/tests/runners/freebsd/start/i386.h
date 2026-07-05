/* _start — i386: extract argc/argv from kernel stack, call runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  xor %ebp, %ebp\n"
	"  mov (%esp), %eax\n"
	"  lea 4(%esp), %ecx\n"
	"  sub $8, %esp\n"
	"  push %ecx\n"
	"  push %eax\n"
	"  call runner_main\n"
	"  mov %eax, %ebx\n"
	"  mov $252, %eax\n"
	"  int $0x80\n");
