/* _start — x86_64: extract argc/argv from kernel stack, call runner_main. */
__asm__(".section .text._start,\"ax\"\n"
	".globl _start\n"
	"_start:\n"
	"  xor %ebp, %ebp\n"
	"  mov (%rsp), %rdi\n"
	"  lea 8(%rsp), %rsi\n"
	"  call runner_main\n"
	"  mov %eax, %edi\n"
	"  mov $231, %eax\n"
	"  syscall\n");
