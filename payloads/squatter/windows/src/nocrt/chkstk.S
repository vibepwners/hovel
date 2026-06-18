#if defined(__x86_64__)
.text
.globl __chkstk_ms
.globl ___chkstk_ms
.def __chkstk_ms; .scl 2; .type 32; .endef
__chkstk_ms:
___chkstk_ms:
	pushq %rcx
	pushq %rax
	cmpq $0x1000, %rax
	leaq 24(%rsp), %rcx
	jb 2f
1:
	subq $0x1000, %rcx
	orq $0, (%rcx)
	subq $0x1000, %rax
	cmpq $0x1000, %rax
	ja 1b
2:
	subq %rax, %rcx
	orq $0, (%rcx)
	popq %rax
	popq %rcx
	ret
#else
.text
.globl ___chkstk_ms
.def ___chkstk_ms; .scl 2; .type 32; .endef
___chkstk_ms:
	pushl %ecx
	pushl %eax
	cmpl $0x1000, %eax
	leal 12(%esp), %ecx
	jb 2f
1:
	subl $0x1000, %ecx
	orl $0, (%ecx)
	subl $0x1000, %eax
	cmpl $0x1000, %eax
	ja 1b
2:
	subl %eax, %ecx
	orl $0, (%ecx)
	popl %eax
	popl %ecx
	ret
#endif
