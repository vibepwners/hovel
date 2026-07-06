#if defined(__x86_64__)
.text
.globl _start
_start:
  mov $1, %eax
  mov $1, %edi
  lea msg(%rip), %rsi
  mov $16, %edx
  syscall
  mov $231, %eax
  xor %edi, %edi
  syscall
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__i386__)
.text
.globl _start
_start:
  call 1f
1:
  pop %ecx
  add $(msg - 1b), %ecx
  mov $4, %eax
  mov $1, %ebx
  mov $16, %edx
  int $0x80
  mov $252, %eax
  xor %ebx, %ebx
  int $0x80
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__aarch64__)
.text
.globl _start
_start:
  mov x8, #64
  mov x0, #1
  adr x1, msg
  mov x2, #16
  svc #0
  mov x8, #94
  mov x0, #0
  svc #0
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__arm__) && defined(__thumb__)
.syntax unified
.text
.globl _start
.thumb_func
_start:
  movs r7, #4
  movs r0, #1
  adr r1, msg
  movs r2, #16
  svc #0
  movs r7, #248
  movs r0, #0
  svc #0
.align 2
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__arm__)
.text
.globl _start
_start:
  mov r7, #4
  mov r0, #1
  adr r1, msg
  mov r2, #16
  svc #0
  mov r7, #248
  mov r0, #0
  svc #0
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__mips__)
.set noreorder
.text
.globl _start
_start:
  li $v0, 4004
  li $a0, 1
  bal 1f
  li $a2, 16
1:
  addiu $a1, $ra, (msg - 1b)
  syscall
  li $v0, 4246
  li $a0, 0
  syscall
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__s390x__)
.text
.globl _start
_start:
  lghi %r1, 4
  lghi %r2, 1
  larl %r3, msg
  lghi %r4, 16
  svc 0
  lghi %r1, 248
  lghi %r2, 0
  svc 0
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__sparc__)
.text
.globl _start
_start:
  mov 4, %g1
  mov 1, %o0
  sethi %hi(msg), %o1
  or %o1, %lo(msg), %o1
  mov 16, %o2
  ta 0x10
  nop
  mov 188, %g1
  clr %o0
  ta 0x10
  nop
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__powerpc64__)
.text
.globl _start
_start:
  li 0, 4
  li 3, 1
  bl 1f
1:
  mflr 4
  addi 4, 4, msg-1b
  li 5, 16
  sc
  li 0, 234
  li 3, 0
  sc
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__powerpc__)
.text
.globl _start
_start:
  li 0, 4
  li 3, 1
  lis 4, msg@ha
  addi 4, 4, msg@l
  li 5, 16
  sc
  li 0, 234
  li 3, 0
  sc
msg:
  .ascii "Hello, ul_exec!\n"

#elif defined(__riscv) && (__riscv_xlen == 64)
.text
.globl _start
_start:
  li a7, 64
  li a0, 1
  la a1, msg
  li a2, 16
  ecall
  li a7, 94
  li a0, 0
  ecall
msg:
  .ascii "Hello, ul_exec!\n"

#else
#error "unsupported architecture for hello_et_exec"
#endif
