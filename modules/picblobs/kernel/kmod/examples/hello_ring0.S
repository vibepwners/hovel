/*
 * hello_ring0.S — "Hello from ring 0!" via printk
 *
 * This is a PIC blob designed for kernel context. It calls printk()
 * to write a message to dmesg. The printk function pointer is passed
 * via a config struct at a fixed offset.
 *
 * Config layout (set by the loader before execution):
 *   offset 0x00:  u64  printk_addr     — pointer to printk()
 *   offset 0x08:  u64  current_addr    — pointer to current task_struct
 *
 * Build:
 *   as -o hello_ring0.o hello_ring0.S
 *   ld --oformat binary -o hello_ring0.bin hello_ring0.o
 *
 * Or use the build script:
 *   python3 mbed/kmod_loader/build_examples.py
 *
 * Result in dmesg:
 *   [12345.678] hello_ring0: greetings from kernel space!
 */

.intel_syntax noprefix
.text
.globl _start

_start:
    /* Save callee-saved registers (kernel calling convention) */
    push rbx
    push r12

    /* Load config pointer — config is at end of blob.
     * We use RIP-relative addressing (PIC). */
    lea  rbx, [rip + config]

    /* Load printk function pointer from config */
    mov  rax, [rbx]          /* rax = printk address */
    test rax, rax
    jz   .done               /* skip if printk not set */

    /* Call printk(fmt) — single argument in rdi */
    lea  rdi, [rip + msg]
    call rax

.done:
    pop  r12
    pop  rbx
    ret

.section .rodata
msg:
    .asciz "hello_ring0: greetings from kernel space!\n"

/* Config struct — filled by loader before execution.
 * Placed at a known offset from _start so the loader can find it. */
.section .data
.balign 8
config:
    .quad 0    /* printk function pointer (filled by loader) */
    .quad 0    /* current task_struct pointer (filled by loader) */
