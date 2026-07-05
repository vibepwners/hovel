/*
 * who_am_i.S — Print current process info from ring 0
 *
 * Reads the current task_struct and prints the process name and PID
 * to dmesg. Demonstrates reading kernel data structures from PIC code.
 *
 * Config layout:
 *   offset 0x00:  u64  printk_addr
 *   offset 0x08:  u64  current_task    — pointer to current task_struct
 *   offset 0x10:  u32  comm_offset     — offsetof(task_struct, comm)
 *   offset 0x14:  u32  pid_offset      — offsetof(task_struct, pid)
 *
 * Result in dmesg:
 *   [12345.678] who_am_i: running as 'insmod' (PID 4567) in ring 0
 */

.intel_syntax noprefix
.text
.globl _start

_start:
    push rbx
    push r12
    push r13

    lea  rbx, [rip + config]

    /* Load function pointer and task pointer */
    mov  r12, [rbx]          /* r12 = printk */
    mov  r13, [rbx + 8]      /* r13 = current task_struct */

    test r12, r12
    jz   .done
    test r13, r13
    jz   .done

    /* Read PID: task_struct + pid_offset */
    mov  eax, [rbx + 0x14]   /* pid_offset */
    mov  esi, [r13 + rax]    /* PID value (2nd arg to printk) */

    /* Read comm: task_struct + comm_offset */
    mov  eax, [rbx + 0x10]   /* comm_offset */
    lea  rdx, [r13 + rax]    /* pointer to comm string (3rd arg) */

    /* printk(fmt, pid, comm) */
    lea  rdi, [rip + msg]
    mov  rax, r12
    xor  ecx, ecx            /* clear for varargs */
    call rax

.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

.section .rodata
msg:
    .asciz "who_am_i: running as '%s' (PID %d) in ring 0\n"

.section .data
.balign 8
config:
    .quad 0    /* printk */
    .quad 0    /* current task_struct */
    .long 0    /* comm_offset */
    .long 0    /* pid_offset */
