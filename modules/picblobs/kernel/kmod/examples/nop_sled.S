/*
 * nop_sled.S — Minimal ring 0 blob that does nothing and returns.
 *
 * The simplest possible kernel blob. Use this to verify the loader
 * works without risking a panic. If dmesg shows the module loaded
 * and the blob "returned", everything is working.
 *
 * No config needed. No function pointers. Just:
 *   entry → nop → ret
 */

.intel_syntax noprefix
.text
.globl _start

_start:
    nop
    nop
    nop
    nop
    ret
