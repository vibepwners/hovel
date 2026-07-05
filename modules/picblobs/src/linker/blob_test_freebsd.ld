/*
 * Test-mode linker script for FreeBSD blob verification.
 *
 * Identical to blob.ld but adds a .shim section at a fixed address
 * (0x10000000) where the FreeBSD syscall verification shim is placed.
 * Test-mode blobs jump to this address instead of executing real
 * FreeBSD syscall instructions.
 */

/* ENTRY marks _start as a GC root so --gc-sections keeps the code. */
ENTRY(_start)

SECTIONS
{
    . = 0;

    __blob_start = .;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    __blob_end = .;

    .config : {
        __config_start = .;
        *(.config .config.*)
    }

    /* FreeBSD syscall shim — placed at a fixed address for test-mode blobs. */
    . = 0x10000000;
    .shim : {
        __shim_start = .;
        *(.shim .shim.*)
        __shim_end = .;
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.got)
        *(.got.plt)
        *(.plt)
        *(.rela.*)
        *(.rel.*)
    }
}
