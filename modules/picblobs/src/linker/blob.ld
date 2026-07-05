/*
 * picblobs linker script — controls blob binary layout (ADR-003).
 *
 * Layout (all 16-byte aligned, base 0):
 *
 *   .text.pic_entry  — blob entry point (PIC_ENTRY)
 *   .text.pic_code   — blob code (PIC_TEXT)
 *   .text            — any remaining text
 *   .rodata          — read-only data (PIC_RODATA)
 *   .got / .got.plt  — GOT (needed by 32-bit arches for PIC)
 *   .data            — writable data (PIC_DATA)
 *   .bss             — zero-initialized data (PIC_BSS)
 *   .config          — config struct (PIC_CONFIG, appended at runtime)
 *
 * Symbols:
 *   __blob_start   — first byte of blob (== entry point)
 *   __blob_end     — end of blob data (before .config)
 *   __config_start — start of config section
 */

ENTRY(_start)

SECTIONS
{
    . = 0;

    __blob_start = .;

    .text.pic_trampoline : ALIGN(16) {
        KEEP(*(.text.pic_trampoline))
    }

    .text.pic_entry : ALIGN(16) {
        KEEP(*(.text.pic_entry))
    }

    .text.pic_code : ALIGN(16) {
        KEEP(*(.text.pic_code))
    }

    .text : ALIGN(16) {
        KEEP(*(.text .text.*))
    }

    .plt : ALIGN(16) {
        KEEP(*(.plt .plt.*))
    }

	.rodata : ALIGN(16) {
		KEEP(*(.rodata .rodata.* .rodata.pic))
	}

	.rela.dyn : ALIGN(16) {
		__rela_dyn_start = .;
		KEEP(*(.rela.dyn))
		KEEP(*(.rel.dyn))
		__rela_dyn_end = .;
	}

	.got : ALIGN(16) {
		__got_start = .;
		KEEP(*(.got))
		KEEP(*(.got.plt))
		KEEP(*(.got2))
		__got_end = .;
	}

    .data : ALIGN(16) {
        KEEP(*(.data .data.* .data.pic))
    }

    .data.rel.ro : ALIGN(16) {
        KEEP(*(.data.rel.ro .data.rel.ro.*))
    }

    .bss : ALIGN(16) {
        KEEP(*(.bss .bss.* .bss.pic))
        KEEP(*(COMMON))
    }

    __blob_end = .;

    .config : ALIGN(16) {
        __config_start = .;
        KEEP(*(.config .config.*))
    }

    /*
	 * Discarded sections.
	 *
	 * .rela.dyn / .rel.dyn are kept in the blob because some 32-bit PIC
	 * ABIs (notably PowerPC) materialize local addresses via relative
	 * dynamic relocations instead of pre-filled GOT entries.
	 */
	/DISCARD/ : {
		*(.comment)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.hash)
        *(.gnu.hash)
		*(.dynsym)
		*(.dynstr)
		*(.dynamic)
		*(.rela.*)
		*(.rel.*)
		*(.interp)
	}
}
