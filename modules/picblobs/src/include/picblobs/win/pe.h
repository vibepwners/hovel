/*
 * picblobs/win/pe.h — PE export directory parsing (REQ-005).
 *
 * Given a DLL base address, parses the PE headers to find the
 * export directory, then resolves a function by DJB2 hash of
 * its name.
 */

#ifndef PICBLOBS_WIN_PE_H
#define PICBLOBS_WIN_PE_H

#include "picblobs/arch.h"
#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/djb2.h"

/* DOS header offset to PE signature. */
#define PE_DOS_E_LFANEW_OFFSET 0x3C

/* Offsets from PE signature. */
#define PE_COFF_HEADER_SIZE 0x18 /* signature (4) + COFF header (20) */

/*
 * DataDirectory[0] offset from optional header start:
 *   PE32  (32-bit): 0x60
 *   PE32+ (64-bit): 0x70
 */
#if PIC_ARCH_IS_32BIT
#define PE_OPT_EXPORT_DIR_OFFSET 0x60
#else
#define PE_OPT_EXPORT_DIR_OFFSET 0x70
#endif

/* Export directory offsets. */
#define EXPORT_DIR_NUM_NAMES 0x18
#define EXPORT_DIR_ADDR_OF_FUNCTIONS 0x1C
#define EXPORT_DIR_ADDR_OF_NAMES 0x20
#define EXPORT_DIR_ADDR_OF_ORDINALS 0x24

/*
 * Resolve an exported function from a PE image by DJB2 hash.
 * Returns the function address, or PIC_NULL if not found.
 *
 * dll_base: base address of the PE image.
 * func_hash: precomputed DJB2 hash of the function name (case-sensitive).
 */
PIC_TEXT
static inline void *pic_find_export(void *dll_base, pic_u32 func_hash)
{
	pic_u8 *base = (pic_u8 *)dll_base;

	/* DOS header → e_lfanew → PE signature. */
	pic_u32 e_lfanew = *(pic_u32 *)(base + PE_DOS_E_LFANEW_OFFSET);
	pic_u8 *pe_sig = base + e_lfanew;

	/* Optional header starts after signature + COFF header. */
	pic_u8 *opt_hdr = pe_sig + PE_COFF_HEADER_SIZE;

	/* DataDirectory[0] = Export Directory {RVA, Size}. */
	pic_u32 export_rva = *(pic_u32 *)(opt_hdr + PE_OPT_EXPORT_DIR_OFFSET);
	if (export_rva == 0) {
		return PIC_NULL;
	}

	pic_u8 *export_dir = base + export_rva;

	/* Export directory fields. */
	pic_u32 num_names = *(pic_u32 *)(export_dir + EXPORT_DIR_NUM_NAMES);
	pic_u32 *addr_table = (pic_u32 *)(base +
		*(pic_u32 *)(export_dir + EXPORT_DIR_ADDR_OF_FUNCTIONS));
	pic_u32 *name_table = (pic_u32 *)(base +
		*(pic_u32 *)(export_dir + EXPORT_DIR_ADDR_OF_NAMES));
	pic_u16 *ordinal_table = (pic_u16 *)(base +
		*(pic_u32 *)(export_dir + EXPORT_DIR_ADDR_OF_ORDINALS));

	/* Linear search through export names. */
	for (pic_u32 i = 0; i < num_names; i++) {
		const char *name = (const char *)(base + name_table[i]);
		if (pic_djb2(name) == func_hash) {
			pic_u16 ordinal = ordinal_table[i];
			pic_u32 func_rva = addr_table[ordinal];
			return (void *)(base + func_rva);
		}
	}

	return PIC_NULL;
}

#endif /* PICBLOBS_WIN_PE_H */
