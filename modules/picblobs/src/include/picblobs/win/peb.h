/*
 * picblobs/win/peb.h — PEB walk for Windows PIC blobs (REQ-005).
 *
 * Walks PEB → PEB_LDR_DATA → InMemoryOrderModuleList to find
 * loaded DLLs by DJB2 hash of their BaseDllName.
 *
 * All offsets are for 64-bit Windows (x86_64 and aarch64).
 */

#ifndef PICBLOBS_WIN_PEB_H
#define PICBLOBS_WIN_PEB_H

#include "picblobs/arch.h"
#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/djb2.h"

/*
 * Structure offsets differ between 32-bit and 64-bit Windows
 * due to pointer size affecting struct layout.
 */
#if PIC_ARCH_IS_32BIT

/* 32-bit Windows offsets (relative to InMemoryOrderLinks pointer). */
#define PEB_LDR_OFFSET 0x0C
#define LDR_IN_MEMORY_ORDER_LIST_OFFSET 0x14
#define LDR_ENTRY_DLLBASE_OFFSET                                               \
	0x10 /* struct 0x18 - InMemoryOrderLinks 0x08 */
#define LDR_ENTRY_BASEDLLNAME_OFFSET                                           \
	0x24 /* struct 0x2C - InMemoryOrderLinks 0x08 */
#define UNICODE_STRING_LENGTH_OFFSET 0x00
#define UNICODE_STRING_BUFFER_OFFSET 0x04

#else

/* 64-bit Windows offsets. */
#define PEB_LDR_OFFSET 0x18
#define LDR_IN_MEMORY_ORDER_LIST_OFFSET 0x20
#define LDR_ENTRY_DLLBASE_OFFSET 0x20
#define LDR_ENTRY_BASEDLLNAME_OFFSET 0x48
#define UNICODE_STRING_LENGTH_OFFSET 0x00
#define UNICODE_STRING_BUFFER_OFFSET 0x08

#endif

/*
 * Find a loaded module by DJB2 hash of its lowercase BaseDllName.
 * Returns the DllBase pointer, or PIC_NULL if not found.
 *
 * peb: PEB pointer (from pic_get_peb).
 * dll_hash: precomputed DJB2 hash of the lowercase DLL name.
 */
PIC_TEXT
static inline void *pic_find_module(void *peb, pic_u32 dll_hash)
{
	/* PEB → Ldr (PEB_LDR_DATA*) */
	void *ldr = *(void **)((pic_u8 *)peb + PEB_LDR_OFFSET);
	if (!ldr) {
		return PIC_NULL;
	}

	/*
	 * Ldr → InMemoryOrderModuleList (LIST_ENTRY).
	 * This is the list head; first real entry is at Flink.
	 */
	pic_u8 *list_head = (pic_u8 *)ldr + LDR_IN_MEMORY_ORDER_LIST_OFFSET;
	pic_u8 *entry = *(pic_u8 **)list_head; /* Flink */

	while (entry != list_head) {
		/* BaseDllName UNICODE_STRING at entry + 0x48. */
		pic_u8 *ustr = entry + LDR_ENTRY_BASEDLLNAME_OFFSET;
		pic_u16 name_len =
			*(pic_u16 *)(ustr + UNICODE_STRING_LENGTH_OFFSET);
		pic_u16 *name_buf =
			*(pic_u16 **)(ustr + UNICODE_STRING_BUFFER_OFFSET);

		if (name_buf && name_len > 0) {
			pic_u32 h = pic_djb2_wide_lower(name_buf, name_len);
			if (h == dll_hash) {
				/* DllBase at entry + 0x20. */
				return *(void **)(entry +
					LDR_ENTRY_DLLBASE_OFFSET);
			}
		}

		/* Advance to next entry (Flink). */
		entry = *(pic_u8 **)entry;
	}

	return PIC_NULL;
}

#endif /* PICBLOBS_WIN_PEB_H */
