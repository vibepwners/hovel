/*
 * picblobs/win/resolve.h — top-level Windows API resolution (REQ-005).
 *
 * Combines TEB access, PEB walk, and PE export parsing into a
 * single resolve_function() call. This is the primary interface
 * for Windows blobs to obtain API function pointers.
 */

#ifndef PICBLOBS_WIN_RESOLVE_H
#define PICBLOBS_WIN_RESOLVE_H

#include "picblobs/section.h"
#include "picblobs/types.h"
#include "picblobs/win/pe.h"
#include "picblobs/win/peb.h"
#include "picblobs/win/teb.h"

/* clang-format off */
/*
 * Resolve a Windows API function by DJB2 hashes.
 *
 * dll_hash:  DJB2 hash of the lowercase DLL name (e.g., "kernel32.dll").
 * func_hash: DJB2 hash of the function name (case-sensitive, e.g., "WriteFile").
 *
 * Returns the function pointer, or PIC_NULL if not found.
 */
/* clang-format on */
PIC_TEXT
static inline void *pic_resolve(pic_u32 dll_hash, pic_u32 func_hash)
{
	void *teb = pic_get_teb();
	void *peb = pic_get_peb(teb);
	void *dll_base = pic_find_module(peb, dll_hash);
	if (!dll_base) {
		return PIC_NULL;
	}
	return pic_find_export(dll_base, func_hash);
}

#endif /* PICBLOBS_WIN_RESOLVE_H */
