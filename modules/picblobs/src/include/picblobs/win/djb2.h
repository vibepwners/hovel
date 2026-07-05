/* clang-format off */
/*
 * picblobs/win/djb2.h — DJB2 hash for Windows API resolution (REQ-006).
 *
 * Two variants:
 *   pic_djb2()           — hash a null-terminated ASCII string (case-sensitive).
 *   pic_djb2_wide_lower() — hash a UTF-16LE UNICODE_STRING as lowercase ASCII.
 */
/* clang-format on */

#ifndef PICBLOBS_WIN_DJB2_H
#define PICBLOBS_WIN_DJB2_H

#include "picblobs/section.h"
#include "picblobs/types.h"

/* DJB2 hash of a null-terminated ASCII string (for export names). */
PIC_TEXT
static inline pic_u32 pic_djb2(const char *str)
{
	pic_u32 hash = 5381;
	while (*str) {
		hash = hash * 33 + (pic_u8)*str;
		str++;
	}
	return hash;
}

/*
 * DJB2 hash of a UTF-16LE string, converted to lowercase ASCII.
 * Used for DLL name comparison (DLL names are case-insensitive).
 * len is in bytes (UNICODE_STRING.Length), not characters.
 */
PIC_TEXT
static inline pic_u32 pic_djb2_wide_lower(const pic_u16 *str, pic_u16 byte_len)
{
	pic_u32 hash = 5381;
	pic_u16 char_count = byte_len / 2;
	for (pic_u16 i = 0; i < char_count; i++) {
		pic_u8 c = (pic_u8)str[i];
		if (c >= 'A' && c <= 'Z') {
			c += 32;
		}
		hash = hash * 33 + c;
	}
	return hash;
}

#endif /* PICBLOBS_WIN_DJB2_H */
