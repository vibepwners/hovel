/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * b64_kernel.h — Minimal base64 decoder for kernel context.
 * No libc, no dynamic allocation. Decodes in-place.
 */
#ifndef _B64_KERNEL_H
#define _B64_KERNEL_H

#include <linux/types.h>

static const u8 b64_table[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,
    ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
    ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
    ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
    ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
    ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
    ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
    ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
    ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45,
    ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
    ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
    ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
    ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
};

/*
 * b64_decode — Decode base64 data in-place.
 *
 * Args:
 *   src:     Base64 encoded string (null-terminated)
 *   dst:     Output buffer (can be same as src — decoded is always smaller)
 *   dst_len: Max output buffer size
 *
 * Returns: number of decoded bytes, or -1 on error.
 */
static inline int b64_decode(const char *src, u8 *dst, int dst_len)
{
    int i = 0, j = 0;
    int len = 0;
    u32 accum;
    int bits;

    /* Calculate input length (skip trailing whitespace/padding) */
    while (src[len] && src[len] != '=' && src[len] != '\n' && src[len] != '\r')
        len++;

    accum = 0;
    bits = 0;

    for (i = 0; i < len; i++) {
        u8 c = (u8)src[i];
        if (c == '\n' || c == '\r' || c == ' ')
            continue;
        if (c < '+' || c > 'z')
            return -1;

        accum = (accum << 6) | b64_table[c];
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (j >= dst_len)
                return -1;
            dst[j++] = (u8)(accum >> bits);
            accum &= (1u << bits) - 1;
        }
    }

    return j;
}

#endif /* _B64_KERNEL_H */
