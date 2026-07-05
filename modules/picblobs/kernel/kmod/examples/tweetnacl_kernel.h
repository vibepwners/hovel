/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * tweetnacl_kernel.h — Kernel-compatible TweetNaCl (single header)
 *
 * Self-contained implementation of NaCl crypto_secretbox (XSalsa20 + Poly1305
 * authenticated encryption) adapted from TweetNaCl by Daniel J. Bernstein,
 * Tanja Lange, and Peter Schwabe.
 *
 * Original source: https://tweetnacl.cr.yp.to/tweetnacl-20140427.c
 * Original license: Public domain
 *
 * Kernel adaptations:
 *   - No libc/stdlib — uses linux/types.h for u8/u32/u64
 *   - No malloc/free — all operations are in-place on caller buffers
 *   - memset/memcpy from linux/string.h
 *   - Compatible with kernels 2.6 through 6.x
 *
 * This file is licensed under GPL-2.0-only for kernel module compatibility.
 */

#ifndef _TWEETNACL_KERNEL_H
#define _TWEETNACL_KERNEL_H

#include <linux/types.h>
#include <linux/string.h>

/* --- Public constants --- */

#define crypto_secretbox_KEYBYTES     32
#define crypto_secretbox_NONCEBYTES   24
#define crypto_secretbox_ZEROBYTES    32
#define crypto_secretbox_BOXZEROBYTES 16

/* Internal constants */
#define crypto_onetimeauth_BYTES     16
#define crypto_onetimeauth_KEYBYTES  32
#define crypto_stream_KEYBYTES       32
#define crypto_stream_NONCEBYTES     24
#define crypto_verify_BYTES          16

/* Salsa20 sigma constant: "expand 32-byte k" */
static const u8 _tn_sigma[16] = {
	'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
};

/* --- crypto_verify_16 --- */

static inline int _tn_crypto_verify_16(const u8 *x, const u8 *y)
{
	u32 d = 0;
	int i;

	for (i = 0; i < 16; i++)
		d |= x[i] ^ y[i];
	return (1 & ((d - 1) >> 8)) - 1;
}

/* --- Utility: load/store little-endian --- */

static inline u32 _tn_ld32(const u8 *x)
{
	return (u32)x[0]
	     | ((u32)x[1] << 8)
	     | ((u32)x[2] << 16)
	     | ((u32)x[3] << 24);
}

static inline void _tn_st32(u8 *x, u32 u)
{
	x[0] = u & 0xff;
	x[1] = (u >> 8) & 0xff;
	x[2] = (u >> 16) & 0xff;
	x[3] = (u >> 24) & 0xff;
}

static inline u32 _tn_rotl32(u32 x, int n)
{
	return (x << n) | (x >> (32 - n));
}

/* --- Core Salsa20 --- */

static void _tn_core_salsa20(u8 *out, const u8 *in, const u8 *k,
			     const u8 *c)
{
	u32 w[16], x[16];
	int i;

	/* Build input block */
	w[0]  = _tn_ld32(c +  0);
	w[1]  = _tn_ld32(k +  0);
	w[2]  = _tn_ld32(k +  4);
	w[3]  = _tn_ld32(k +  8);
	w[4]  = _tn_ld32(k + 12);
	w[5]  = _tn_ld32(c +  4);
	w[6]  = _tn_ld32(in + 0);
	w[7]  = _tn_ld32(in + 4);
	w[8]  = _tn_ld32(in + 8);
	w[9]  = _tn_ld32(in + 12);
	w[10] = _tn_ld32(c +  8);
	w[11] = _tn_ld32(k + 16);
	w[12] = _tn_ld32(k + 20);
	w[13] = _tn_ld32(k + 24);
	w[14] = _tn_ld32(k + 28);
	w[15] = _tn_ld32(c + 12);

	for (i = 0; i < 16; i++)
		x[i] = w[i];

	/* 20 rounds (10 double-rounds) */
	for (i = 0; i < 20; i += 2) {
		/* Column quarter-rounds */
		x[ 4] ^= _tn_rotl32(x[ 0] + x[12],  7);
		x[ 8] ^= _tn_rotl32(x[ 4] + x[ 0],  9);
		x[12] ^= _tn_rotl32(x[ 8] + x[ 4], 13);
		x[ 0] ^= _tn_rotl32(x[12] + x[ 8], 18);

		x[ 9] ^= _tn_rotl32(x[ 5] + x[ 1],  7);
		x[13] ^= _tn_rotl32(x[ 9] + x[ 5],  9);
		x[ 1] ^= _tn_rotl32(x[13] + x[ 9], 13);
		x[ 5] ^= _tn_rotl32(x[ 1] + x[13], 18);

		x[14] ^= _tn_rotl32(x[10] + x[ 6],  7);
		x[ 2] ^= _tn_rotl32(x[14] + x[10],  9);
		x[ 6] ^= _tn_rotl32(x[ 2] + x[14], 13);
		x[10] ^= _tn_rotl32(x[ 6] + x[ 2], 18);

		x[ 3] ^= _tn_rotl32(x[15] + x[11],  7);
		x[ 7] ^= _tn_rotl32(x[ 3] + x[15],  9);
		x[11] ^= _tn_rotl32(x[ 7] + x[ 3], 13);
		x[15] ^= _tn_rotl32(x[11] + x[ 7], 18);

		/* Row quarter-rounds */
		x[ 1] ^= _tn_rotl32(x[ 0] + x[ 3],  7);
		x[ 2] ^= _tn_rotl32(x[ 1] + x[ 0],  9);
		x[ 3] ^= _tn_rotl32(x[ 2] + x[ 1], 13);
		x[ 0] ^= _tn_rotl32(x[ 3] + x[ 2], 18);

		x[ 6] ^= _tn_rotl32(x[ 5] + x[ 4],  7);
		x[ 7] ^= _tn_rotl32(x[ 6] + x[ 5],  9);
		x[ 4] ^= _tn_rotl32(x[ 7] + x[ 6], 13);
		x[ 5] ^= _tn_rotl32(x[ 4] + x[ 7], 18);

		x[11] ^= _tn_rotl32(x[10] + x[ 9],  7);
		x[ 8] ^= _tn_rotl32(x[11] + x[10],  9);
		x[ 9] ^= _tn_rotl32(x[ 8] + x[11], 13);
		x[10] ^= _tn_rotl32(x[ 9] + x[ 8], 18);

		x[12] ^= _tn_rotl32(x[15] + x[14],  7);
		x[13] ^= _tn_rotl32(x[12] + x[15],  9);
		x[14] ^= _tn_rotl32(x[13] + x[12], 13);
		x[15] ^= _tn_rotl32(x[14] + x[13], 18);
	}

	for (i = 0; i < 16; i++)
		_tn_st32(out + 4 * i, x[i] + w[i]);
}

/* --- HSalsa20 (used by XSalsa20 for key derivation) --- */

static void _tn_core_hsalsa20(u8 *out, const u8 *in, const u8 *k,
			      const u8 *c)
{
	u32 w[16], x[16];
	int i;

	w[0]  = _tn_ld32(c +  0);
	w[1]  = _tn_ld32(k +  0);
	w[2]  = _tn_ld32(k +  4);
	w[3]  = _tn_ld32(k +  8);
	w[4]  = _tn_ld32(k + 12);
	w[5]  = _tn_ld32(c +  4);
	w[6]  = _tn_ld32(in + 0);
	w[7]  = _tn_ld32(in + 4);
	w[8]  = _tn_ld32(in + 8);
	w[9]  = _tn_ld32(in + 12);
	w[10] = _tn_ld32(c +  8);
	w[11] = _tn_ld32(k + 16);
	w[12] = _tn_ld32(k + 20);
	w[13] = _tn_ld32(k + 24);
	w[14] = _tn_ld32(k + 28);
	w[15] = _tn_ld32(c + 12);

	for (i = 0; i < 16; i++)
		x[i] = w[i];

	for (i = 0; i < 20; i += 2) {
		x[ 4] ^= _tn_rotl32(x[ 0] + x[12],  7);
		x[ 8] ^= _tn_rotl32(x[ 4] + x[ 0],  9);
		x[12] ^= _tn_rotl32(x[ 8] + x[ 4], 13);
		x[ 0] ^= _tn_rotl32(x[12] + x[ 8], 18);

		x[ 9] ^= _tn_rotl32(x[ 5] + x[ 1],  7);
		x[13] ^= _tn_rotl32(x[ 9] + x[ 5],  9);
		x[ 1] ^= _tn_rotl32(x[13] + x[ 9], 13);
		x[ 5] ^= _tn_rotl32(x[ 1] + x[13], 18);

		x[14] ^= _tn_rotl32(x[10] + x[ 6],  7);
		x[ 2] ^= _tn_rotl32(x[14] + x[10],  9);
		x[ 6] ^= _tn_rotl32(x[ 2] + x[14], 13);
		x[10] ^= _tn_rotl32(x[ 6] + x[ 2], 18);

		x[ 3] ^= _tn_rotl32(x[15] + x[11],  7);
		x[ 7] ^= _tn_rotl32(x[ 3] + x[15],  9);
		x[11] ^= _tn_rotl32(x[ 7] + x[ 3], 13);
		x[15] ^= _tn_rotl32(x[11] + x[ 7], 18);

		x[ 1] ^= _tn_rotl32(x[ 0] + x[ 3],  7);
		x[ 2] ^= _tn_rotl32(x[ 1] + x[ 0],  9);
		x[ 3] ^= _tn_rotl32(x[ 2] + x[ 1], 13);
		x[ 0] ^= _tn_rotl32(x[ 3] + x[ 2], 18);

		x[ 6] ^= _tn_rotl32(x[ 5] + x[ 4],  7);
		x[ 7] ^= _tn_rotl32(x[ 6] + x[ 5],  9);
		x[ 4] ^= _tn_rotl32(x[ 7] + x[ 6], 13);
		x[ 5] ^= _tn_rotl32(x[ 4] + x[ 7], 18);

		x[11] ^= _tn_rotl32(x[10] + x[ 9],  7);
		x[ 8] ^= _tn_rotl32(x[11] + x[10],  9);
		x[ 9] ^= _tn_rotl32(x[ 8] + x[11], 13);
		x[10] ^= _tn_rotl32(x[ 9] + x[ 8], 18);

		x[12] ^= _tn_rotl32(x[15] + x[14],  7);
		x[13] ^= _tn_rotl32(x[12] + x[15],  9);
		x[14] ^= _tn_rotl32(x[13] + x[12], 13);
		x[15] ^= _tn_rotl32(x[14] + x[13], 18);
	}

	/* HSalsa20 outputs x[0],x[5],x[10],x[15],x[6],x[7],x[8],x[9] */
	_tn_st32(out +  0, x[ 0]);
	_tn_st32(out +  4, x[ 5]);
	_tn_st32(out +  8, x[10]);
	_tn_st32(out + 12, x[15]);
	_tn_st32(out + 16, x[ 6]);
	_tn_st32(out + 20, x[ 7]);
	_tn_st32(out + 24, x[ 8]);
	_tn_st32(out + 28, x[ 9]);
}

/*
 * _tn_crypto_stream_salsa20_xor — Salsa20 stream cipher encrypt/decrypt
 *
 * XORs the Salsa20 keystream with the message in-place.
 * If m is NULL, writes the raw keystream to c.
 */
static void _tn_crypto_stream_salsa20_xor(u8 *c, const u8 *m, u64 b,
					  const u8 *n, const u8 *k)
{
	u8 z[16], x[64];
	u32 u;
	u64 i;

	if (!b) return;

	memset(z, 0, 16);
	memcpy(z, n, 8);  /* Salsa20 nonce is first 8 bytes */

	while (b >= 64) {
		_tn_core_salsa20(x, z, k, _tn_sigma);
		for (i = 0; i < 64; i++)
			c[i] = (m ? m[i] : 0) ^ x[i];
		/* Increment 64-bit block counter in z[8..15] */
		u = 1;
		for (i = 8; i < 16; i++) {
			u += (u32)z[i];
			z[i] = u & 0xff;
			u >>= 8;
		}
		b -= 64;
		c += 64;
		if (m) m += 64;
	}

	if (b) {
		_tn_core_salsa20(x, z, k, _tn_sigma);
		for (i = 0; i < b; i++)
			c[i] = (m ? m[i] : 0) ^ x[i];
	}
}

/*
 * _tn_crypto_stream_xsalsa20_xor — XSalsa20 stream cipher
 *
 * Uses HSalsa20 to derive a subkey from the first 16 bytes of the
 * 24-byte nonce, then runs Salsa20 with the remaining 8 bytes.
 */
static void _tn_crypto_stream_xsalsa20_xor(u8 *c, const u8 *m, u64 b,
					   const u8 *n, const u8 *k)
{
	u8 s[32];

	_tn_core_hsalsa20(s, n, k, _tn_sigma);
	_tn_crypto_stream_salsa20_xor(c, m, b, n + 16, s);
}

/* Generate raw XSalsa20 keystream (no message XOR) */
static inline void _tn_crypto_stream_xsalsa20(u8 *c, u64 b,
					      const u8 *n, const u8 *k)
{
	_tn_crypto_stream_xsalsa20_xor(c, NULL, b, n, k);
}

/* --- Poly1305 one-time authenticator --- */

static void _tn_crypto_onetimeauth(u8 *out, const u8 *m, u64 n,
				   const u8 *k)
{
	u32 s, u, j;
	u32 x[17], r[17], h[17], c[17];
	u64 i;

	for (j = 0; j < 17; j++)
		r[j] = h[j] = 0;

	for (j = 0; j < 16; j++)
		r[j] = k[j];

	/* Clamp r */
	r[3]  &= 15;
	r[4]  &= 252;
	r[7]  &= 15;
	r[8]  &= 252;
	r[11] &= 15;
	r[12] &= 252;
	r[15] &= 15;

	while (n > 0) {
		for (j = 0; j < 17; j++)
			c[j] = 0;

		for (j = 0; j < 16 && j < n; j++)
			c[j] = m[j];
		c[j] = 1;

		m += j;
		n -= j;

		/* h += c */
		for (j = 0; j < 17; j++)
			h[j] += c[j];

		/* h *= r (mod 2^130 - 5) */
		for (i = 0; i < 17; i++) {
			x[i] = 0;
			for (j = 0; j <= i; j++)
				x[i] += h[j] * r[i - j];
			for (j = i + 1; j < 17; j++)
				x[i] += 320 * h[j] * r[i + 17 - j];
		}

		for (i = 0; i < 17; i++)
			h[i] = x[i];

		/* Carry propagation */
		u = 0;
		for (j = 0; j < 16; j++) {
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u & 3;
		u = 5 * (u >> 2);
		for (j = 0; j < 16; j++) {
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u;
	}

	/* Final reduction: compute h - (2^130 - 5), keep if non-negative */
	for (j = 0; j < 17; j++)
		c[j] = h[j];

	/* Add -(2^130 - 5) = add 5, then check bit 130 */
	u = 5;
	for (j = 0; j < 16; j++) {
		u += h[j];
		c[j] = u & 255;
		u >>= 8;
	}
	u += h[16];
	c[16] = u;

	/* If c[16] has bit 2 set (>= 2^130), use c; otherwise keep h */
	s = (c[16] >> 2) & 1; /* 1 if h >= 2^130 - 5, else 0 */
	/* Branchless select: result = s ? c : h, but we need to be more
	 * careful. The standard approach: subtract conditionally. */

	/* Actually, the canonical TweetNaCl approach for final freeze:
	 * try subtracting p = 2^130-5; if no borrow, keep the result. */
	for (j = 0; j < 17; j++) {
		/* s=1 means we should use c (reduced), s=0 means keep h */
		h[j] = (s & c[j]) | ((1 - s) & h[j]);
	}

	/* Add second half of key (s = k[16..31]) */
	u = 0;
	for (j = 0; j < 16; j++) {
		u += h[j] + (u32)k[j + 16];
		out[j] = u & 255;
		u >>= 8;
	}
}

static int _tn_crypto_onetimeauth_verify(const u8 *h, const u8 *m,
					 u64 n, const u8 *k)
{
	u8 x[16];

	_tn_crypto_onetimeauth(x, m, n, k);
	return _tn_crypto_verify_16(h, x);
}

/* --- crypto_secretbox (XSalsa20-Poly1305) --- */

/*
 * crypto_secretbox — Authenticated encryption
 *
 * The first crypto_secretbox_ZEROBYTES (32) bytes of m must be zero.
 * Output c has crypto_secretbox_BOXZEROBYTES (16) leading zero bytes.
 * Total length d includes the zero-padding.
 *
 * Returns 0 on success, -1 if d < 32.
 */
static int crypto_secretbox(u8 *c, const u8 *m, u64 d,
			    const u8 *n, const u8 *k)
{
	if (d < 32) return -1;

	_tn_crypto_stream_xsalsa20_xor(c, m, d, n, k);
	_tn_crypto_onetimeauth(c + 16, c + 32, d - 32, c);
	memset(c, 0, 16);
	return 0;
}

/*
 * crypto_secretbox_open — Authenticated decryption
 *
 * The first crypto_secretbox_BOXZEROBYTES (16) bytes of c must be zero.
 * Output m has crypto_secretbox_ZEROBYTES (32) leading zero bytes.
 *
 * Returns 0 on success, -1 on authentication failure or if d < 32.
 */
static int crypto_secretbox_open(u8 *m, const u8 *c, u64 d,
				 const u8 *n, const u8 *k)
{
	u8 x[32];

	if (d < 32) return -1;

	_tn_crypto_stream_xsalsa20(x, 32, n, k);
	if (_tn_crypto_onetimeauth_verify(c + 16, c + 32, d - 32, x) != 0)
		return -1;

	_tn_crypto_stream_xsalsa20_xor(m, c, d, n, k);
	memset(m, 0, 32);
	return 0;
}

#endif /* _TWEETNACL_KERNEL_H */
