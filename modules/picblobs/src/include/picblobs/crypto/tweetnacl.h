/*
 * picblobs/crypto/tweetnacl.h — TweetNaCl header-only, freestanding.
 *
 * Original: Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen,
 *           Tanja Lange, Peter Schwabe, Sjaak Smetsers (2014).
 *           Public domain. https://tweetnacl.cr.yp.to/
 *
 * Modifications for picblobs:
 *   - All functions made static (header-only, no linker symbols).
 *   - Removed #include dependencies (freestanding).
 *   - Requires randombytes() defined before inclusion
 *     (use picblobs/crypto/randombytes.h).
 *
 * Usage:
 *   #include "picblobs/os/linux.h"
 *   #include "picblobs/crypto/randombytes.h"
 *   #include "picblobs/crypto/tweetnacl.h"
 */

#ifndef PICBLOBS_CRYPTO_TWEETNACL_H
#define PICBLOBS_CRYPTO_TWEETNACL_H

#ifndef RANDOMBYTES_DEFINED
#error "Include picblobs/crypto/randombytes.h before tweetnacl.h"
#endif

/* Suppress unused-function warnings — callers use a subset of TweetNaCl. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

/*
 * Vendored, near-verbatim TweetNaCl (public domain). Not subject to the
 * project's clang-tidy style rules — kept close to upstream so it can be
 * re-synced. NOLINTBEGIN ... NOLINTEND (paired with the marker near EOF).
 */
// NOLINTBEGIN

/* ---- API constants ---- */

#define crypto_box_PUBLICKEYBYTES 32
#define crypto_box_SECRETKEYBYTES 32
#define crypto_box_BEFORENMBYTES 32
#define crypto_box_NONCEBYTES 24
#define crypto_box_ZEROBYTES 32
#define crypto_box_BOXZEROBYTES 16

#define crypto_secretbox_KEYBYTES 32
#define crypto_secretbox_NONCEBYTES 24
#define crypto_secretbox_ZEROBYTES 32
#define crypto_secretbox_BOXZEROBYTES 16

#define crypto_scalarmult_BYTES 32
#define crypto_scalarmult_SCALARBYTES 32

#define crypto_hash_BYTES 64

#define crypto_sign_BYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_SECRETKEYBYTES 64

#define crypto_verify_16_BYTES 16
#define crypto_verify_32_BYTES 32

/* ---- Internal types ---- */

typedef unsigned char _tn_u8;
typedef unsigned long _tn_u32;
typedef unsigned long long _tn_u64;
typedef long long _tn_i64;
typedef _tn_i64 _tn_gf[16];

#define _TN_FOR(i, n) for ((i) = 0; (i) < (n); ++(i))

/* ---- Internal constants ---- */

static const _tn_u8 _tn_0[16];
static const _tn_u8 _tn_9[32] = {9};
static const _tn_gf _tn_gf0;
static const _tn_gf _tn_gf1 = {1};
static const _tn_gf _tn_121665 = {0xDB41, 1};
static const _tn_gf _tn_D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141,
	0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee,
	0x5203};
static const _tn_gf _tn_D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283,
	0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc,
	0x2406};
static const _tn_gf _tn_X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525,
	0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3,
	0x2169};
static const _tn_gf _tn_Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
	0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
	0x6666};
static const _tn_gf _tn_I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f,
	0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480,
	0x2b83};

static const _tn_u8 _tn_sigma[16] = "expand 32-byte k";

/* ---- Core primitives ---- */

static _tn_u32 _tn_L32(_tn_u32 x, int c)
{
	return (x << c) | ((x & 0xffffffff) >> (32 - c));
}

static _tn_u32 _tn_ld32(const _tn_u8 *x)
{
	_tn_u32 u = x[3];
	u = (u << 8) | x[2];
	u = (u << 8) | x[1];
	return (u << 8) | x[0];
}

static _tn_u64 _tn_dl64(const _tn_u8 *x)
{
	_tn_u64 i, u = 0;
	_TN_FOR(i, 8) u = (u << 8) | x[i];
	return u;
}

static void _tn_st32(_tn_u8 *x, _tn_u32 u)
{
	int i;
	_TN_FOR(i, 4)
	{
		x[i] = (_tn_u8)u;
		u >>= 8;
	}
}

static void _tn_ts64(_tn_u8 *x, _tn_u64 u)
{
	int i;
	for (i = 7; i >= 0; --i) {
		x[i] = (_tn_u8)u;
		u >>= 8;
	}
}

static int _tn_vn(const _tn_u8 *x, const _tn_u8 *y, int n)
{
	_tn_u32 i, d = 0;
	_TN_FOR(i, n) d |= x[i] ^ y[i];
	return (1 & ((d - 1) >> 8)) - 1;
}

static int crypto_verify_16(const _tn_u8 *x, const _tn_u8 *y)
{
	return _tn_vn(x, y, 16);
}

static int crypto_verify_32(const _tn_u8 *x, const _tn_u8 *y)
{
	return _tn_vn(x, y, 32);
}

static void _tn_core(
	_tn_u8 *out, const _tn_u8 *in, const _tn_u8 *k, const _tn_u8 *c, int h)
{
	_tn_u32 w[16], x[16], y[16], t[4];
	int i, j, m;

	_TN_FOR(i, 4)
	{
		x[5 * i] = _tn_ld32(c + 4 * i);
		x[1 + i] = _tn_ld32(k + 4 * i);
		x[6 + i] = _tn_ld32(in + 4 * i);
		x[11 + i] = _tn_ld32(k + 16 + 4 * i);
	}

	_TN_FOR(i, 16) y[i] = x[i];

	_TN_FOR(i, 20)
	{
		_TN_FOR(j, 4)
		{
			_TN_FOR(m, 4) t[m] = x[(5 * j + 4 * m) % 16];
			t[1] ^= _tn_L32(t[0] + t[3], 7);
			t[2] ^= _tn_L32(t[1] + t[0], 9);
			t[3] ^= _tn_L32(t[2] + t[1], 13);
			t[0] ^= _tn_L32(t[3] + t[2], 18);
			_TN_FOR(m, 4) w[4 * j + (j + m) % 4] = t[m];
		}
		_TN_FOR(m, 16) x[m] = w[m];
	}

	if (h) {
		_TN_FOR(i, 16) x[i] += y[i];
		_TN_FOR(i, 4)
		{
			x[5 * i] -= _tn_ld32(c + 4 * i);
			x[6 + i] -= _tn_ld32(in + 4 * i);
		}
		_TN_FOR(i, 4)
		{
			_tn_st32(out + 4 * i, x[5 * i]);
			_tn_st32(out + 16 + 4 * i, x[6 + i]);
		}
	} else {
		_TN_FOR(i, 16) _tn_st32(out + 4 * i, x[i] + y[i]);
	}
}

static int crypto_core_salsa20(
	_tn_u8 *out, const _tn_u8 *in, const _tn_u8 *k, const _tn_u8 *c)
{
	_tn_core(out, in, k, c, 0);
	return 0;
}

static int crypto_core_hsalsa20(
	_tn_u8 *out, const _tn_u8 *in, const _tn_u8 *k, const _tn_u8 *c)
{
	_tn_core(out, in, k, c, 1);
	return 0;
}

static int crypto_stream_salsa20_xor(
	_tn_u8 *c, const _tn_u8 *m, _tn_u64 b, const _tn_u8 *n, const _tn_u8 *k)
{
	_tn_u8 z[16], x[64];
	_tn_u32 u, i;
	if (!b) {
		return 0;
	}
	_TN_FOR(i, 16) z[i] = 0;
	_TN_FOR(i, 8) z[i] = n[i];
	while (b >= 64) {
		crypto_core_salsa20(x, z, k, _tn_sigma);
		_TN_FOR(i, 64) c[i] = (m ? m[i] : 0) ^ x[i];
		u = 1;
		for (i = 8; i < 16; ++i) {
			u += (_tn_u32)z[i];
			z[i] = (_tn_u8)u;
			u >>= 8;
		}
		b -= 64;
		c += 64;
		if (m) {
			m += 64;
		}
	}
	if (b) {
		crypto_core_salsa20(x, z, k, _tn_sigma);
		_TN_FOR(i, b) c[i] = (m ? m[i] : 0) ^ x[i];
	}
	return 0;
}

static int crypto_stream_salsa20(
	_tn_u8 *c, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	return crypto_stream_salsa20_xor(c, 0, d, n, k);
}

static int crypto_stream(_tn_u8 *c, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	_tn_u8 s[32];
	crypto_core_hsalsa20(s, n, k, _tn_sigma);
	return crypto_stream_salsa20(c, d, n + 16, s);
}

static int crypto_stream_xor(
	_tn_u8 *c, const _tn_u8 *m, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	_tn_u8 s[32];
	crypto_core_hsalsa20(s, n, k, _tn_sigma);
	return crypto_stream_salsa20_xor(c, m, d, n + 16, s);
}

/* ---- Poly1305 ---- */

static void _tn_add1305(_tn_u32 *h, const _tn_u32 *c)
{
	_tn_u32 j, u = 0;
	_TN_FOR(j, 17)
	{
		u += h[j] + c[j];
		h[j] = u & 255;
		u >>= 8;
	}
}

static const _tn_u32 _tn_minusp[17] = {
	5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252};

static int crypto_onetimeauth(
	_tn_u8 *out, const _tn_u8 *m, _tn_u64 n, const _tn_u8 *k)
{
	_tn_u32 s, i, j, u, x[17], r[17], h[17], c[17], g[17];

	_TN_FOR(j, 17) r[j] = h[j] = 0;
	_TN_FOR(j, 16) r[j] = k[j];
	r[3] &= 15;
	r[4] &= 252;
	r[7] &= 15;
	r[8] &= 252;
	r[11] &= 15;
	r[12] &= 252;
	r[15] &= 15;

	while (n > 0) {
		_TN_FOR(j, 17) c[j] = 0;
		for (j = 0; (j < 16) && (j < n); ++j) {
			c[j] = m[j];
		}
		c[j] = 1;
		m += j;
		n -= j;
		_tn_add1305(h, c);
		_TN_FOR(i, 17)
		{
			x[i] = 0;
			_TN_FOR(j, 17)
			x[i] += h[j] *
				((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
		}
		_TN_FOR(i, 17) h[i] = x[i];
		u = 0;
		_TN_FOR(j, 16)
		{
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u & 3;
		u = 5 * (u >> 2);
		_TN_FOR(j, 16)
		{
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u;
	}

	_TN_FOR(j, 17) g[j] = h[j];
	_tn_add1305(h, _tn_minusp);
	s = -(_tn_u32)(h[16] >> 7);
	_TN_FOR(j, 17) h[j] ^= s & (g[j] ^ h[j]);

	_TN_FOR(j, 16) c[j] = k[j + 16];
	c[16] = 0;
	_tn_add1305(h, c);
	_TN_FOR(j, 16) out[j] = (_tn_u8)h[j];
	return 0;
}

static int crypto_onetimeauth_verify(
	const _tn_u8 *h, const _tn_u8 *m, _tn_u64 n, const _tn_u8 *k)
{
	_tn_u8 x[16];
	crypto_onetimeauth(x, m, n, k);
	return crypto_verify_16(h, x);
}

/* ---- Secretbox (XSalsa20-Poly1305) ---- */

static int crypto_secretbox(
	_tn_u8 *c, const _tn_u8 *m, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	int i;
	if (d < 32) {
		return -1;
	}
	crypto_stream_xor(c, m, d, n, k);
	crypto_onetimeauth(c + 16, c + 32, d - 32, c);
	_TN_FOR(i, 16) c[i] = 0;
	return 0;
}

static int crypto_secretbox_open(
	_tn_u8 *m, const _tn_u8 *c, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	int i;
	_tn_u8 x[32];
	if (d < 32) {
		return -1;
	}
	crypto_stream(x, 32, n, k);
	if (crypto_onetimeauth_verify(c + 16, c + 32, d - 32, x) != 0) {
		return -1;
	}
	crypto_stream_xor(m, c, d, n, k);
	_TN_FOR(i, 32) m[i] = 0;
	return 0;
}

/* ---- Curve25519 ---- */

static void _tn_set25519(_tn_gf r, const _tn_gf a)
{
	int i;
	_TN_FOR(i, 16) r[i] = a[i];
}

static void _tn_car25519(_tn_gf o)
{
	int i;
	_tn_i64 c;
	_TN_FOR(i, 16)
	{
		o[i] += (1LL << 16);
		c = o[i] >> 16;
		o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
		o[i] -= c << 16;
	}
}

static void _tn_sel25519(_tn_gf p, _tn_gf q, int b)
{
	_tn_i64 t, i, c = ~(b - 1);
	_TN_FOR(i, 16)
	{
		t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}

static void _tn_pack25519(_tn_u8 *o, const _tn_gf n)
{
	int i, j, b;
	_tn_gf m, t;
	_TN_FOR(i, 16) t[i] = n[i];
	_tn_car25519(t);
	_tn_car25519(t);
	_tn_car25519(t);
	_TN_FOR(j, 2)
	{
		m[0] = t[0] - 0xffed;
		for (i = 1; i < 15; i++) {
			m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
			m[i - 1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		b = (int)((m[15] >> 16) & 1);
		m[14] &= 0xffff;
		_tn_sel25519(t, m, 1 - b);
	}
	_TN_FOR(i, 16)
	{
		o[2 * i] = (_tn_u8)(t[i] & 0xff);
		o[2 * i + 1] = (_tn_u8)(t[i] >> 8);
	}
}

static int _tn_neq25519(const _tn_gf a, const _tn_gf b)
{
	_tn_u8 c[32], d[32];
	_tn_pack25519(c, a);
	_tn_pack25519(d, b);
	return crypto_verify_32(c, d);
}

static _tn_u8 _tn_par25519(const _tn_gf a)
{
	_tn_u8 d[32];
	_tn_pack25519(d, a);
	return d[0] & 1;
}

static void _tn_unpack25519(_tn_gf o, const _tn_u8 *n)
{
	int i;
	_TN_FOR(i, 16) o[i] = n[2 * i] + ((_tn_i64)n[2 * i + 1] << 8);
	o[15] &= 0x7fff;
}

static void _tn_A(_tn_gf o, const _tn_gf a, const _tn_gf b)
{
	int i;
	_TN_FOR(i, 16) o[i] = a[i] + b[i];
}

static void _tn_Z(_tn_gf o, const _tn_gf a, const _tn_gf b)
{
	int i;
	_TN_FOR(i, 16) o[i] = a[i] - b[i];
}

static void _tn_M(_tn_gf o, const _tn_gf a, const _tn_gf b)
{
	_tn_i64 i, j, t[31];
	_TN_FOR(i, 31) t[i] = 0;
	_TN_FOR(i, 16) _TN_FOR(j, 16) t[i + j] += a[i] * b[j];
	_TN_FOR(i, 15) t[i] += 38 * t[i + 16];
	_TN_FOR(i, 16) o[i] = t[i];
	_tn_car25519(o);
	_tn_car25519(o);
}

static void _tn_S(_tn_gf o, const _tn_gf a) { _tn_M(o, a, a); }

static void _tn_inv25519(_tn_gf o, const _tn_gf i)
{
	_tn_gf c;
	int a;
	_TN_FOR(a, 16) c[a] = i[a];
	for (a = 253; a >= 0; a--) {
		_tn_S(c, c);
		if (a != 2 && a != 4) {
			_tn_M(c, c, i);
		}
	}
	_TN_FOR(a, 16) o[a] = c[a];
}

static void _tn_pow2523(_tn_gf o, const _tn_gf i)
{
	_tn_gf c;
	int a;
	_TN_FOR(a, 16) c[a] = i[a];
	for (a = 250; a >= 0; a--) {
		_tn_S(c, c);
		if (a != 1) {
			_tn_M(c, c, i);
		}
	}
	_TN_FOR(a, 16) o[a] = c[a];
}

static int crypto_scalarmult(_tn_u8 *q, const _tn_u8 *n, const _tn_u8 *p)
{
	_tn_u8 z[32];
	_tn_i64 x[80], r, i;
	_tn_gf a, b, c, d, e, f;
	_TN_FOR(i, 31) z[i] = n[i];
	z[31] = (n[31] & 127) | 64;
	z[0] &= 248;
	_tn_unpack25519(x, p);
	_TN_FOR(i, 16)
	{
		b[i] = x[i];
		d[i] = a[i] = c[i] = 0;
	}
	a[0] = d[0] = 1;
	for (i = 254; i >= 0; --i) {
		r = (z[i >> 3] >> (i & 7)) & 1;
		_tn_sel25519(a, b, (int)r);
		_tn_sel25519(c, d, (int)r);
		_tn_A(e, a, c);
		_tn_Z(a, a, c);
		_tn_A(c, b, d);
		_tn_Z(b, b, d);
		_tn_S(d, e);
		_tn_S(f, a);
		_tn_M(a, c, a);
		_tn_M(c, b, e);
		_tn_A(e, a, c);
		_tn_Z(a, a, c);
		_tn_S(b, a);
		_tn_Z(c, d, f);
		_tn_M(a, c, _tn_121665);
		_tn_A(a, a, d);
		_tn_M(c, c, a);
		_tn_M(a, d, f);
		_tn_M(d, b, x);
		_tn_S(b, e);
		_tn_sel25519(a, b, (int)r);
		_tn_sel25519(c, d, (int)r);
	}
	_TN_FOR(i, 16)
	{
		x[i + 16] = a[i];
		x[i + 32] = c[i];
		x[i + 48] = b[i];
		x[i + 64] = d[i];
	}
	_tn_inv25519(x + 32, x + 32);
	_tn_M(x + 16, x + 16, x + 32);
	_tn_pack25519(q, x + 16);
	return 0;
}

static int crypto_scalarmult_base(_tn_u8 *q, const _tn_u8 *n)
{
	return crypto_scalarmult(q, n, _tn_9);
}

/* ---- Box (X25519 + XSalsa20-Poly1305) ---- */

static int crypto_box_keypair(_tn_u8 *y, _tn_u8 *x)
{
	randombytes(x, 32);
	return crypto_scalarmult_base(y, x);
}

static int crypto_box_beforenm(_tn_u8 *k, const _tn_u8 *y, const _tn_u8 *x)
{
	_tn_u8 s[32];
	crypto_scalarmult(s, x, y);
	return crypto_core_hsalsa20(k, _tn_0, s, _tn_sigma);
}

static int crypto_box_afternm(
	_tn_u8 *c, const _tn_u8 *m, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	return crypto_secretbox(c, m, d, n, k);
}

static int crypto_box_open_afternm(
	_tn_u8 *m, const _tn_u8 *c, _tn_u64 d, const _tn_u8 *n, const _tn_u8 *k)
{
	return crypto_secretbox_open(m, c, d, n, k);
}

static int crypto_box(_tn_u8 *c, const _tn_u8 *m, _tn_u64 d, const _tn_u8 *n,
	const _tn_u8 *y, const _tn_u8 *x)
{
	_tn_u8 k[32];
	crypto_box_beforenm(k, y, x);
	return crypto_box_afternm(c, m, d, n, k);
}

static int crypto_box_open(_tn_u8 *m, const _tn_u8 *c, _tn_u64 d,
	const _tn_u8 *n, const _tn_u8 *y, const _tn_u8 *x)
{
	_tn_u8 k[32];
	crypto_box_beforenm(k, y, x);
	return crypto_box_open_afternm(m, c, d, n, k);
}

/* ---- SHA-512 ---- */

static _tn_u64 _tn_R(_tn_u64 x, int c) { return (x >> c) | (x << (64 - c)); }
static _tn_u64 _tn_Ch(_tn_u64 x, _tn_u64 y, _tn_u64 z)
{
	return (x & y) ^ (~x & z);
}
static _tn_u64 _tn_Maj(_tn_u64 x, _tn_u64 y, _tn_u64 z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}
static _tn_u64 _tn_Sigma0(_tn_u64 x)
{
	return _tn_R(x, 28) ^ _tn_R(x, 34) ^ _tn_R(x, 39);
}
static _tn_u64 _tn_Sigma1(_tn_u64 x)
{
	return _tn_R(x, 14) ^ _tn_R(x, 18) ^ _tn_R(x, 41);
}
static _tn_u64 _tn_sigma0(_tn_u64 x)
{
	return _tn_R(x, 1) ^ _tn_R(x, 8) ^ (x >> 7);
}
static _tn_u64 _tn_sigma1(_tn_u64 x)
{
	return _tn_R(x, 19) ^ _tn_R(x, 61) ^ (x >> 6);
}

static const _tn_u64 _tn_K[80] = {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
	0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL,
	0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL,
	0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL,
	0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL,
	0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
	0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL,
	0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL,
	0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL,
	0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL,
	0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
	0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL,
	0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL,
	0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static int crypto_hashblocks(_tn_u8 *x, const _tn_u8 *m, _tn_u64 n)
{
	_tn_u64 z[8], b[8], a[8], w[16], t;
	int i, j;

	_TN_FOR(i, 8) z[i] = a[i] = _tn_dl64(x + 8 * i);

	while (n >= 128) {
		_TN_FOR(i, 16) w[i] = _tn_dl64(m + 8 * i);

		_TN_FOR(i, 80)
		{
			_TN_FOR(j, 8) b[j] = a[j];
			t = a[7] + _tn_Sigma1(a[4]) + _tn_Ch(a[4], a[5], a[6]) +
				_tn_K[i] + w[i % 16];
			b[7] = t + _tn_Sigma0(a[0]) + _tn_Maj(a[0], a[1], a[2]);
			b[3] += t;
			_TN_FOR(j, 8) a[(j + 1) % 8] = b[j];
			/* clang-format off */
			if (i % 16 == 15)
				_TN_FOR(j, 16)
					w[j] += w[(j + 9) % 16] + _tn_sigma0(w[(j + 1) % 16]) +
						_tn_sigma1(w[(j + 14) % 16]);
			/* clang-format on */
		}

		_TN_FOR(i, 8)
		{
			a[i] += z[i];
			z[i] = a[i];
		}

		m += 128;
		n -= 128;
	}

	_TN_FOR(i, 8) _tn_ts64(x + 8 * i, z[i]);

	return (int)n;
}

static const _tn_u8 _tn_iv[64] = {0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9,
	0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3,
	0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36,
	0xf1, 0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68,
	0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
	0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

static int crypto_hash(_tn_u8 *out, const _tn_u8 *m, _tn_u64 n)
{
	_tn_u8 h[64], x[256];
	_tn_u64 i, b = n;

	_TN_FOR(i, 64) h[i] = _tn_iv[i];

	crypto_hashblocks(h, m, n);
	m += n;
	n &= 127;
	m -= n;

	_TN_FOR(i, 256) x[i] = 0;
	_TN_FOR(i, n) x[i] = m[i];
	x[n] = 128;

	n = 256 - 128 * (n < 112);
	x[n - 9] = (_tn_u8)(b >> 61);
	_tn_ts64(x + n - 8, b << 3);
	crypto_hashblocks(h, x, n);

	_TN_FOR(i, 64) out[i] = h[i];

	return 0;
}

/* ---- Ed25519 ---- */

static void _tn_add(_tn_gf p[4], _tn_gf q[4])
{
	_tn_gf a, b, c, d, t, e, f, g, h;

	_tn_Z(a, p[1], p[0]);
	_tn_Z(t, q[1], q[0]);
	_tn_M(a, a, t);
	_tn_A(b, p[0], p[1]);
	_tn_A(t, q[0], q[1]);
	_tn_M(b, b, t);
	_tn_M(c, p[3], q[3]);
	_tn_M(c, c, _tn_D2);
	_tn_M(d, p[2], q[2]);
	_tn_A(d, d, d);
	_tn_Z(e, b, a);
	_tn_Z(f, d, c);
	_tn_A(g, d, c);
	_tn_A(h, b, a);

	_tn_M(p[0], e, f);
	_tn_M(p[1], h, g);
	_tn_M(p[2], g, f);
	_tn_M(p[3], e, h);
}

static void _tn_cswap(_tn_gf p[4], _tn_gf q[4], _tn_u8 b)
{
	int i;
	/* clang-format off */
	_TN_FOR(i, 4)
		_tn_sel25519(p[i], q[i], b);
	/* clang-format on */
}

static void _tn_pack(_tn_u8 *r, _tn_gf p[4])
{
	_tn_gf tx, ty, zi;
	_tn_inv25519(zi, p[2]);
	_tn_M(tx, p[0], zi);
	_tn_M(ty, p[1], zi);
	_tn_pack25519(r, ty);
	r[31] ^= _tn_par25519(tx) << 7;
}

static void _tn_scalarmult(_tn_gf p[4], _tn_gf q[4], const _tn_u8 *s)
{
	int i;
	_tn_set25519(p[0], _tn_gf0);
	_tn_set25519(p[1], _tn_gf1);
	_tn_set25519(p[2], _tn_gf1);
	_tn_set25519(p[3], _tn_gf0);
	for (i = 255; i >= 0; --i) {
		_tn_u8 b = (s[i / 8] >> (i & 7)) & 1;
		_tn_cswap(p, q, b);
		_tn_add(q, p);
		_tn_add(p, p);
		_tn_cswap(p, q, b);
	}
}

static void _tn_scalarbase(_tn_gf p[4], const _tn_u8 *s)
{
	_tn_gf q[4];
	_tn_set25519(q[0], _tn_X);
	_tn_set25519(q[1], _tn_Y);
	_tn_set25519(q[2], _tn_gf1);
	_tn_M(q[3], _tn_X, _tn_Y);
	_tn_scalarmult(p, q, s);
}

static int crypto_sign_keypair(_tn_u8 *pk, _tn_u8 *sk)
{
	_tn_u8 d[64];
	_tn_gf p[4];
	int i;

	randombytes(sk, 32);
	crypto_hash(d, sk, 32);
	d[0] &= 248;
	d[31] &= 127;
	d[31] |= 64;

	_tn_scalarbase(p, d);
	_tn_pack(pk, p);

	_TN_FOR(i, 32) sk[32 + i] = pk[i];
	return 0;
}

static const _tn_u64 _tn_L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12,
	0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void _tn_modL(_tn_u8 *r, _tn_i64 x[64])
{
	_tn_i64 carry, i, j;
	for (i = 63; i >= 32; --i) {
		carry = 0;
		for (j = i - 32; j < i - 12; ++j) {
			x[j] += carry -
				16 * x[i] * (_tn_i64)_tn_L[j - (i - 32)];
			carry = (x[j] + 128) >> 8;
			x[j] -= carry << 8;
		}
		x[j] += carry;
		x[i] = 0;
	}
	carry = 0;
	_TN_FOR(j, 32)
	{
		x[j] += carry - (x[31] >> 4) * (_tn_i64)_tn_L[j];
		carry = x[j] >> 8;
		x[j] &= 255;
	}
	_TN_FOR(j, 32) x[j] -= carry * (_tn_i64)_tn_L[j];
	_TN_FOR(i, 32)
	{
		x[i + 1] += x[i] >> 8;
		r[i] = (_tn_u8)(x[i] & 255);
	}
}

static void _tn_reduce(_tn_u8 *r)
{
	_tn_i64 x[64], i;
	_TN_FOR(i, 64) x[i] = (_tn_u64)r[i];
	_TN_FOR(i, 64) r[i] = 0;
	_tn_modL(r, x);
}

static int crypto_sign(_tn_u8 *sm, _tn_u64 *smlen, const _tn_u8 *m, _tn_u64 n,
	const _tn_u8 *sk)
{
	_tn_u8 d[64], h[64], r[64];
	_tn_i64 i, j, x[64];
	_tn_gf p[4];

	crypto_hash(d, sk, 32);
	d[0] &= 248;
	d[31] &= 127;
	d[31] |= 64;

	*smlen = n + 64;
	_TN_FOR(i, (_tn_i64)n) sm[64 + i] = m[i];
	_TN_FOR(i, 32) sm[32 + i] = d[32 + i];

	crypto_hash(r, sm + 32, n + 32);
	_tn_reduce(r);
	_tn_scalarbase(p, r);
	_tn_pack(sm, p);

	_TN_FOR(i, 32) sm[i + 32] = sk[i + 32];
	crypto_hash(h, sm, n + 64);
	_tn_reduce(h);

	_TN_FOR(i, 64) x[i] = 0;
	_TN_FOR(i, 32) x[i] = (_tn_u64)r[i];
	_TN_FOR(i, 32) _TN_FOR(j, 32) x[i + j] += h[i] * (_tn_u64)d[j];
	_tn_modL(sm + 32, x);

	return 0;
}

static int _tn_unpackneg(_tn_gf r[4], const _tn_u8 p[32])
{
	_tn_gf t, chk, num, den, den2, den4, den6;
	_tn_set25519(r[2], _tn_gf1);
	_tn_unpack25519(r[1], p);
	_tn_S(num, r[1]);
	_tn_M(den, num, _tn_D);
	_tn_Z(num, num, r[2]);
	_tn_A(den, r[2], den);

	_tn_S(den2, den);
	_tn_S(den4, den2);
	_tn_M(den6, den4, den2);
	_tn_M(t, den6, num);
	_tn_M(t, t, den);

	_tn_pow2523(t, t);
	_tn_M(t, t, num);
	_tn_M(t, t, den);
	_tn_M(t, t, den);
	_tn_M(r[0], t, den);

	_tn_S(chk, r[0]);
	_tn_M(chk, chk, den);
	if (_tn_neq25519(chk, num)) {
		_tn_M(r[0], r[0], _tn_I);
	}

	_tn_S(chk, r[0]);
	_tn_M(chk, chk, den);
	if (_tn_neq25519(chk, num)) {
		return -1;
	}

	if (_tn_par25519(r[0]) == (p[31] >> 7)) {
		_tn_Z(r[0], _tn_gf0, r[0]);
	}

	_tn_M(r[3], r[0], r[1]);
	return 0;
}

static int crypto_sign_open(
	_tn_u8 *m, _tn_u64 *mlen, const _tn_u8 *sm, _tn_u64 n, const _tn_u8 *pk)
{
	int i;
	_tn_u8 t[32], h[64];
	_tn_gf p[4], q[4];

	*mlen = (_tn_u64)-1;
	if (n < 64) {
		return -1;
	}

	if (_tn_unpackneg(q, pk)) {
		return -1;
	}

	_TN_FOR(i, (_tn_i64)n) m[i] = sm[i];
	_TN_FOR(i, 32) m[i + 32] = pk[i];
	crypto_hash(h, m, n);
	_tn_reduce(h);
	_tn_scalarmult(p, q, h);

	_tn_scalarbase(q, sm + 32);
	_tn_add(p, q);
	_tn_pack(t, p);

	n -= 64;
	if (crypto_verify_32(sm, t)) {
		_TN_FOR(i, (_tn_i64)n) m[i] = 0;
		return -1;
	}

	_TN_FOR(i, (_tn_i64)n) m[i] = sm[i + 64];
	*mlen = n;
	return 0;
}

// NOLINTEND

#pragma GCC diagnostic pop

#endif /* PICBLOBS_CRYPTO_TWEETNACL_H */
