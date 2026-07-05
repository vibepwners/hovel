/*
 * nacl_hello — NaCl crypto self-test PIC blob.
 *
 * Proves that TweetNaCl (crypto_secretbox / XSalsa20-Poly1305) works
 * correctly inside a position-independent blob.  No networking required.
 *
 * 1. Encrypts a known plaintext with crypto_secretbox.
 * 2. Decrypts the ciphertext with crypto_secretbox_open.
 * 3. Verifies the round-tripped plaintext matches.
 * 4. Prints "NaCl OK\n" and exits 0 on success, 1 on failure.
 */

/* OS header must precede crypto headers (which transitively pull sys/). */
#include "picblobs/os/linux.h"

#include "picblobs/crypto/randombytes.h"
#include "picblobs/crypto/tweetnacl.h"
#include "picblobs/mem.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/write.h"

/* Test key — 32 bytes. */
PIC_RODATA
static const unsigned char key[32] = {
	0x4e,
	0x61,
	0x43,
	0x6c,
	0x2d,
	0x50,
	0x49,
	0x43,
	0x2d,
	0x73,
	0x65,
	0x6c,
	0x66,
	0x2d,
	0x74,
	0x65,
	0x73,
	0x74,
	0x2d,
	0x6b,
	0x65,
	0x79,
	0x2d,
	0x30,
	0x30,
	0x31,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
};

PIC_RODATA static const char msg_ok[] = "NaCl OK\n";
PIC_RODATA static const char msg_fail[] = "NaCl FAIL\n";
PIC_RODATA static const char plaintext[] = "Hello from NaCl PIC blob!";

#define PT_LEN (sizeof(plaintext) - 1)

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();

	unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
	unsigned char pt_in[crypto_secretbox_ZEROBYTES + PT_LEN];
	unsigned char ct[crypto_secretbox_ZEROBYTES + PT_LEN];
	unsigned char pt_out[crypto_secretbox_ZEROBYTES + PT_LEN];

	/* Generate a random nonce. */
	randombytes(nonce, sizeof(nonce));

	/* Prepare zero-padded plaintext. */
	pic_memset(pt_in, 0, crypto_secretbox_ZEROBYTES);
	pic_memcpy(pt_in + crypto_secretbox_ZEROBYTES, plaintext, PT_LEN);

	/* Encrypt. */
	crypto_secretbox(ct, pt_in, sizeof(pt_in), nonce, key);

	/* Decrypt. */
	pic_memset(pt_out, 0, sizeof(pt_out));
	if (crypto_secretbox_open(pt_out, ct, sizeof(ct), nonce, key) != 0) {
		goto fail;
	}

	/* Verify round-trip. */
	if (pic_memcmp(pt_out + crypto_secretbox_ZEROBYTES, plaintext,
		    PT_LEN) != 0) {
		goto fail;
	}

	pic_write(1, msg_ok, sizeof(msg_ok) - 1);
	pic_exit_group(0);

fail:
	pic_write(2, msg_fail, sizeof(msg_fail) - 1);
	pic_exit_group(1);
}
