/*
 * nacl_client — NaCl encrypted TCP client PIC blob.
 *
 * Performs an authenticated ephemeral X25519 (Curve25519) key exchange, then
 * encrypts application data under the resulting per-session key with
 * crypto_secretbox (XSalsa20-Poly1305).
 *
 * Forward secrecy: the session key is derived from ephemeral keypairs that
 * never leave memory, so recovering the long-term auth key later does not
 * decrypt past sessions. Authentication: the ephemeral public keys are sealed
 * under a 32-byte auth key supplied via deployment config, so a wire attacker
 * who lacks that key cannot substitute keys and therefore cannot
 * man-in-the-middle / hijack the session. The configured runtime image does
 * contain the key and must be provisioned over a protected path. See
 * nacl_server.c for the security rationale and residual trust assumptions.
 *
 * Protocol:
 *   1. Connect to <configured IPv4 address>:<configured port>.
 *   2. Handshake: send secretbox(auth_key, eph_pk); recv secretbox(auth_key,
 *      peer eph_pk); session_key = X25519(eph_sk, peer eph_pk).
 *   3. Send the message encrypted under session_key.
 *   4. Receive the encrypted ACK, decrypt and verify.
 *   5. Exit 0 on success, 1 on failure.
 *
 * Each framed message is: nonce (24B) + length (4B LE) + ciphertext.
 */

#ifndef PIC_PLATFORM_HOSTED
#include "picblobs/os/linux.h"
#endif
#include "picblobs/crypto/randombytes.h"
#include "picblobs/crypto/tweetnacl.h"
#include "picblobs/log.h"
#include "picblobs/mem.h"
#include "picblobs/net.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/close.h"
#include "picblobs/sys/connect.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/read.h"
#include "picblobs/sys/socket.h"
#include "picblobs/sys/write.h"

#define MAX_PLAINTEXT 4096
#define MAX_CIPHERTEXT (MAX_PLAINTEXT + crypto_secretbox_BOXZEROBYTES)

/*
 * Config layout: port (u16 LE), server IPv4 address (4 bytes in network
 * order), then a 32-byte handshake authentication key. The auth key is
 * injected at deploy time into the .config section rather than hard-coded in
 * source or unconfigured release artifacts. A configured image does contain
 * the key, so protect provisioning and the deployed image. The .skip below
 * only reserves space; a deployment must overwrite it with a real random key.
 * The blob rejects an all-zero key.
 */
struct __attribute__((packed)) nacl_client_config {
	pic_u16 port; /* little-endian */
	unsigned char server_ipv4[4];
	unsigned char auth_key[32];
};

__asm__(".section .config,\"aw\"\n"
	".globl nacl_client_config\n"
	"nacl_client_config:\n"
	".byte 0x0f, 0x27\n"   /* port = 9999 */
	".byte 127, 0, 0, 1\n" /* server IPv4 placeholder */
	".skip 32, 0\n" /* auth_key placeholder — inject at deploy time */
	".previous\n");

PIC_RODATA static const char tag_send[] =
	"[client] sending encrypted message\n";
PIC_RODATA static const char tag_ack[] = "[client] decrypted ACK: ";
PIC_RODATA static const char tag_ok[] = "[client] secure channel OK\n";
PIC_RODATA static const char tag_fail[] = "[client] FAILED\n";
PIC_RODATA static const char newline[] = "\n";
PIC_RODATA static const char message[] = "Hello from NaCl PIC blob!";
PIC_RODATA static const char expected_ack[] = "OK";

PIC_TEXT
static int read_exact(int fd, void *buf, pic_size_t n)
{
	pic_u8 *p = (pic_u8 *)buf;
	pic_size_t done = 0;
	while (done < n) {
		long r = pic_read(fd, p + done, n - done);
		if (r <= 0) {
			return -1;
		}
		done += (pic_size_t)r;
	}
	return 0;
}

PIC_TEXT
static int write_all(int fd, const void *buf, pic_size_t n)
{
	const pic_u8 *p = (const pic_u8 *)buf;
	pic_size_t done = 0;
	while (done < n) {
		long r = pic_write(fd, p + done, n - done);
		if (r <= 0) {
			return -1;
		}
		done += (pic_size_t)r;
	}
	return 0;
}

PIC_TEXT
static long recv_decrypt(
	int fd, const unsigned char *key, unsigned char *pt, pic_size_t pt_cap)
{
	unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
	unsigned char ct[crypto_secretbox_ZEROBYTES + MAX_PLAINTEXT];
	pic_u8 len_buf[4] = {0};
	pic_u32 ct_len = 0;
	pic_u64 box_len = 0;

	if (read_exact(fd, nonce, sizeof(nonce)) < 0) {
		return -1;
	}
	if (read_exact(fd, len_buf, 4) < 0) {
		return -1;
	}

	ct_len = (pic_u32)len_buf[0] | ((pic_u32)len_buf[1] << 8) |
		((pic_u32)len_buf[2] << 16) | ((pic_u32)len_buf[3] << 24);
	if (ct_len > MAX_CIPHERTEXT) {
		return -1;
	}

	pic_memset(ct, 0, crypto_secretbox_BOXZEROBYTES);
	if (read_exact(fd, ct + crypto_secretbox_BOXZEROBYTES, ct_len) < 0) {
		return -1;
	}

	box_len = (pic_u64)ct_len + crypto_secretbox_BOXZEROBYTES;
	if (box_len > pt_cap) {
		return -1;
	}

	if (crypto_secretbox_open(pt, ct, box_len, nonce, key) != 0) {
		return -1;
	}

	return (long)(box_len - crypto_secretbox_ZEROBYTES);
}

PIC_TEXT
static int encrypt_send(
	int fd, const unsigned char *key, const void *msg, pic_size_t msg_len)
{
	unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
	unsigned char pt[crypto_secretbox_ZEROBYTES + MAX_PLAINTEXT];
	unsigned char ct[crypto_secretbox_ZEROBYTES + MAX_PLAINTEXT];
	pic_u64 box_len = crypto_secretbox_ZEROBYTES + msg_len;
	pic_u32 ct_len = 0;
	pic_u8 len_buf[4] = {0};

	if (msg_len > MAX_PLAINTEXT) {
		return -1;
	}

	randombytes(nonce, sizeof(nonce));
	pic_memset(pt, 0, crypto_secretbox_ZEROBYTES);
	pic_memcpy(pt + crypto_secretbox_ZEROBYTES, msg, msg_len);

	crypto_secretbox(ct, pt, box_len, nonce, key);

	ct_len = (pic_u32)(box_len - crypto_secretbox_BOXZEROBYTES);
	len_buf[0] = (pic_u8)(ct_len);
	len_buf[1] = (pic_u8)(ct_len >> 8);
	len_buf[2] = (pic_u8)(ct_len >> 16);
	len_buf[3] = (pic_u8)(ct_len >> 24);

	if (write_all(fd, nonce, sizeof(nonce)) < 0) {
		return -1;
	}
	if (write_all(fd, len_buf, 4) < 0) {
		return -1;
	}
	if (write_all(fd, ct + crypto_secretbox_BOXZEROBYTES, ct_len) < 0) {
		return -1;
	}
	return 0;
}

PIC_TEXT
static pic_u16 config_port(void)
{
	extern char nacl_client_config[] __attribute__((visibility("hidden")));
	const pic_u8 *cfg = (const pic_u8 *)(void *)nacl_client_config;
	return (pic_u16)cfg[0] | ((pic_u16)cfg[1] << 8);
}

/* Pointer to the configured server IPv4 bytes in network order. */
PIC_TEXT
static const unsigned char *config_server_ipv4(void)
{
	extern char nacl_client_config[] __attribute__((visibility("hidden")));
	return (const unsigned char *)(void *)(nacl_client_config + 2);
}

/* Pointer to the 32-byte handshake auth key within the config section. */
PIC_TEXT
static const unsigned char *config_auth_key(void)
{
	extern char nacl_client_config[] __attribute__((visibility("hidden")));
	return (const unsigned char *)(void *)(nacl_client_config + 6);
}

PIC_TEXT
static int auth_key_is_zero(const unsigned char *key)
{
	unsigned char aggregate = 0;
	for (pic_size_t i = 0; i < crypto_secretbox_KEYBYTES; i++) {
		aggregate |= key[i];
	}
	return aggregate == 0;
}

PIC_TEXT
static void secure_zero(void *buf, pic_size_t len)
{
	volatile pic_u8 *p = (volatile pic_u8 *)buf;
	while (len > 0) {
		*p++ = 0;
		len--;
	}
}

/*
 * Authenticated ephemeral X25519 key exchange.
 *
 * Generates an ephemeral keypair, swaps public keys with the peer (each public
 * key sealed under the shared auth key so a party lacking that key cannot
 * substitute its own), then derives a fresh per-session key via X25519. The
 * ephemeral secret is wiped once the session key is derived. send_first orders
 * the exchange to avoid a deadlock (client sends first, server receives first).
 */
PIC_TEXT
static int handshake(int fd, const unsigned char *auth_key,
	unsigned char *session_key, int send_first)
{
	/* Zero-init the key material: crypto_box_keypair fills eph_pk/eph_sk
	 * via randombytes, but the static analyzer cannot model the
	 * /dev/urandom read, so it would otherwise flag a false "uninitialized"
	 * read inside the vendored X25519 (tweetnacl.h). The zeroing is
	 * harmless — every byte is overwritten before use. */
	unsigned char eph_pk[crypto_scalarmult_BYTES] = {0};
	unsigned char eph_sk[crypto_scalarmult_SCALARBYTES] = {0};
	unsigned char peer_pk[crypto_scalarmult_BYTES] = {0};
	unsigned char hs[crypto_secretbox_ZEROBYTES + 64] = {0};
	long n = 0;
	int result = -1;

	if (crypto_box_keypair(eph_pk, eph_sk) != 0) {
		goto cleanup;
	}

	if (send_first) {
		if (encrypt_send(fd, auth_key, eph_pk, sizeof(eph_pk)) < 0) {
			goto cleanup;
		}
		n = recv_decrypt(fd, auth_key, hs, sizeof(hs));
		if (n != (long)sizeof(eph_pk)) {
			goto cleanup;
		}
	} else {
		n = recv_decrypt(fd, auth_key, hs, sizeof(hs));
		if (n != (long)sizeof(eph_pk)) {
			goto cleanup;
		}
		if (encrypt_send(fd, auth_key, eph_pk, sizeof(eph_pk)) < 0) {
			goto cleanup;
		}
	}

	pic_memcpy(peer_pk, hs + crypto_secretbox_ZEROBYTES, sizeof(peer_pk));
	result = crypto_box_beforenm(session_key, peer_pk, eph_sk);

cleanup:
	secure_zero(eph_sk, sizeof(eph_sk));
	return result;
}

PIC_TEXT
static int connect_retry(struct pic_sockaddr_in *addr)
{
	int sock = (int)pic_socket(PIC_AF_INET, PIC_SOCK_STREAM, 0);
	if (sock < 0) {
		return -1;
	}

	int attempts = 50;
	while (attempts > 0) {
		long ret = pic_connect(sock, addr, sizeof(*addr));
		if (ret >= 0) {
			return sock;
		}
		for (volatile int i = 0; i < 1000000; i++) {
		}
		attempts--;
		if (attempts == 0) {
			break;
		}
		pic_close(sock);
		sock = (int)pic_socket(PIC_AF_INET, PIC_SOCK_STREAM, 0);
		if (sock < 0) {
			return -1;
		}
	}
	pic_close(sock);
	return -1;
}

PIC_TEXT
static void init_sockaddr(struct pic_sockaddr_in *addr)
{
	pic_memset(addr, 0, sizeof(*addr));
	addr->sin_family = PIC_AF_INET;
	addr->sin_port = pic_htons(config_port());
	pic_memcpy(&addr->sin_addr, config_server_ipv4(), 4);
}

PIC_ENTRY
void _start(
#ifdef PIC_PLATFORM_HOSTED
	const struct pic_platform *plat
#else
	void
#endif
)
{
	PIC_SELF_RELOCATE();
#ifdef PIC_PLATFORM_HOSTED
	PIC_PLATFORM_INIT(plat);
#endif

	unsigned char pt[crypto_secretbox_ZEROBYTES + MAX_PLAINTEXT] = {0};
	unsigned char session_key[crypto_secretbox_KEYBYTES] = {0};
	int sock = -1;
	long pt_len = 0;
	const unsigned char *auth_key = config_auth_key();

	if (auth_key_is_zero(auth_key)) {
		goto fail;
	}

	struct pic_sockaddr_in addr;
	init_sockaddr(&addr);
	sock = connect_retry(&addr);
	if (sock < 0) {
		goto fail;
	}

	/* Authenticated ephemeral X25519 key exchange (client sends first). */
	if (handshake(sock, auth_key, session_key, 1) < 0) {
		goto fail;
	}

	/* Send the message encrypted under the per-session key. */
	pic_write(1, tag_send, sizeof(tag_send) - 1);
	if (encrypt_send(sock, session_key, message, sizeof(message) - 1) < 0) {
		goto fail;
	}

	/* Receive encrypted ACK. */
	pt_len = recv_decrypt(sock, session_key, pt, sizeof(pt));
	if (pt_len != (long)(sizeof(expected_ack) - 1) ||
		pic_memcmp(pt + crypto_secretbox_ZEROBYTES, expected_ack,
			sizeof(expected_ack) - 1) != 0) {
		goto fail;
	}

	pic_write(1, tag_ack, sizeof(tag_ack) - 1);
	pic_write(1, pt + crypto_secretbox_ZEROBYTES, (pic_size_t)pt_len);
	pic_write(1, newline, 1);

	pic_write(1, tag_ok, sizeof(tag_ok) - 1);
	pic_close(sock);
	secure_zero(pt, sizeof(pt));
	secure_zero(session_key, sizeof(session_key));
	pic_exit_group(0);

fail:
	pic_write(2, tag_fail, sizeof(tag_fail) - 1);
	if (sock >= 0) {
		pic_close(sock);
	}
	secure_zero(pt, sizeof(pt));
	secure_zero(session_key, sizeof(session_key));
	pic_exit_group(1);
}
