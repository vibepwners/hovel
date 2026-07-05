/*
 * picblobs/net.h — minimal networking types and constants.
 *
 * Provides sockaddr_in, AF_INET, SOCK_STREAM, htons/ntohs for
 * freestanding PIC blobs that do TCP networking.
 */

#ifndef PICBLOBS_NET_H
#define PICBLOBS_NET_H

#include "picblobs/types.h"

/* Address families. */
#define PIC_AF_INET 2

/* Socket types — MIPS Linux swaps STREAM/DGRAM values. */
#if defined(__mips__)
#define PIC_SOCK_STREAM 2
#define PIC_SOCK_DGRAM 1
#else
#define PIC_SOCK_STREAM 1
#define PIC_SOCK_DGRAM 2
#endif

/* Socket options — MIPS Linux uses different SOL_SOCKET and option values. */
#if defined(__mips__)
#define PIC_SOL_SOCKET 0xffff
#define PIC_SO_REUSEADDR 0x0004
#else
#define PIC_SOL_SOCKET 1
#define PIC_SO_REUSEADDR 2
#endif

/* IPv4 address: network byte order. */
struct pic_sockaddr_in {
	pic_u16 sin_family;
	pic_u16 sin_port;
	pic_u32 sin_addr;
	pic_u8 sin_zero[8];
};

/* Host-to-network byte order for 16-bit values. */
static inline pic_u16 pic_htons(pic_u16 v)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return v;
#else
	return (pic_u16)((v >> 8) | (v << 8));
#endif
}

#define pic_ntohs pic_htons

/* Host-to-network byte order for 32-bit values. */
static inline pic_u32 pic_htonl(pic_u32 v)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return v;
#else
	return ((v >> 24) & 0x000000ff) | ((v >> 8) & 0x0000ff00) |
		((v << 8) & 0x00ff0000) | ((v << 24) & 0xff000000);
#endif
}

#define pic_ntohl pic_htonl

/* INADDR_ANY = 0.0.0.0 */
#define PIC_INADDR_ANY 0

#endif /* PICBLOBS_NET_H */
