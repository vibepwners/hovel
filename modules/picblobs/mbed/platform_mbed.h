/*
 * platform_mbed.h — Mbed OS 5.15 vtable implementation for PIC blobs.
 *
 * Provides a pic_platform vtable backed by Mbed OS C++ socket API,
 * hardware RNG, and serial console. Socket operations use an fd table
 * mapping integer descriptors to Mbed OS TCPServer/TCPSocket objects.
 */

#ifndef PLATFORM_MBED_H
#define PLATFORM_MBED_H

#include "picblobs/platform.h"

#ifdef __cplusplus
#include "mbed.h"
#include "EthernetInterface.h"

/* Maximum simultaneous file descriptors (fd 0-2 reserved for console). */
#define MBED_PLAT_MAX_FDS 16

/* Initialize the platform vtable with Mbed OS implementations.
 * Must be called after the network interface is connected. */
void mbed_platform_init(struct pic_platform *plat, NetworkInterface *net);

/* Run a PIC blob from a memory buffer.
 * Copies blob into RAM and branches to it in Thumb mode. */
void mbed_run_blob(const unsigned char *blob, unsigned int blob_size,
		   const struct pic_platform *plat);

#endif /* __cplusplus */

#endif /* PLATFORM_MBED_H */
