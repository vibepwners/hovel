/*
 * test_mbed_runner.cpp — Test runner for platform_mbed.cpp with POSIX mocks.
 *
 * Compiles platform_mbed.cpp against mock Mbed OS headers backed by
 * real POSIX sockets. Loads a PIC blob from a file path and runs it
 * through the Mbed OS platform vtable — exercising the fd table,
 * sockaddr parsing, socket lifecycle, and RNG wrapper.
 *
 * Usage (under QEMU): test_mbed_runner <blob.bin>
 */

#include "platform_mbed.h"
#include <cstdio>
#include <cstdlib>

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <blob.bin>\n", argv[0]);
		return 127;
	}

	/* Read blob from file. */
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		perror("fopen");
		return 127;
	}
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (size <= 0) {
		fclose(f);
		return 127;
	}

	unsigned char *blob = (unsigned char *)malloc((size_t)size);
	if (!blob) {
		fclose(f);
		return 127;
	}
	if (fread(blob, 1, (size_t)size, f) != (size_t)size) {
		free(blob);
		fclose(f);
		return 127;
	}
	fclose(f);

	/* Initialize Mbed OS platform (mocked with POSIX sockets). */
	EthernetInterface eth;
	eth.connect();

	struct pic_platform plat;
	mbed_platform_init(&plat, &eth);

	/* Run the blob through the real platform_mbed.cpp vtable. */
	mbed_run_blob(blob, (unsigned int)size, &plat);

	/* mbed_run_blob should not return (blob calls exit_group). */
	free(blob);
	return 127;
}
