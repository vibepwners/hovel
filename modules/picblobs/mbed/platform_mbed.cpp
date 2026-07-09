/*
 * platform_mbed.cpp — Mbed OS 5.15 vtable implementation.
 *
 * Maps the PIC blob's POSIX-like syscall interface to Mbed OS C++ APIs.
 *
 * FD table:
 *   0 = stdin  (console, read-only)
 *   1 = stdout (console, write-only)
 *   2 = stderr (console, write-only)
 *   3+ = dynamically allocated sockets
 *
 * Socket lifecycle:
 *   socket() → reserves an fd; bind/connect creates a TCPSocket
 *   bind()   → opens socket on network, binds to port
 *   listen() → starts listening
 *   accept() → accepts connection into new fd
 *   connect()→ opens socket on network, connects to remote
 *   close()  → deletes socket, frees fd
 */

#include "platform_mbed.h"
#include "SocketAddress.h"
#include "TCPSocket.h"
#include "hal/trng_api.h"
#include "picblobs/net.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#ifdef __linux__
#include <sys/mman.h>
#endif

#if !DEVICE_TRNG
#error "The Mbed picblobs runner requires a target with DEVICE_TRNG"
#endif

/* ---- FD table ---- */

enum fd_type {
	FD_NONE = 0,
	FD_CONSOLE_IN,
	FD_CONSOLE_OUT,
	FD_TCP_LISTEN,
	FD_TCP_CONN,
};

struct fd_entry {
	enum fd_type type;
	TCPSocket *socket;
	bool close_deletes_socket;
	bool reuse_address;
};

static struct fd_entry fd_table[MBED_PLAT_MAX_FDS];
static NetworkInterface *g_net;
static trng_t g_trng;

static void fd_table_init(void)
{
	memset(fd_table, 0, sizeof(fd_table));
	fd_table[0].type = FD_CONSOLE_IN;
	fd_table[1].type = FD_CONSOLE_OUT;
	fd_table[2].type = FD_CONSOLE_OUT;
}

static int fd_alloc(void)
{
	for (int i = 3; i < MBED_PLAT_MAX_FDS; i++) {
		if (fd_table[i].type == FD_NONE)
			return i;
	}
	return -1;
}

/* ---- Platform callbacks ---- */

static long plat_write(int fd, const void *buf, pic_size_t count)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS || (!buf && count > 0))
		return -1;
	if (count == 0)
		return 0;

	struct fd_entry *e = &fd_table[fd];

	switch (e->type) {
	case FD_CONSOLE_OUT: {
		size_t written = std::fwrite(buf, 1, (size_t)count, stdout);
		std::fflush(stdout);
		return written == 0 && count > 0 ? -1 : (long)written;
	}

	case FD_TCP_CONN:
		if (!e->socket)
			return -1;
		return (long)e->socket->send(buf, (nsapi_size_t)count);

	default:
		return -1;
	}
}

static long plat_read(int fd, void *buf, pic_size_t count)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS || (!buf && count > 0))
		return -1;
	if (count == 0)
		return 0;

	struct fd_entry *e = &fd_table[fd];

	switch (e->type) {
	case FD_CONSOLE_IN: {
		size_t received = std::fread(buf, 1, (size_t)count, stdin);
		return (long)received;
	}

	case FD_TCP_CONN:
		if (!e->socket)
			return -1;
		return (long)e->socket->recv(buf, (nsapi_size_t)count);

	default:
		return -1;
	}
}

static long plat_close(int fd)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;
	if (fd < 3)
		return 0; /* don't close the console */

	struct fd_entry *e = &fd_table[fd];
	if (e->type == FD_NONE) {
		return -1;
	}

	TCPSocket *socket = e->socket;
	bool close_deletes_socket = e->close_deletes_socket;
	e->socket = NULL;
	e->close_deletes_socket = false;
	e->reuse_address = false;
	e->type = FD_NONE;

	if (socket) {
		socket->close();
		if (!close_deletes_socket) {
			delete socket;
		}
	}
	return 0;
}

static long plat_socket(int domain, int type, int protocol)
{
	if (domain != PIC_AF_INET || type != PIC_SOCK_STREAM || protocol != 0) {
		return -1;
	}

	/* Actual Mbed socket creation is deferred to bind/connect,
	 * because we need to know the role (server vs client). */
	int fd = fd_alloc();
	if (fd < 0)
		return -1;
	fd_table[fd].type = FD_TCP_CONN;
	fd_table[fd].socket = NULL;
	fd_table[fd].close_deletes_socket = false;
	fd_table[fd].reuse_address = false;
	return fd;
}

static long plat_bind(int fd, const void *addr, pic_size_t addrlen)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS || !addr || addrlen < 8)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_CONN || e->socket) {
		return -1;
	}

	/* Extract port from pic_sockaddr_in (family(2) + port(2) + addr(4)). */
	const unsigned char *sa = (const unsigned char *)addr;
	if (sa[0] != PIC_AF_INET || sa[1] != 0) {
		return -1;
	}
	uint16_t port = (uint16_t)((sa[2] << 8) | sa[3]); /* network byte order */

	/* Convert from generic socket to server. */
	TCPSocket *srv = new (std::nothrow) TCPSocket();
	if (!srv) {
		return -1;
	}
	if (srv->open(g_net) != NSAPI_ERROR_OK) {
		delete srv;
		return -1;
	}
	if (e->reuse_address) {
		int one = 1;
		(void)srv->setsockopt(
			NSAPI_SOCKET, NSAPI_REUSEADDR, &one, sizeof(one));
	}
	if (srv->bind(port) != NSAPI_ERROR_OK) {
		srv->close();
		delete srv;
		return -1;
	}

	e->type = FD_TCP_LISTEN;
	e->socket = srv;
	e->close_deletes_socket = false;
	return 0;
}

static long plat_listen(int fd, int backlog)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_LISTEN || !e->socket)
		return -1;

	return (e->socket->listen(backlog) == NSAPI_ERROR_OK) ? 0 : -1;
}

static long plat_accept(int fd, void *addr, void *addrlen)
{
	(void)addr;
	(void)addrlen;

	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_LISTEN || !e->socket)
		return -1;

	int new_fd = fd_alloc();
	if (new_fd < 0)
		return -1;

	nsapi_error_t err = NSAPI_ERROR_OK;
	TCPSocket *client = e->socket->accept(&err);
	if (!client || err != NSAPI_ERROR_OK) {
		return -1;
	}

	fd_table[new_fd].type = FD_TCP_CONN;
	fd_table[new_fd].socket = client;
	/* Mbed factory-allocated sockets delete themselves on close(). */
	fd_table[new_fd].close_deletes_socket = true;
	fd_table[new_fd].reuse_address = false;
	return new_fd;
}

static long plat_connect(int fd, const void *addr, pic_size_t addrlen)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS || !addr || addrlen < 8)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_CONN || e->socket) {
		return -1;
	}

	/* Extract IP and port from pic_sockaddr_in. */
	const unsigned char *sa = (const unsigned char *)addr;
	if (sa[0] != PIC_AF_INET || sa[1] != 0) {
		return -1;
	}
	uint16_t port = (uint16_t)((sa[2] << 8) | sa[3]);
	SocketAddress remote(sa + 4, NSAPI_IPv4, port);
	if (!remote) {
		return -1;
	}

	TCPSocket *sock = new (std::nothrow) TCPSocket();
	if (!sock) {
		return -1;
	}
	if (sock->open(g_net) != NSAPI_ERROR_OK) {
		delete sock;
		return -1;
	}

	nsapi_error_t err = sock->connect(remote);
	if (err != NSAPI_ERROR_OK) {
		sock->close();
		delete sock;
		return -1;
	}

	e->type = FD_TCP_CONN;
	e->socket = sock;
	e->close_deletes_socket = false;
	return 0;
}

static long plat_setsockopt(int fd, int level, int optname,
			    const void *optval, pic_size_t optlen)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS || !optval ||
	    optlen < sizeof(int)) {
		return -1;
	}
	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_CONN || e->socket || level != PIC_SOL_SOCKET ||
	    optname != PIC_SO_REUSEADDR) {
		return -1;
	}
	e->reuse_address = *(const int *)optval != 0;
	return 0;
}

static void plat_exit_group(int code);

static int fill_random(unsigned char *buf, unsigned long long len)
{
	while (len > 0) {
		size_t chunk = (len > 256) ? 256 : (size_t)len;
		size_t produced = 0;
		int err = trng_get_bytes(&g_trng, buf, chunk, &produced);
		if (err != 0 || produced == 0 || produced > chunk) {
			return -1;
		}
		buf += produced;
		len -= produced;
	}
	return 0;
}

static void plat_randombytes(unsigned char *buf, unsigned long long len)
{
	if ((!buf && len > 0) || fill_random(buf, len) < 0) {
		plat_exit_group(92);
	}
}

static void plat_exit_group(int code)
{
	if (code == 0)
		printf("[mbed-runner] blob exited OK\r\n");
	else
		printf("[mbed-runner] blob exited with code %d\r\n", code);
	std::fflush(stdout);

#ifdef __linux__
	std::exit(code);
#else
	/* Halt — no process model on bare-metal. */
	while (1)
		__WFI();
#endif
}

/* ---- Public API ---- */

void mbed_platform_init(struct pic_platform *plat, NetworkInterface *net)
{
	g_net = net;
	fd_table_init();
	trng_init(&g_trng);

	plat->write = plat_write;
	plat->read = plat_read;
	plat->close = plat_close;
	plat->socket = plat_socket;
	plat->bind = plat_bind;
	plat->listen = plat_listen;
	plat->accept = plat_accept;
	plat->connect = plat_connect;
	plat->setsockopt = plat_setsockopt;
	plat->randombytes = plat_randombytes;
	plat->exit_group = plat_exit_group;
}

void mbed_run_blob(const unsigned char *blob, unsigned int blob_size,
		   const struct pic_platform *plat)
{
	if (!blob || blob_size == 0 || !plat) {
		printf("[mbed-runner] invalid blob launch arguments\r\n");
		return;
	}

	/*
	 * Allocate executable memory for the blob.
	 *
	 * On bare-metal Cortex-M (real Mbed OS), all SRAM is executable
	 * and malloc() suffices. Under Linux (mock/test), heap memory
	 * has the NX bit set, so we need mmap with PROT_EXEC.
	 */
#ifdef __linux__
	/* Test/mock path: mmap RWX region (matches the Linux PIC runner). */
	unsigned char *ram = (unsigned char *)mmap(
		NULL, blob_size,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ram == MAP_FAILED) {
		printf("[mbed-runner] mmap failed for blob (%u bytes)\r\n",
		       blob_size);
		return;
	}
#else
	/* Bare-metal path: all SRAM is executable. */
	unsigned char *ram = (unsigned char *)malloc(blob_size);
	if (!ram) {
		printf("[mbed-runner] malloc failed for blob (%u bytes)\r\n",
		       blob_size);
		return;
	}
#endif
	memcpy(ram, blob, blob_size);

#ifndef __linux__
	/* Complete writes to SRAM before fetching copied Thumb instructions. */
	__DSB();
	__ISB();
#endif

	/* Branch to blob entry point.
	 * Set Thumb bit (bit 0) only if this runner was itself compiled
	 * in Thumb mode — the blob must match. */
	typedef void (*blob_entry_t)(const struct pic_platform *);
#if defined(__thumb__)
	blob_entry_t entry = (blob_entry_t)((uintptr_t)ram | 1);
#else
	blob_entry_t entry = (blob_entry_t)ram;
#endif

	printf("[mbed-runner] launching blob at %p (%u bytes)\r\n",
	       ram, blob_size);
	mbed::ScopedRamExecutionLock make_ram_executable;
	entry(plat);

	/* Blob called exit_group, so we should not reach here.
	 * If we do, clean up. */
#ifdef __linux__
	munmap(ram, blob_size);
#else
	free(ram);
#endif
}
