/*
 * platform_mbed.cpp — Mbed OS 5.15 vtable implementation.
 *
 * Maps the PIC blob's POSIX-like syscall interface to Mbed OS C++ APIs.
 *
 * FD table:
 *   0 = stdin  (console, read-only)
 *   1 = stdout (console, write-only)
 *   2 = stderr (console, write-only)
 *   3 = /dev/urandom (virtual, read returns random bytes)
 *   4+ = dynamically allocated sockets
 *
 * Socket lifecycle:
 *   socket() → allocates fd, creates TCPSocket
 *   bind()   → opens socket on network, binds to port
 *   listen() → starts listening
 *   accept() → accepts connection into new fd
 *   connect()→ opens socket on network, connects to remote
 *   close()  → deletes socket, frees fd
 */

#include "platform_mbed.h"
#include <cstring>
#ifdef __linux__
#include <sys/mman.h>
#endif

/* ---- FD table ---- */

enum fd_type {
	FD_NONE = 0,
	FD_CONSOLE_IN,
	FD_CONSOLE_OUT,
	FD_URANDOM,
	FD_TCP_LISTEN,
	FD_TCP_CONN,
};

struct fd_entry {
	enum fd_type type;
	union {
		TCPServer *server;
		TCPSocket *socket;
	};
};

static struct fd_entry fd_table[MBED_PLAT_MAX_FDS];
static NetworkInterface *g_net;
static Serial *g_serial;

static void fd_table_init(void)
{
	memset(fd_table, 0, sizeof(fd_table));
	fd_table[0].type = FD_CONSOLE_IN;
	fd_table[1].type = FD_CONSOLE_OUT;
	fd_table[2].type = FD_CONSOLE_OUT;
}

static int fd_alloc(void)
{
	for (int i = 4; i < MBED_PLAT_MAX_FDS; i++) {
		if (fd_table[i].type == FD_NONE)
			return i;
	}
	return -1;
}

/* ---- Platform callbacks ---- */

static long plat_write(int fd, const void *buf, pic_size_t count)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	const char *p = (const char *)buf;

	switch (e->type) {
	case FD_CONSOLE_OUT:
		for (pic_size_t i = 0; i < count; i++)
			g_serial->putc(p[i]);
		return (long)count;

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
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];

	switch (e->type) {
	case FD_CONSOLE_IN:
		/* Blocking single-byte read from serial. */
		((char *)buf)[0] = (char)g_serial->getc();
		return 1;

	case FD_URANDOM: {
		/* Read from hardware RNG. */
		unsigned char *p = (unsigned char *)buf;
		for (pic_size_t i = 0; i < count; i++) {
			uint32_t rnd;
			/* Use Mbed OS HAL TRNG or mbedtls entropy. */
			mbedtls_hardware_poll(NULL, (unsigned char *)&rnd,
					      sizeof(rnd), NULL);
			p[i] = (unsigned char)(rnd & 0xFF);
		}
		return (long)count;
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
	if (fd < 4)
		return 0; /* don't close console or urandom */

	struct fd_entry *e = &fd_table[fd];

	switch (e->type) {
	case FD_TCP_LISTEN:
		if (e->server) {
			e->server->close();
			delete e->server;
			e->server = NULL;
		}
		break;
	case FD_TCP_CONN:
		if (e->socket) {
			e->socket->close();
			delete e->socket;
			e->socket = NULL;
		}
		break;
	default:
		break;
	}

	e->type = FD_NONE;
	return 0;
}

static long plat_socket(int domain, int type, int protocol)
{
	(void)domain;
	(void)protocol;
	(void)type;
	/* Actual Mbed socket creation is deferred to bind/connect,
	 * because we need to know the role (server vs client). */
	int fd = fd_alloc();
	if (fd < 0)
		return -1;
	fd_table[fd].type = FD_TCP_CONN;
	fd_table[fd].socket = NULL;
	return fd;
}

static long plat_bind(int fd, const void *addr, pic_size_t addrlen)
{
	(void)addrlen;
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];

	/* Extract port from pic_sockaddr_in (family(2) + port(2) + addr(4)). */
	const unsigned char *sa = (const unsigned char *)addr;
	uint16_t port = (uint16_t)((sa[2] << 8) | sa[3]); /* network byte order */

	/* Convert from generic socket to server. */
	TCPServer *srv = new TCPServer();
	if (srv->open(g_net) != NSAPI_ERROR_OK) {
		delete srv;
		return -1;
	}
	if (srv->bind(port) != NSAPI_ERROR_OK) {
		srv->close();
		delete srv;
		return -1;
	}

	e->type = FD_TCP_LISTEN;
	e->server = srv;
	return 0;
}

static long plat_listen(int fd, int backlog)
{
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_LISTEN || !e->server)
		return -1;

	return (e->server->listen(backlog) == NSAPI_ERROR_OK) ? 0 : -1;
}

static long plat_accept(int fd, void *addr, void *addrlen)
{
	(void)addr;
	(void)addrlen;

	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];
	if (e->type != FD_TCP_LISTEN || !e->server)
		return -1;

	int new_fd = fd_alloc();
	if (new_fd < 0)
		return -1;

	TCPSocket *client = new TCPSocket();
	nsapi_error_t err = e->server->accept(client);
	if (err != NSAPI_ERROR_OK) {
		delete client;
		return -1;
	}

	fd_table[new_fd].type = FD_TCP_CONN;
	fd_table[new_fd].socket = client;
	return new_fd;
}

static long plat_connect(int fd, const void *addr, pic_size_t addrlen)
{
	(void)addrlen;
	if (fd < 0 || fd >= MBED_PLAT_MAX_FDS)
		return -1;

	struct fd_entry *e = &fd_table[fd];

	/* Extract IP and port from pic_sockaddr_in. */
	const unsigned char *sa = (const unsigned char *)addr;
	uint16_t port = (uint16_t)((sa[2] << 8) | sa[3]);
	char ip[16];
	snprintf(ip, sizeof(ip), "%d.%d.%d.%d", sa[4], sa[5], sa[6], sa[7]);

	TCPSocket *sock = new TCPSocket();
	if (sock->open(g_net) != NSAPI_ERROR_OK) {
		delete sock;
		return -1;
	}

	nsapi_error_t err = sock->connect(ip, port);
	if (err != NSAPI_ERROR_OK) {
		sock->close();
		delete sock;
		return -1;
	}

	e->type = FD_TCP_CONN;
	e->socket = sock;
	return 0;
}

static long plat_setsockopt(int fd, int level, int optname,
			    const void *optval, pic_size_t optlen)
{
	(void)fd;
	(void)level;
	(void)optname;
	(void)optval;
	(void)optlen;
	/* SO_REUSEADDR is the only option the blobs set.
	 * Mbed OS TCP sockets don't expose this directly — no-op. */
	return 0;
}

static void plat_randombytes(unsigned char *buf, unsigned long long len)
{
	size_t olen = 0;
	while (len > 0) {
		size_t chunk = (len > 256) ? 256 : (size_t)len;
		mbedtls_hardware_poll(NULL, buf, chunk, &olen);
		buf += olen;
		len -= olen;
	}
}

static void plat_exit_group(int code)
{
	if (code == 0)
		printf("[mbed-runner] blob exited OK\r\n");
	else
		printf("[mbed-runner] blob exited with code %d\r\n", code);

	/* Halt — no process model on bare-metal. */
	while (1)
		__WFI();
}

/* ---- Public API ---- */

void mbed_platform_init(struct pic_platform *plat, NetworkInterface *net)
{
	g_net = net;
	static Serial serial(USBTX, USBRX, 115200);
	g_serial = &serial;

	fd_table_init();
	/* Reserve fd 3 for /dev/urandom. */
	fd_table[3].type = FD_URANDOM;

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
	entry(plat);

	/* Blob called exit_group, so we should not reach here.
	 * If we do, clean up. */
#ifdef __linux__
	munmap(ram, blob_size);
#else
	free(ram);
#endif
}
