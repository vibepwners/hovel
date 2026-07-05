/*
 * Mock mbed.h — POSIX-backed stubs for testing platform_mbed.cpp.
 *
 * Provides the subset of the Mbed OS 5.15 API that platform_mbed.cpp
 * uses, implemented with POSIX sockets and standard libc. Runs as a
 * normal Linux binary under QEMU user-mode.
 */

#ifndef MBED_H
#define MBED_H

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- NSAPI types ---- */

typedef int nsapi_error_t;
typedef unsigned nsapi_size_t;
typedef int nsapi_size_or_error_t;
#define NSAPI_ERROR_OK 0

/* ---- PinName ---- */

typedef int PinName;
#define USBTX 0
#define USBRX 1

/* ---- Serial ---- */

class Serial
{
      public:
	Serial(PinName, PinName, int) {}
	void putc(int c)
	{
		char ch = (char)c;
		::write(1, &ch, 1);
	}
	int getc()
	{
		char c = 0;
		::read(0, &c, 1);
		return (int)c;
	}
};

/* ---- NetworkInterface ---- */

class NetworkInterface
{
};

/* ---- TCPSocket ---- */

class TCPServer; /* forward */

class TCPSocket
{
	int _fd;
	friend class TCPServer;

      public:
	TCPSocket() : _fd(-1) {}
	~TCPSocket() { close(); }

	nsapi_error_t open(NetworkInterface *)
	{
		_fd = ::socket(AF_INET, SOCK_STREAM, 0);
		return _fd >= 0 ? NSAPI_ERROR_OK : -1;
	}

	nsapi_error_t connect(const char *host, uint16_t port)
	{
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		inet_aton(host, &addr.sin_addr);
		return ::connect(_fd, (struct sockaddr *)&addr, sizeof(addr)) ==
				0
			? NSAPI_ERROR_OK
			: -1;
	}

	nsapi_size_or_error_t send(const void *data, nsapi_size_t size)
	{
		return (nsapi_size_or_error_t)::send(_fd, data, size, 0);
	}

	nsapi_size_or_error_t recv(void *data, nsapi_size_t size)
	{
		return (nsapi_size_or_error_t)::recv(_fd, data, size, 0);
	}

	nsapi_error_t close()
	{
		if (_fd >= 0) {
			::close(_fd);
			_fd = -1;
		}
		return NSAPI_ERROR_OK;
	}
};

/* ---- TCPServer ---- */

class TCPServer
{
	int _fd;

      public:
	TCPServer() : _fd(-1) {}
	~TCPServer() { close(); }

	nsapi_error_t open(NetworkInterface *)
	{
		_fd = ::socket(AF_INET, SOCK_STREAM, 0);
		return _fd >= 0 ? NSAPI_ERROR_OK : -1;
	}

	nsapi_error_t bind(uint16_t port)
	{
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = INADDR_ANY;
		int one = 1;
		::setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		return ::bind(_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0
			? NSAPI_ERROR_OK
			: -1;
	}

	nsapi_error_t listen(int backlog = 1)
	{
		return ::listen(_fd, backlog) == 0 ? NSAPI_ERROR_OK : -1;
	}

	nsapi_error_t accept(TCPSocket *client)
	{
		int cfd = ::accept(_fd, NULL, NULL);
		if (cfd < 0) {
			return -1;
		}
		client->_fd = cfd;
		return NSAPI_ERROR_OK;
	}

	nsapi_error_t close()
	{
		if (_fd >= 0) {
			::close(_fd);
			_fd = -1;
		}
		return NSAPI_ERROR_OK;
	}
};

/* ---- mbedtls hardware poll mock (uses /dev/urandom) ---- */

extern "C" {
static inline int mbedtls_hardware_poll(
	void *, unsigned char *output, size_t len, size_t *olen)
{
	int fd = ::open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	ssize_t n = ::read(fd, output, len);
	::close(fd);
	if (olen) {
		*olen = (n > 0) ? (size_t)n : 0;
	}
	return (n > 0) ? 0 : -1;
}
}

/* ---- ARM intrinsic mock ---- */

static inline void __WFI(void)
{
	fflush(stdout);
	fflush(stderr);
	_exit(0);
}

#endif /* MBED_H */
