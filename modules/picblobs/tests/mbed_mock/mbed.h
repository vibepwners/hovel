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
#define DEVICE_TRNG 1
#define NSAPI_SOCKET 7000
#define NSAPI_REUSEADDR 0

enum nsapi_version_t {
	NSAPI_UNSPEC = 0,
	NSAPI_IPv4 = 4,
	NSAPI_IPv6 = 6,
};

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

namespace mbed
{
class ScopedRamExecutionLock
{
      public:
	ScopedRamExecutionLock() {}
	~ScopedRamExecutionLock() {}
};
} // namespace mbed

/* ---- SocketAddress ---- */

class SocketAddress
{
	struct sockaddr_in _addr;
	bool _valid;
	char _text[INET_ADDRSTRLEN];

      public:
	SocketAddress() : _valid(false)
	{
		memset(&_addr, 0, sizeof(_addr));
		memset(_text, 0, sizeof(_text));
	}
	SocketAddress(const void *bytes, nsapi_version_t version, uint16_t port)
	    : _valid(version == NSAPI_IPv4 && bytes != NULL)
	{
		memset(&_addr, 0, sizeof(_addr));
		memset(_text, 0, sizeof(_text));
		if (_valid) {
			_addr.sin_family = AF_INET;
			_addr.sin_port = htons(port);
			memcpy(&_addr.sin_addr, bytes, 4);
			inet_ntop(
				AF_INET, &_addr.sin_addr, _text, sizeof(_text));
		}
	}
	SocketAddress(const char *address, uint16_t port = 0) : _valid(false)
	{
		memset(&_addr, 0, sizeof(_addr));
		memset(_text, 0, sizeof(_text));
		_addr.sin_family = AF_INET;
		_addr.sin_port = htons(port);
		_valid = address &&
			inet_pton(AF_INET, address, &_addr.sin_addr) == 1;
		if (_valid) {
			inet_ntop(
				AF_INET, &_addr.sin_addr, _text, sizeof(_text));
		}
	}

	operator bool() const { return _valid; }
	const char *get_ip_address() const { return _valid ? _text : NULL; }
	const struct sockaddr_in &native() const { return _addr; }
};

/* ---- TCPSocket ---- */

class TCPSocket
{
	int _fd;
	bool _factory_allocated;

      public:
	TCPSocket() : _fd(-1), _factory_allocated(false) {}
	~TCPSocket()
	{
		if (_fd >= 0) {
			::close(_fd);
		}
	}

	nsapi_error_t open(NetworkInterface *)
	{
		_fd = ::socket(AF_INET, SOCK_STREAM, 0);
		return _fd >= 0 ? NSAPI_ERROR_OK : -1;
	}

	nsapi_error_t connect(const SocketAddress &address)
	{
		const struct sockaddr_in &addr = address.native();
		return ::connect(_fd, (const struct sockaddr *)&addr,
			       sizeof(addr)) == 0
			? NSAPI_ERROR_OK
			: -1;
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

	nsapi_error_t setsockopt(
		int level, int option, const void *value, unsigned length)
	{
		if (level != NSAPI_SOCKET || option != NSAPI_REUSEADDR) {
			return -1;
		}
		return ::setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, value,
			       length) == 0
			? NSAPI_ERROR_OK
			: -1;
	}

	TCPSocket *accept(nsapi_error_t *error = NULL)
	{
		int accepted_fd = ::accept(_fd, NULL, NULL);
		if (accepted_fd < 0) {
			if (error) {
				*error = -1;
			}
			return NULL;
		}

		TCPSocket *client = new TCPSocket();
		client->_fd = accepted_fd;
		client->_factory_allocated = true;
		if (error) {
			*error = NSAPI_ERROR_OK;
		}
		return client;
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
		if (_factory_allocated) {
			_factory_allocated = false;
			delete this;
		}
		return NSAPI_ERROR_OK;
	}
};

/* ---- ARM intrinsic mock ---- */

static inline void __WFI(void)
{
	fflush(stdout);
	fflush(stderr);
	_exit(0);
}

#endif /* MBED_H */
