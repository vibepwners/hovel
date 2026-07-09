/*
 * Mock EthernetInterface.h for testing platform_mbed.cpp.
 */

#ifndef ETHERNET_INTERFACE_H
#define ETHERNET_INTERFACE_H

#include "mbed.h"

class EthernetInterface : public NetworkInterface
{
      public:
	nsapi_error_t connect() { return NSAPI_ERROR_OK; }
	const char *get_ip_address() { return "127.0.0.1"; }
	nsapi_error_t get_ip_address(SocketAddress *address)
	{
		if (!address) {
			return -1;
		}
		*address = SocketAddress("127.0.0.1");
		return NSAPI_ERROR_OK;
	}
};

#endif /* ETHERNET_INTERFACE_H */
