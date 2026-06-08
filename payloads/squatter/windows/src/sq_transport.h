#ifndef SQUATTER_WINDOWS_SQ_TRANSPORT_H_
#define SQUATTER_WINDOWS_SQ_TRANSPORT_H_

#include "sq_winapi.h"

#define SQ_TRANSPORT_KIND_AUTO 0u
#define SQ_TRANSPORT_KIND_REVERSE_TCP 1u
#define SQ_TRANSPORT_KIND_SMB_NAMED_PIPE 2u
#define SQ_TRANSPORT_PIPE_NAME_CAPACITY 128u

struct sq_transport_config {
    sq_u8 magic[8];
    sq_u32 kind;
    sq_u8 reverse_tcp_host[4];
    sq_u16 reverse_tcp_port;
    WCHAR named_pipe[SQ_TRANSPORT_PIPE_NAME_CAPACITY];
};

struct sq_transport {
    sq_u32 kind;
    HANDLE pipe;
    SOCKET socket_value;
};

enum sq_status SqTransportInitialize(struct sq_transport *transport);
enum sq_status SqTransportConnect(
    struct sq_transport *transport,
    struct sq_winapi *api,
    const struct sq_transport_config *config);
enum sq_status SqTransportSend(
    struct sq_transport *transport,
    struct sq_winapi *api,
    const void *buffer,
    sq_u32 length,
    sq_u32 *bytes_sent);
enum sq_status SqTransportReceive(
    struct sq_transport *transport,
    struct sq_winapi *api,
    void *buffer,
    sq_u32 length,
    sq_u32 *bytes_received);
enum sq_status SqTransportClose(
    struct sq_transport *transport,
    struct sq_winapi *api);

#endif
