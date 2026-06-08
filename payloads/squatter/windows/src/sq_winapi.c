#include "sq_winapi.h"

#define SQ_WINSOCK_VERSION_2_2 ((WORD)0x0202u)

static enum sq_status SqWinApiResolveKernel32(
    struct sq_winapi *api,
    LPCSTR symbol,
    FARPROC *procedure) {
    if (api == SQ_NULL || symbol == SQ_NULL || procedure == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    return SqLinkerResolve(api->linker, L"kernel32.dll", symbol, procedure);
}

static enum sq_status SqWinApiResolveWs2_32(
    struct sq_winapi *api,
    LPCSTR symbol,
    FARPROC *procedure) {
    if (api == SQ_NULL || symbol == SQ_NULL || procedure == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    return SqLinkerResolve(api->linker, L"ws2_32.dll", symbol, procedure);
}

enum sq_status SqWinApiInitialize(
    struct sq_winapi *api,
    struct sq_linker *linker) {
    if (api == SQ_NULL || linker == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(api, (sq_u32)sizeof(*api));
    api->linker = linker;
    return SqStatusSuccess;
}

enum sq_status SqWinApiCreateFileW(
    struct sq_winapi *api,
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file,
    HANDLE *file) {
    FARPROC procedure;

    if (api == SQ_NULL || file_name == SQ_NULL || file == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->CreateFileW == SQ_NULL) {
        if (SqWinApiResolveKernel32(api, "CreateFileW", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->CreateFileW = (HANDLE(WINAPI *)(
            LPCWSTR,
            DWORD,
            DWORD,
            LPSECURITY_ATTRIBUTES,
            DWORD,
            DWORD,
            HANDLE))procedure;
    }

    *file = api->CreateFileW(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file);
    if (*file == INVALID_HANDLE_VALUE) {
        return SqStatusInternalError;
    }

    return SqStatusSuccess;
}

enum sq_status SqWinApiReadFile(
    struct sq_winapi *api,
    HANDLE file,
    void *buffer,
    sq_u32 bytes_to_read,
    sq_u32 *bytes_read) {
    DWORD local_bytes_read;
    FARPROC procedure;

    if (api == SQ_NULL || file == INVALID_HANDLE_VALUE || file == SQ_NULL || buffer == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->ReadFile == SQ_NULL) {
        if (SqWinApiResolveKernel32(api, "ReadFile", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->ReadFile = (BOOL(WINAPI *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))procedure;
    }

    local_bytes_read = 0;
    if (!api->ReadFile(file, buffer, (DWORD)bytes_to_read, &local_bytes_read, SQ_NULL)) {
        return SqStatusInternalError;
    }

    if (bytes_read != SQ_NULL) {
        *bytes_read = (sq_u32)local_bytes_read;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiWriteFile(
    struct sq_winapi *api,
    HANDLE file,
    const void *buffer,
    sq_u32 bytes_to_write,
    sq_u32 *bytes_written) {
    DWORD local_bytes_written;
    FARPROC procedure;

    if (api == SQ_NULL || file == INVALID_HANDLE_VALUE || file == SQ_NULL || buffer == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->WriteFile == SQ_NULL) {
        if (SqWinApiResolveKernel32(api, "WriteFile", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->WriteFile = (BOOL(WINAPI *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))procedure;
    }

    local_bytes_written = 0;
    if (!api->WriteFile(file, buffer, (DWORD)bytes_to_write, &local_bytes_written, SQ_NULL)) {
        return SqStatusInternalError;
    }

    if (bytes_written != SQ_NULL) {
        *bytes_written = (sq_u32)local_bytes_written;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiCloseHandle(struct sq_winapi *api, HANDLE object) {
    FARPROC procedure;

    if (api == SQ_NULL || object == SQ_NULL || object == INVALID_HANDLE_VALUE) {
        return SqStatusInvalidParameter;
    }

    if (api->CloseHandle == SQ_NULL) {
        if (SqWinApiResolveKernel32(api, "CloseHandle", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->CloseHandle = (BOOL(WINAPI *)(HANDLE))procedure;
    }

    if (!api->CloseHandle(object)) {
        return SqStatusInternalError;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiSleep(struct sq_winapi *api, DWORD milliseconds) {
    FARPROC procedure;

    if (api == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->Sleep == SQ_NULL) {
        if (SqWinApiResolveKernel32(api, "Sleep", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->Sleep = (VOID(WINAPI *)(DWORD))procedure;
    }

    api->Sleep(milliseconds);
    return SqStatusSuccess;
}

enum sq_status SqWinApiWaitNamedPipeW(
    struct sq_winapi *api,
    LPCWSTR pipe_name,
    DWORD timeout) {
    FARPROC procedure;

    if (api == SQ_NULL || pipe_name == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->WaitNamedPipeW == SQ_NULL) {
        if (SqWinApiResolveKernel32(api, "WaitNamedPipeW", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->WaitNamedPipeW = (BOOL(WINAPI *)(LPCWSTR, DWORD))procedure;
    }

    if (!api->WaitNamedPipeW(pipe_name, timeout)) {
        return SqStatusInternalError;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiWSAStartup(struct sq_winapi *api) {
    WSADATA wsa_data;
    FARPROC procedure;

    if (api == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->WSAStartup == SQ_NULL) {
        if (SqWinApiResolveWs2_32(api, "WSAStartup", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->WSAStartup = (int(WSAAPI *)(WORD, LPWSADATA))procedure;
    }

    SqZeroMemory(&wsa_data, (sq_u32)sizeof(wsa_data));
    if (api->WSAStartup(SQ_WINSOCK_VERSION_2_2, &wsa_data) != 0) {
        return SqStatusInternalError;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiSocket(
    struct sq_winapi *api,
    int address_family,
    int socket_type,
    int protocol,
    SOCKET *socket_out) {
    FARPROC procedure;

    if (api == SQ_NULL || socket_out == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->socket == SQ_NULL) {
        if (SqWinApiResolveWs2_32(api, "socket", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->socket = (SOCKET(WSAAPI *)(int, int, int))procedure;
    }

    *socket_out = api->socket(address_family, socket_type, protocol);
    if (*socket_out == INVALID_SOCKET) {
        return SqStatusInternalError;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiConnect(
    struct sq_winapi *api,
    SOCKET socket_value,
    const struct sockaddr *name,
    int name_length) {
    FARPROC procedure;

    if (api == SQ_NULL || socket_value == INVALID_SOCKET || name == SQ_NULL || name_length <= 0) {
        return SqStatusInvalidParameter;
    }

    if (api->connect == SQ_NULL) {
        if (SqWinApiResolveWs2_32(api, "connect", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->connect = (int(WSAAPI *)(SOCKET, const struct sockaddr *, int))procedure;
    }

    if (api->connect(socket_value, name, name_length) != 0) {
        return SqStatusInternalError;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiSend(
    struct sq_winapi *api,
    SOCKET socket_value,
    const void *buffer,
    sq_u32 length,
    sq_u32 *bytes_sent) {
    int result;
    FARPROC procedure;

    if (api == SQ_NULL || socket_value == INVALID_SOCKET || buffer == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->send == SQ_NULL) {
        if (SqWinApiResolveWs2_32(api, "send", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->send = (int(WSAAPI *)(SOCKET, const char *, int, int))procedure;
    }

    result = api->send(socket_value, (const char *)buffer, (int)length, 0);
    if (result == SOCKET_ERROR) {
        return SqStatusInternalError;
    }

    if (bytes_sent != SQ_NULL) {
        *bytes_sent = (sq_u32)result;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiRecv(
    struct sq_winapi *api,
    SOCKET socket_value,
    void *buffer,
    sq_u32 length,
    sq_u32 *bytes_received) {
    int result;
    FARPROC procedure;

    if (api == SQ_NULL || socket_value == INVALID_SOCKET || buffer == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (api->recv == SQ_NULL) {
        if (SqWinApiResolveWs2_32(api, "recv", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->recv = (int(WSAAPI *)(SOCKET, char *, int, int))procedure;
    }

    result = api->recv(socket_value, (char *)buffer, (int)length, 0);
    if (result == SOCKET_ERROR) {
        return SqStatusInternalError;
    }

    if (bytes_received != SQ_NULL) {
        *bytes_received = (sq_u32)result;
    }
    return SqStatusSuccess;
}

enum sq_status SqWinApiCloseSocket(
    struct sq_winapi *api,
    SOCKET socket_value) {
    FARPROC procedure;

    if (api == SQ_NULL || socket_value == INVALID_SOCKET) {
        return SqStatusInvalidParameter;
    }

    if (api->closesocket == SQ_NULL) {
        if (SqWinApiResolveWs2_32(api, "closesocket", &procedure) != SqStatusSuccess) {
            return SqStatusNotFound;
        }
        api->closesocket = (int(WSAAPI *)(SOCKET))procedure;
    }

    if (api->closesocket(socket_value) != 0) {
        return SqStatusInternalError;
    }
    return SqStatusSuccess;
}
