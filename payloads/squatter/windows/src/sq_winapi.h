#ifndef SQUATTER_WINDOWS_SQ_WINAPI_H_
#define SQUATTER_WINDOWS_SQ_WINAPI_H_

#include <winsock2.h>

#include "sq_linker.h"

struct sq_winapi {
    struct sq_linker *linker;
    HMODULE ws2_32;

    HANDLE(WINAPI *CreateFileW)(
        LPCWSTR file_name,
        DWORD desired_access,
        DWORD share_mode,
        LPSECURITY_ATTRIBUTES security_attributes,
        DWORD creation_disposition,
        DWORD flags_and_attributes,
        HANDLE template_file);
    BOOL(WINAPI *ReadFile)(
        HANDLE file,
        LPVOID buffer,
        DWORD bytes_to_read,
        LPDWORD bytes_read,
        LPOVERLAPPED overlapped);
    BOOL(WINAPI *WriteFile)(
        HANDLE file,
        LPCVOID buffer,
        DWORD bytes_to_write,
        LPDWORD bytes_written,
        LPOVERLAPPED overlapped);
    BOOL(WINAPI *CloseHandle)(HANDLE object);
    VOID(WINAPI *Sleep)(DWORD milliseconds);
    BOOL(WINAPI *WaitNamedPipeW)(LPCWSTR pipe_name, DWORD timeout);

    int(WSAAPI *WSAStartup)(WORD version_requested, LPWSADATA wsa_data);
    SOCKET(WSAAPI *socket)(int address_family, int socket_type, int protocol);
    int(WSAAPI *connect)(SOCKET socket, const struct sockaddr *name, int name_length);
    int(WSAAPI *send)(SOCKET socket, const char *buffer, int length, int flags);
    int(WSAAPI *recv)(SOCKET socket, char *buffer, int length, int flags);
    int(WSAAPI *closesocket)(SOCKET socket);
};

enum sq_status SqWinApiInitialize(
    struct sq_winapi *api,
    struct sq_linker *linker);

enum sq_status SqWinApiCreateFileW(
    struct sq_winapi *api,
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file,
    HANDLE *file);
enum sq_status SqWinApiReadFile(
    struct sq_winapi *api,
    HANDLE file,
    void *buffer,
    sq_u32 bytes_to_read,
    sq_u32 *bytes_read);
enum sq_status SqWinApiWriteFile(
    struct sq_winapi *api,
    HANDLE file,
    const void *buffer,
    sq_u32 bytes_to_write,
    sq_u32 *bytes_written);
enum sq_status SqWinApiCloseHandle(struct sq_winapi *api, HANDLE object);
enum sq_status SqWinApiSleep(struct sq_winapi *api, DWORD milliseconds);
enum sq_status SqWinApiWaitNamedPipeW(
    struct sq_winapi *api,
    LPCWSTR pipe_name,
    DWORD timeout);

enum sq_status SqWinApiWSAStartup(struct sq_winapi *api);
enum sq_status SqWinApiSocket(
    struct sq_winapi *api,
    int address_family,
    int socket_type,
    int protocol,
    SOCKET *socket_out);
enum sq_status SqWinApiConnect(
    struct sq_winapi *api,
    SOCKET socket_value,
    const struct sockaddr *name,
    int name_length);
enum sq_status SqWinApiSend(
    struct sq_winapi *api,
    SOCKET socket_value,
    const void *buffer,
    sq_u32 length,
    sq_u32 *bytes_sent);
enum sq_status SqWinApiRecv(
    struct sq_winapi *api,
    SOCKET socket_value,
    void *buffer,
    sq_u32 length,
    sq_u32 *bytes_received);
enum sq_status SqWinApiCloseSocket(
    struct sq_winapi *api,
    SOCKET socket_value);

#endif
