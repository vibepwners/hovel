#include "security/tls.h"

/* Windows' lmerrlog.h owns ERROR_LOG as a public typedef. wolfSSL uses the
 * same token for an internal logging enum; namespace it at inclusion time. */
#define ERROR_LOG WOLFSSL_ERROR_LOG
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfio.h>
#undef ERROR_LOG

enum
{
        SQ_TLS_ERROR_NONE = 0,
        SQ_TLS_ERROR_STAMP = 1,
        SQ_TLS_ERROR_ALLOCATOR = 2,
        SQ_TLS_ERROR_LIBRARY = 3,
        SQ_TLS_ERROR_CONTEXT = 4,
        SQ_TLS_ERROR_CERTIFICATE = 5,
        SQ_TLS_ERROR_PRIVATE_KEY = 6,
        SQ_TLS_ERROR_HANDSHAKE = 7
};

struct sq_tls_session
{
        WOLFSSL *ssl;
        SOCKET socket;
};

static WOLFSSL_CTX *g_tls_context;
static BOOL g_tls_enabled;
static int g_tls_error;

static void secure_zero(void *pointer, SIZE_T length)
{
        volatile BYTE *cursor = (volatile BYTE *)pointer;

        while (length-- != 0u)
        {
                *cursor++ = 0u;
        }
}

time_t sq_wolfssl_time(time_t *timer)
{
        FILETIME file_time;
        ULARGE_INTEGER ticks;
        ULONGLONG seconds = 0u;
        time_t result = 0;

        GetSystemTimeAsFileTime(&file_time);
        ticks.LowPart = file_time.dwLowDateTime;
        ticks.HighPart = file_time.dwHighDateTime;
        seconds = ticks.QuadPart / 10000000u;
        if (seconds >= 11644473600u)
        {
                seconds -= 11644473600u;
        }
        else
        {
                seconds = 0u;
        }
        result = (time_t)seconds;
        if (timer != NULL)
        {
                *timer = result;
        }
        return result;
}

static void *sq_wolfssl_malloc(size_t size)
{
        return HeapAlloc(GetProcessHeap(), 0, size == 0u ? 1u : size);
}

static void sq_wolfssl_free(void *pointer)
{
        if (pointer != NULL)
        {
                (void)HeapFree(GetProcessHeap(), 0, pointer);
        }
}

static void *sq_wolfssl_realloc(void *pointer, size_t size)
{
        if (pointer == NULL)
        {
                return sq_wolfssl_malloc(size);
        }
        if (size == 0u)
        {
                sq_wolfssl_free(pointer);
                return NULL;
        }
        return HeapReAlloc(GetProcessHeap(), 0, pointer, size);
}

static BOOL digest_equal(const BYTE left[WC_SHA256_DIGEST_SIZE], const BYTE right[WC_SHA256_DIGEST_SIZE])
{
        BYTE difference = 0u;
        UINT32 i = 0u;

        for (i = 0u; i < WC_SHA256_DIGEST_SIZE; i++)
        {
                difference |= (BYTE)(left[i] ^ right[i]);
        }
        return difference == 0u;
}

static BOOL validate_stamp_digests(const sq_hovel_pki_config *config)
{
        BYTE digest[WC_SHA256_DIGEST_SIZE];

        if (wc_Sha256Hash(config->payload, config->payload_length, digest) != 0 ||
            !digest_equal(digest, config->payload_sha256))
        {
                secure_zero(digest, sizeof digest);
                return FALSE;
        }
        if (wc_Sha256Hash(config->payload, config->bundle_length, digest) != 0 ||
            !digest_equal(digest, config->bundle_sha256))
        {
                secure_zero(digest, sizeof digest);
                return FALSE;
        }
        secure_zero(digest, sizeof digest);
        return TRUE;
}

static BOOL read_u32(const BYTE **cursor, const BYTE *end, DWORD *value)
{
        const BYTE *at = *cursor;

        if ((SIZE_T)(end - at) < sizeof *value)
        {
                return FALSE;
        }
        *value = (DWORD)at[0] | ((DWORD)at[1] << 8u) | ((DWORD)at[2] << 16u) | ((DWORD)at[3] << 24u);
        *cursor += sizeof *value;
        return TRUE;
}

static BOOL skip_manifest_members(const BYTE **cursor, const BYTE *end, DWORD count)
{
        DWORD member_length = 0u;
        DWORD i = 0u;

        for (i = 0u; i < count; i++)
        {
                if (!read_u32(cursor, end, &member_length) || member_length == 0u ||
                    member_length > (DWORD)(end - *cursor))
                {
                        return FALSE;
                }
                *cursor += member_length;
        }
        return TRUE;
}

static BOOL validate_manifest_layout(const sq_hovel_pki_config *config)
{
        const BYTE *cursor = config->payload + config->bundle_length + config->certificate_length +
                             config->private_key_length;
        const BYTE *end = config->payload + config->payload_length;

        if (cursor > end || !skip_manifest_members(&cursor, end, config->chain_count) ||
            !skip_manifest_members(&cursor, end, config->trust_anchor_count) ||
            !skip_manifest_members(&cursor, end, config->crl_count))
        {
                return FALSE;
        }
        return cursor == end;
}

static BYTE *build_server_chain(const sq_hovel_pki_config *config, DWORD *chain_length)
{
        const BYTE *cursor = config->payload + config->bundle_length + config->certificate_length +
                             config->private_key_length;
        const BYTE *end = config->payload + config->payload_length;
        DWORD total = config->certificate_length;
        DWORD member_length = 0u;
        DWORD i = 0u;
        BYTE *chain = NULL;
        BYTE *destination = NULL;

        for (i = 0u; i < config->chain_count; i++)
        {
                if (!read_u32(&cursor, end, &member_length) || member_length == 0u ||
                    member_length > (DWORD)(end - cursor) || total > SQ_PKI_BUNDLE_CAPACITY - member_length)
                {
                        return NULL;
                }
                total += member_length;
                cursor += member_length;
        }

        chain = HeapAlloc(GetProcessHeap(), 0, total);
        if (chain == NULL)
        {
                return NULL;
        }
        destination = chain;
        CopyMemory(destination, config->payload + config->bundle_length, config->certificate_length);
        destination += config->certificate_length;
        cursor = config->payload + config->bundle_length + config->certificate_length + config->private_key_length;
        for (i = 0u; i < config->chain_count; i++)
        {
                if (!read_u32(&cursor, end, &member_length))
                {
                        secure_zero(chain, total);
                        (void)HeapFree(GetProcessHeap(), 0, chain);
                        return NULL;
                }
                CopyMemory(destination, cursor, member_length);
                destination += member_length;
                cursor += member_length;
        }
        *chain_length = total;
        return chain;
}

static int socket_receive(WOLFSSL *ssl, char *buffer, int size, void *context)
{
        SOCKET socket = *(SOCKET *)context;
        int received = 0;
        int error = 0;

        (void)ssl;
        received = recv(socket, buffer, size, 0);
        if (received > 0)
        {
                return received;
        }
        if (received == 0)
        {
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK)
        {
                return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        if (error == WSAEINTR)
        {
                return WOLFSSL_CBIO_ERR_ISR;
        }
        if (error == WSAECONNRESET)
        {
                return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        if (error == WSAETIMEDOUT)
        {
                return WOLFSSL_CBIO_ERR_TIMEOUT;
        }
        return WOLFSSL_CBIO_ERR_GENERAL;
}

static int socket_send(WOLFSSL *ssl, char *buffer, int size, void *context)
{
        SOCKET socket = *(SOCKET *)context;
        int sent = 0;
        int error = 0;

        (void)ssl;
        sent = send(socket, buffer, size, 0);
        if (sent >= 0)
        {
                return sent;
        }
        error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK)
        {
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        if (error == WSAEINTR)
        {
                return WOLFSSL_CBIO_ERR_ISR;
        }
        if (error == WSAECONNRESET)
        {
                return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        if (error == WSAETIMEDOUT)
        {
                return WOLFSSL_CBIO_ERR_TIMEOUT;
        }
        return WOLFSSL_CBIO_ERR_GENERAL;
}

BOOL sq_tls_runtime_init(const sq_hovel_pki_config *config)
{
        WOLFSSL_METHOD *method = NULL;
        BYTE *chain = NULL;
        DWORD chain_length = 0u;
        const BYTE *private_key = NULL;

        g_tls_error = SQ_TLS_ERROR_NONE;
        g_tls_enabled = FALSE;
        g_tls_context = NULL;
        if (config != NULL && config->flags == 0u)
        {
                return TRUE;
        }
        if (!sq_pki_config_present(config) || !validate_stamp_digests(config) || !validate_manifest_layout(config))
        {
                g_tls_error = SQ_TLS_ERROR_STAMP;
                return FALSE;
        }
        if (wolfSSL_SetAllocators(sq_wolfssl_malloc, sq_wolfssl_free, sq_wolfssl_realloc) != 0)
        {
                g_tls_error = SQ_TLS_ERROR_ALLOCATOR;
                return FALSE;
        }
        if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        {
                g_tls_error = SQ_TLS_ERROR_LIBRARY;
                return FALSE;
        }
        method = wolfTLSv1_3_server_method();
        g_tls_context = wolfSSL_CTX_new(method);
        if (g_tls_context == NULL)
        {
                g_tls_error = SQ_TLS_ERROR_CONTEXT;
                (void)wolfSSL_Cleanup();
                return FALSE;
        }

        wolfSSL_CTX_SetIORecv(g_tls_context, socket_receive);
        wolfSSL_CTX_SetIOSend(g_tls_context, socket_send);
        chain = build_server_chain(config, &chain_length);
        if (chain == NULL || wolfSSL_CTX_use_certificate_chain_buffer_format(
                                 g_tls_context, chain, (long)chain_length, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        {
                g_tls_error = SQ_TLS_ERROR_CERTIFICATE;
                goto fail;
        }
        private_key = config->payload + config->bundle_length + config->certificate_length;
        if (wolfSSL_CTX_use_PrivateKey_buffer(g_tls_context, private_key, (long)config->private_key_length,
                                              WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_check_private_key(g_tls_context) != WOLFSSL_SUCCESS)
        {
                g_tls_error = SQ_TLS_ERROR_PRIVATE_KEY;
                goto fail;
        }
        secure_zero(chain, chain_length);
        (void)HeapFree(GetProcessHeap(), 0, chain);
        g_tls_enabled = TRUE;
        return TRUE;

fail:
        if (chain != NULL)
        {
                secure_zero(chain, chain_length);
                (void)HeapFree(GetProcessHeap(), 0, chain);
        }
        wolfSSL_CTX_free(g_tls_context);
        g_tls_context = NULL;
        (void)wolfSSL_Cleanup();
        return FALSE;
}

void sq_tls_runtime_cleanup(void)
{
        if (g_tls_context != NULL)
        {
                wolfSSL_CTX_free(g_tls_context);
                g_tls_context = NULL;
        }
        if (g_tls_enabled)
        {
                (void)wolfSSL_Cleanup();
        }
        g_tls_enabled = FALSE;
}

BOOL sq_tls_runtime_enabled(void) { return g_tls_enabled; }

int sq_tls_runtime_error(void) { return g_tls_error; }

sq_tls_session *sq_tls_session_accept(SOCKET socket)
{
        sq_tls_session *session = NULL;
        int result = 0;
        int error = 0;

        if (!g_tls_enabled || g_tls_context == NULL || socket == INVALID_SOCKET)
        {
                return NULL;
        }
        session = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *session);
        if (session == NULL)
        {
                return NULL;
        }
        session->socket = socket;
        session->ssl = wolfSSL_new(g_tls_context);
        if (session->ssl == NULL)
        {
                (void)HeapFree(GetProcessHeap(), 0, session);
                return NULL;
        }
        wolfSSL_SetIOReadCtx(session->ssl, &session->socket);
        wolfSSL_SetIOWriteCtx(session->ssl, &session->socket);
        for (;;)
        {
                result = wolfSSL_accept(session->ssl);
                if (result == WOLFSSL_SUCCESS)
                {
                        return session;
                }
                error = wolfSSL_get_error(session->ssl, result);
                if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE)
                {
                        break;
                }
        }
        g_tls_error = SQ_TLS_ERROR_HANDSHAKE;
        wolfSSL_free(session->ssl);
        secure_zero(session, sizeof *session);
        (void)HeapFree(GetProcessHeap(), 0, session);
        return NULL;
}

int sq_tls_session_read_some(sq_tls_session *session, BYTE *buffer, UINT32 capacity)
{
        int result = 0;
        int error = 0;

        if (session == NULL || buffer == NULL || capacity == 0u)
        {
                return -1;
        }
        for (;;)
        {
                result = wolfSSL_read(session->ssl, buffer, (int)capacity);
                if (result > 0)
                {
                        return result;
                }
                error = wolfSSL_get_error(session->ssl, result);
                if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE)
                {
                        continue;
                }
                return (error == WOLFSSL_ERROR_ZERO_RETURN) ? 0 : -1;
        }
}

BOOL sq_tls_session_write_all(sq_tls_session *session, const BYTE *buffer, UINT32 length)
{
        UINT32 offset = 0u;

        if (session == NULL || (buffer == NULL && length != 0u))
        {
                return FALSE;
        }
        while (offset < length)
        {
                int result = wolfSSL_write(session->ssl, buffer + offset, (int)(length - offset));
                if (result <= 0)
                {
                        int error = wolfSSL_get_error(session->ssl, result);
                        if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                continue;
                        }
                        return FALSE;
                }
                offset += (UINT32)result;
        }
        return TRUE;
}

void sq_tls_session_close(sq_tls_session *session)
{
        if (session != NULL && session->socket != INVALID_SOCKET)
        {
                (void)shutdown(session->socket, SD_BOTH);
                (void)closesocket(session->socket);
                session->socket = INVALID_SOCKET;
        }
}

void sq_tls_session_free(sq_tls_session *session)
{
        if (session == NULL)
        {
                return;
        }
        sq_tls_session_close(session);
        if (session->ssl != NULL)
        {
                wolfSSL_free(session->ssl);
        }
        secure_zero(session, sizeof *session);
        (void)HeapFree(GetProcessHeap(), 0, session);
}
