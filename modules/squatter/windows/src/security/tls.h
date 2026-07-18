/* tls.h -- wolfSSL-backed TLS for stamped Squatter TCP-bind payloads. */
#ifndef SQ_SECURITY_TLS_H
#define SQ_SECURITY_TLS_H

#include "base/win.h"
#include "security/pki_config.h"

#ifdef __cplusplus
extern "C"
{
#endif

        typedef struct sq_tls_session sq_tls_session;

        /* Initialize the process-wide server context. An unstamped payload is
         * intentionally left in plaintext mode. A present but invalid stamp is
         * a hard failure and never falls back to plaintext. */
        BOOL sq_tls_runtime_init(const sq_hovel_pki_config *config);
        void sq_tls_runtime_cleanup(void);
        BOOL sq_tls_runtime_enabled(void);
        int sq_tls_runtime_error(void);

        /* Create a TLS session over an owned socket. The blocking handshake is
         * deferred until the session worker performs its first I/O, so the TCP
         * listener remains available to accept other clients. */
        sq_tls_session *sq_tls_session_create(SOCKET socket);
        int sq_tls_session_read_some(sq_tls_session *session, BYTE *buffer, UINT32 capacity);
        BOOL sq_tls_session_write_all(sq_tls_session *session, const BYTE *buffer, UINT32 length);
        void sq_tls_session_close(sq_tls_session *session);
        void sq_tls_session_free(sq_tls_session *session);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_SECURITY_TLS_H */
