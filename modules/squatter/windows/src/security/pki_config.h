/* pki_config.h -- versioned Hovel PKI credential slot embedded in Squatter.
 *
 * The provider locates SQPKI001 in the PE and replaces the zeroed payload with
 * one complete hovel.pki.bundle/v1 JSON document.  Keeping the envelope small,
 * fixed-width, and independent of PE section names makes stamping identical on
 * PE32 and PE32+ while allowing the bundle schema to evolve independently.
 */
#ifndef SQ_SECURITY_PKI_CONFIG_H
#define SQ_SECURITY_PKI_CONFIG_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SQ_PKI_CONFIG_VERSION 1u
#define SQ_PKI_CONFIG_FLAG_PRESENT 0xa5c35a3cu
#define SQ_PKI_BUNDLE_CAPACITY (1024u * 1024u)

        typedef struct sq_hovel_pki_config
        {
                char magic[8];
                DWORD version;
                DWORD flags;
                DWORD payload_length;
                DWORD bundle_length;
                DWORD certificate_length;
                DWORD private_key_length;
                DWORD chain_count;
                DWORD trust_anchor_count;
                DWORD crl_count;
                BYTE bundle_sha256[32];
                BYTE payload_sha256[32];
                BYTE payload[SQ_PKI_BUNDLE_CAPACITY];
        } sq_hovel_pki_config;

        extern sq_hovel_pki_config squatter_pki_config;

        BOOL sq_pki_config_present(const sq_hovel_pki_config *config);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_SECURITY_PKI_CONFIG_H */
