#include "security/pki_config.h"

__attribute__((used)) sq_hovel_pki_config squatter_pki_config = {
    {'S', 'Q', 'P', 'K', 'I', '0', '0', '1'},
    SQ_PKI_CONFIG_VERSION,
    0u,
    0u,
    0u,
    0u,
    0u,
    0u,
    0u,
    0u,
    {0u},
    {0u},
    {0u},
};

BOOL sq_pki_config_present(const sq_hovel_pki_config *config)
{
        DWORD required = 0u;

        if (config == NULL || config->version != SQ_PKI_CONFIG_VERSION ||
            config->flags != SQ_PKI_CONFIG_FLAG_PRESENT || config->payload_length == 0u ||
            config->payload_length > SQ_PKI_BUNDLE_CAPACITY || config->bundle_length == 0u ||
            config->certificate_length == 0u || config->private_key_length == 0u)
        {
                return FALSE;
        }
        required = config->bundle_length;
        if (required > config->payload_length || config->certificate_length > config->payload_length - required)
        {
                return FALSE;
        }
        required += config->certificate_length;
        if (config->private_key_length > config->payload_length - required)
        {
                return FALSE;
        }
        required += config->private_key_length;
        if (required > config->payload_length)
        {
                return FALSE;
        }
        return TRUE;
}
