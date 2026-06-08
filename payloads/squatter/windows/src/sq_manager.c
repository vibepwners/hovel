#include "sq_manager.h"

enum sq_status SqManagerInitialize(struct sq_manager *manager) {
    enum sq_status status;
    struct sq_task_descriptor noop_task;

    if (manager == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(manager, (sq_u32)sizeof(*manager));

    status = SqIoInitialize(&manager->io);
    if (status != SqStatusSuccess) {
        return status;
    }

    status = SqTaskRegistryInitialize(&manager->tasks);
    if (status != SqStatusSuccess) {
        return status;
    }

    status = SqLinkerInitialize(&manager->linker);
    if (status == SqStatusSuccess) {
        manager->linker_initialized = 1u;
        status = SqWinApiInitialize(&manager->api, &manager->linker);
        if (status != SqStatusSuccess) {
            return status;
        }
        manager->api_initialized = 1u;
    }

    status = SqTransportInitialize(&manager->transport);
    if (status != SqStatusSuccess) {
        return status;
    }

    SqZeroMemory(&noop_task, (sq_u32)sizeof(noop_task));
    noop_task.task_id = SQ_TASK_NOOP;
    noop_task.name[0] = 'n';
    noop_task.name[1] = 'o';
    noop_task.name[2] = 'o';
    noop_task.name[3] = 'p';
    noop_task.entry = SqTaskNoopEntry;

    status = SqTaskRegister(&manager->tasks, &noop_task);
    if (status != SqStatusSuccess) {
        return status;
    }

    manager->initialized = 1u;
    return SqStatusSuccess;
}

enum sq_status SqManagerConnectTransport(
    struct sq_manager *manager,
    const struct sq_transport_config *config) {
    enum sq_status status;

    if (manager == SQ_NULL || config == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (manager->initialized == 0u || manager->api_initialized == 0u) {
        return SqStatusInvalidParameter;
    }

    status = SqTransportConnect(&manager->transport, &manager->api, config);
    if (status != SqStatusSuccess) {
        return status;
    }

    manager->transport_connected = 1u;
    return SqStatusSuccess;
}

enum sq_status SqManagerSendProtocolHello(struct sq_manager *manager) {
    static const sq_u8 hello[] = {
        'S', 'Q', 'U', 'A', 'T', 'T', 'E', 'R',
        0x01u, 0x00u, 0x00u, 0x00u,
    };
    sq_u32 bytes_sent;

    if (manager == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (manager->transport_connected == 0u) {
        return SqStatusInvalidParameter;
    }

    bytes_sent = 0;
    return SqTransportSend(
        &manager->transport,
        &manager->api,
        hello,
        (sq_u32)sizeof(hello),
        &bytes_sent);
}

enum sq_status SqManagerStartTask(
    struct sq_manager *manager,
    const struct sq_task_request *request) {
    const struct sq_task_descriptor *descriptor;
    enum sq_status status;

    if (manager == SQ_NULL || request == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (manager->initialized == 0u) {
        return SqStatusInvalidParameter;
    }

    status = SqTaskFind(&manager->tasks, request->task_id, &descriptor);
    if (status != SqStatusSuccess) {
        return status;
    }

    /*
     * This scaffold executes inline to preserve the no-import PE contract.
     * The next runtime slice should replace this call with a thread start
     * routine that owns this exact task context and posts completions through
     * the same I/O dispatcher.
     */
    return SqTaskRunInline(descriptor, request, &manager->io);
}

enum sq_status SqManagerDrainOne(
    struct sq_manager *manager,
    struct sq_io_packet *packet) {
    if (manager == SQ_NULL || packet == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    return SqIoTryDequeue(&manager->io, packet);
}
