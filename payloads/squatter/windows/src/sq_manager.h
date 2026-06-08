#ifndef SQUATTER_WINDOWS_SQ_MANAGER_H_
#define SQUATTER_WINDOWS_SQ_MANAGER_H_

#include "sq_task.h"
#include "sq_transport.h"

#define SQ_TASK_NOOP 1u

struct sq_manager {
    struct sq_io_dispatcher io;
    struct sq_task_registry tasks;
    struct sq_linker linker;
    struct sq_winapi api;
    struct sq_transport transport;
    sq_u32 linker_initialized;
    sq_u32 api_initialized;
    sq_u32 transport_connected;
    sq_u32 initialized;
};

enum sq_status SqManagerInitialize(struct sq_manager *manager);
enum sq_status SqManagerConnectTransport(
    struct sq_manager *manager,
    const struct sq_transport_config *config);
enum sq_status SqManagerSendProtocolHello(struct sq_manager *manager);
enum sq_status SqManagerStartTask(
    struct sq_manager *manager,
    const struct sq_task_request *request);
enum sq_status SqManagerDrainOne(
    struct sq_manager *manager,
    struct sq_io_packet *packet);

#endif
