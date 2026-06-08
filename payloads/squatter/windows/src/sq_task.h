#ifndef SQUATTER_WINDOWS_SQ_TASK_H_
#define SQUATTER_WINDOWS_SQ_TASK_H_

#include "sq_io.h"

#define SQ_TASK_MAX_ARGUMENTS 8u
#define SQ_TASK_ARGUMENT_CAPACITY 64u
#define SQ_TASK_NAME_CAPACITY 32u
#define SQ_TASK_REGISTRY_CAPACITY 8u

struct sq_task_argument {
    sq_u32 length;
    sq_u8 value[SQ_TASK_ARGUMENT_CAPACITY];
};

struct sq_task_request {
    sq_u32 task_id;
    sq_u32 argument_count;
    struct sq_task_argument arguments[SQ_TASK_MAX_ARGUMENTS];
};

struct sq_task_context {
    sq_u32 task_id;
    sq_u32 cancellation_requested;
    const struct sq_task_request *request;
    struct sq_io_dispatcher *io;
};

typedef enum sq_status (*sq_task_entry)(struct sq_task_context *context);

struct sq_task_descriptor {
    sq_u32 task_id;
    char name[SQ_TASK_NAME_CAPACITY];
    sq_task_entry entry;
};

struct sq_task_registry {
    sq_u32 count;
    struct sq_task_descriptor descriptors[SQ_TASK_REGISTRY_CAPACITY];
};

enum sq_status SqTaskRegistryInitialize(struct sq_task_registry *registry);
enum sq_status SqTaskRegister(
    struct sq_task_registry *registry,
    const struct sq_task_descriptor *descriptor);
enum sq_status SqTaskFind(
    const struct sq_task_registry *registry,
    sq_u32 task_id,
    const struct sq_task_descriptor **descriptor);
enum sq_status SqTaskRunInline(
    const struct sq_task_descriptor *descriptor,
    const struct sq_task_request *request,
    struct sq_io_dispatcher *io);

enum sq_status SqTaskNoopEntry(struct sq_task_context *context);

#endif
