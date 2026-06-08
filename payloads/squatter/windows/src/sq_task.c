#include "sq_task.h"

static sq_u32 SqStringLength(const char *text, sq_u32 maximum) {
    sq_u32 length;

    if (text == SQ_NULL) {
        return 0;
    }

    for (length = 0; length < maximum; length++) {
        if (text[length] == '\0') {
            return length;
        }
    }

    return maximum;
}

enum sq_status SqTaskRegistryInitialize(struct sq_task_registry *registry) {
    if (registry == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(registry, (sq_u32)sizeof(*registry));
    return SqStatusSuccess;
}

enum sq_status SqTaskRegister(
    struct sq_task_registry *registry,
    const struct sq_task_descriptor *descriptor) {
    struct sq_task_descriptor *slot;
    sq_u32 name_length;

    if (registry == SQ_NULL || descriptor == SQ_NULL || descriptor->entry == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (registry->count == SQ_TASK_REGISTRY_CAPACITY) {
        return SqStatusQueueFull;
    }

    slot = &registry->descriptors[registry->count];
    SqZeroMemory(slot, (sq_u32)sizeof(*slot));
    slot->task_id = descriptor->task_id;
    slot->entry = descriptor->entry;
    name_length = SqStringLength(descriptor->name, SQ_TASK_NAME_CAPACITY - 1u);
    if (name_length != 0) {
        SqCopyMemory(slot->name, descriptor->name, name_length);
    }

    registry->count++;
    return SqStatusSuccess;
}

enum sq_status SqTaskFind(
    const struct sq_task_registry *registry,
    sq_u32 task_id,
    const struct sq_task_descriptor **descriptor) {
    sq_u32 index;

    if (registry == SQ_NULL || descriptor == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    *descriptor = SQ_NULL;
    for (index = 0; index < registry->count; index++) {
        if (registry->descriptors[index].task_id == task_id) {
            *descriptor = &registry->descriptors[index];
            return SqStatusSuccess;
        }
    }

    return SqStatusNotFound;
}

enum sq_status SqTaskRunInline(
    const struct sq_task_descriptor *descriptor,
    const struct sq_task_request *request,
    struct sq_io_dispatcher *io) {
    struct sq_task_context context;

    if (descriptor == SQ_NULL || descriptor->entry == SQ_NULL || request == SQ_NULL || io == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(&context, (sq_u32)sizeof(context));
    context.task_id = request->task_id;
    context.request = request;
    context.io = io;
    return descriptor->entry(&context);
}

enum sq_status SqTaskNoopEntry(struct sq_task_context *context) {
    static const sq_u8 message[] = {'n', 'o', 'o', 'p'};
    enum sq_status status;

    if (context == SQ_NULL || context->io == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    status = SqIoPost(
        context->io,
        SqIoPacketTaskOutput,
        context->task_id,
        message,
        (sq_u32)sizeof(message));
    if (status != SqStatusSuccess) {
        return status;
    }

    return SqIoPost(
        context->io,
        SqIoPacketTaskComplete,
        context->task_id,
        SQ_NULL,
        0);
}
