#include "sq_io.h"

enum sq_status SqIoInitialize(struct sq_io_dispatcher *dispatcher) {
    if (dispatcher == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    SqZeroMemory(dispatcher, (sq_u32)sizeof(*dispatcher));
    return SqStatusSuccess;
}

enum sq_status SqIoPost(
    struct sq_io_dispatcher *dispatcher,
    sq_u32 kind,
    sq_u32 task_id,
    const void *payload,
    sq_u32 length) {
    struct sq_io_packet *packet;

    if (dispatcher == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (length > SQ_IO_PACKET_PAYLOAD_CAPACITY) {
        return SqStatusBufferTooSmall;
    }

    if (length != 0 && payload == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (dispatcher->count == SQ_IO_QUEUE_CAPACITY) {
        return SqStatusQueueFull;
    }

    packet = &dispatcher->packets[dispatcher->tail];
    SqZeroMemory(packet, (sq_u32)sizeof(*packet));
    packet->kind = kind;
    packet->task_id = task_id;
    packet->sequence = dispatcher->next_sequence++;
    packet->length = length;
    if (length != 0) {
        SqCopyMemory(packet->payload, payload, length);
    }

    dispatcher->tail = (dispatcher->tail + 1u) % SQ_IO_QUEUE_CAPACITY;
    dispatcher->count++;
    return SqStatusSuccess;
}

enum sq_status SqIoTryDequeue(
    struct sq_io_dispatcher *dispatcher,
    struct sq_io_packet *packet) {
    if (dispatcher == SQ_NULL || packet == SQ_NULL) {
        return SqStatusInvalidParameter;
    }

    if (dispatcher->count == 0) {
        return SqStatusQueueEmpty;
    }

    SqCopyMemory(packet, &dispatcher->packets[dispatcher->head], (sq_u32)sizeof(*packet));
    SqZeroMemory(&dispatcher->packets[dispatcher->head], (sq_u32)sizeof(dispatcher->packets[dispatcher->head]));
    dispatcher->head = (dispatcher->head + 1u) % SQ_IO_QUEUE_CAPACITY;
    dispatcher->count--;
    return SqStatusSuccess;
}
