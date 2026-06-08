#ifndef SQUATTER_WINDOWS_SQ_IO_H_
#define SQUATTER_WINDOWS_SQ_IO_H_

#include "squatter.h"

#define SQ_IO_QUEUE_CAPACITY 16u
#define SQ_IO_PACKET_PAYLOAD_CAPACITY 128u

enum sq_io_packet_kind {
    SqIoPacketInvalid = 0,
    SqIoPacketTaskOutput = 1,
    SqIoPacketTaskError = 2,
    SqIoPacketTaskComplete = 3,
    SqIoPacketProtocolFrame = 4,
};

struct sq_io_packet {
    sq_u32 kind;
    sq_u32 task_id;
    sq_u32 sequence;
    sq_u32 length;
    sq_u8 payload[SQ_IO_PACKET_PAYLOAD_CAPACITY];
};

struct sq_io_dispatcher {
    sq_u32 head;
    sq_u32 tail;
    sq_u32 count;
    sq_u32 next_sequence;
    struct sq_io_packet packets[SQ_IO_QUEUE_CAPACITY];
};

enum sq_status SqIoInitialize(struct sq_io_dispatcher *dispatcher);
enum sq_status SqIoPost(
    struct sq_io_dispatcher *dispatcher,
    sq_u32 kind,
    sq_u32 task_id,
    const void *payload,
    sq_u32 length);
enum sq_status SqIoTryDequeue(
    struct sq_io_dispatcher *dispatcher,
    struct sq_io_packet *packet);

#endif
