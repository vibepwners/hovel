#include "squatter.h"

void SqZeroMemory(void *buffer, sq_u32 length) {
    sq_u8 *cursor;
    sq_u32 index;

    if (buffer == SQ_NULL) {
        return;
    }

    cursor = (sq_u8 *)buffer;
    for (index = 0; index < length; index++) {
        cursor[index] = 0;
    }
}

void SqCopyMemory(void *destination, const void *source, sq_u32 length) {
    sq_u8 *dst;
    const sq_u8 *src;
    sq_u32 index;

    if (destination == SQ_NULL || source == SQ_NULL) {
        return;
    }

    dst = (sq_u8 *)destination;
    src = (const sq_u8 *)source;
    for (index = 0; index < length; index++) {
        dst[index] = src[index];
    }
}
