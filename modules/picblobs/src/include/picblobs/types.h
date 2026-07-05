/*
 * picblobs/types.h — portable type definitions for freestanding PIC blobs.
 *
 * No standard library headers are available. All types used by blobs
 * and test runners are defined here.
 */

#ifndef PICBLOBS_TYPES_H
#define PICBLOBS_TYPES_H

/* Fixed-width integer types — compiler builtins, no headers needed. */
typedef __UINT8_TYPE__ pic_u8;
typedef __UINT16_TYPE__ pic_u16;
typedef __UINT32_TYPE__ pic_u32;
typedef __UINT64_TYPE__ pic_u64;
typedef __INT8_TYPE__ pic_i8;
typedef __INT16_TYPE__ pic_i16;
typedef __INT32_TYPE__ pic_i32;
typedef __INT64_TYPE__ pic_i64;

/* Size type — word-sized unsigned. */
typedef __SIZE_TYPE__ pic_size_t;

/* Pointer-sized integer. */
typedef __UINTPTR_TYPE__ pic_uintptr;

/* Null pointer. */
#define PIC_NULL ((void *)0)

#endif /* PICBLOBS_TYPES_H */
