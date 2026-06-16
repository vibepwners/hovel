/* control_codec.h -- encode/decode the OPEN/CLOSE frame payloads.
 *
 * These helpers encode the protobuf wire shape documented in control.proto for
 * the small field subset Squatter uses. Encoded buffers come from the process
 * heap; free with sq_control_buffer_free. */
#ifndef SQ_MUX_CONTROL_CODEC_H
#define SQ_MUX_CONTROL_CODEC_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        enum
        {
                SQMUX_OPEN_MODULE_MAX = 64,
                SQMUX_OPEN_ARGS_MAX = 16,
                SQMUX_OPEN_ARG_MAX = 256,
                SQMUX_EVENT_MESSAGE_MAX = 512,
        };

        enum
        {
                SQMUX_EVENT_STARTED = 1,
                SQMUX_EVENT_INTERACTIVE = 2,
                SQMUX_EVENT_EXITED = 3,
                SQMUX_EVENT_ERROR = 4,
                SQMUX_EVENT_DEBUG = 5,
        };

        typedef struct sqmux_OpenStream
        {
                char module[SQMUX_OPEN_MODULE_MAX];
                int args_count;
                char args[SQMUX_OPEN_ARGS_MAX][SQMUX_OPEN_ARG_MAX];
        } sqmux_OpenStream;

        typedef struct sqmux_StreamEvent
        {
                UINT32 kind;
                UINT32 code;
                char message[SQMUX_EVENT_MESSAGE_MAX];
        } sqmux_StreamEvent;

        /* Encode an OpenStream{module, args[0..n_args)} into *out / *out_len. */
        BOOL sq_control_encode_open(const char *module, const char *const *args, int n_args, BYTE **out,
                                    UINT32 *out_len);

        /* Decode an OpenStream payload into *out. Returns FALSE on a malformed body. */
        BOOL sq_control_decode_open(const BYTE *payload, UINT32 len, sqmux_OpenStream *out);

        /* Encode a CloseStream{code}. */
        BOOL sq_control_encode_close(UINT32 code, BYTE **out, UINT32 *out_len);

        BOOL sq_control_decode_close(const BYTE *payload, UINT32 len, UINT32 *code);

        BOOL sq_control_encode_event(UINT32 kind, UINT32 code, const char *message, BYTE **out, UINT32 *out_len);

        BOOL sq_control_decode_event(const BYTE *payload, UINT32 len, sqmux_StreamEvent *out);

        void sq_control_buffer_free(BYTE *buf);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_CONTROL_CODEC_H */
