/* module_wire.h -- the packet format between the runtime and modules.
 *
 * The outer session multiplexes OPEN/DATA/CONTROL/CLOSE frames over one
 * transport. Inside the process, each module gets two message-mode pipes carrying
 * these small SQM1 packets. The helpers below keep module code simple: most
 * modules only need sq_module_read_data/sq_module_write_data.
 */
#ifndef SQ_RUNTIME_MODULE_WIRE_H
#define SQ_RUNTIME_MODULE_WIRE_H

#include "base/win.h"

#ifdef __cplusplus
extern "C"
{
#endif

        enum
        {
                SQ_MODULE_PACKET_HEADER_SIZE = 16,
                SQ_MODULE_PACKET_MAX_PAYLOAD = 65520,
        };

        typedef enum sq_module_packet_kind
        {
                SQ_MODULE_PACKET_NONE = 0,
                SQ_MODULE_PACKET_DATA = 1,
                SQ_MODULE_PACKET_CONTROL = 2,
        } sq_module_packet_kind;

        typedef enum sq_module_control_kind
        {
                SQ_MODULE_CONTROL_CLOSE = 256,
        } sq_module_control_kind;

        typedef struct sq_module_packet
        {
                sq_module_packet_kind kind;
                UINT32 control_kind;
                UINT32 code;
                const BYTE *payload;
                DWORD length;
        } sq_module_packet;

        BOOL sq_module_packet_encode(sq_module_packet_kind kind, UINT32 control_kind, UINT32 code, const BYTE *payload,
                                     DWORD len, BYTE **out, DWORD *out_len);
        BOOL sq_module_packet_decode(const BYTE *buf, DWORD len, sq_module_packet *out);
        void sq_module_packet_free(BYTE *buf);

        BOOL sq_module_read_packet(HANDLE input, BYTE *buf, DWORD cap, sq_module_packet *out);
        BOOL sq_module_read_data(HANDLE input, BYTE *buf, DWORD cap, DWORD *out_len);
        BOOL sq_module_write_data(HANDLE output, const BYTE *data, DWORD len);
        BOOL sq_module_write_control(HANDLE output, UINT32 kind, UINT32 code, const char *message);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_RUNTIME_MODULE_WIRE_H */
