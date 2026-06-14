/* getfile_module.h -- streams a server-side file to the peer.
 *
 *   args: getfile <remote-path>
 *
 * Reads the file SQ_XFER_CHUNK at a time and sends each chunk as a 'D' message,
 * preceded by an "OK <size>" status and followed by an 'E' marker. The whole
 * file never resides in memory. See file_xfer.h for the protocol.
 */
#ifndef SQ_MUX_GETFILE_MODULE_H
#define SQ_MUX_GETFILE_MODULE_H

#include "runtime/module.h"

#ifdef __cplusplus
extern "C" {
#endif

int sq_getfile_module_main(HANDLE input, HANDLE output, int argc,
                           wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_GETFILE_MODULE_H */
