/* putfile_module.h -- receives a file from the peer and writes it server-side.
 *
 *   args: putfile <remote-path>
 *
 * Sends "OK" when the file is ready, then writes each incoming 'D' chunk
 * straight to disk until an 'E' marker arrives, then replies "OK <bytes>". The
 * whole file never resides in memory. See file_xfer.h for the protocol.
 */
#ifndef SQ_MUX_PUTFILE_MODULE_H
#define SQ_MUX_PUTFILE_MODULE_H

#include "runtime/module.h"

#ifdef __cplusplus
extern "C"
{
#endif

        int sq_putfile_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_PUTFILE_MODULE_H */
