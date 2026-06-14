/* echo_module.h -- the proof-of-concept module.
 *
 * Behavior:
 *   1. On start, write one message echoing its own argc/argv back to the peer,
 *      in the form:  "argc=<N> <argv0> <argv1> ..."
 *   2. Then echo every message it receives back verbatim, until it receives a
 *      message whose bytes are exactly "END".
 *   3. On "END" (or if the pipe closes), return -- which ends the stream
 *      gracefully (the runtime emits CLOSE to the peer).
 */
#ifndef SQ_MUX_ECHO_MODULE_H
#define SQ_MUX_ECHO_MODULE_H

#include "runtime/module.h"

#ifdef __cplusplus
extern "C" {
#endif

int sq_echo_module_main(HANDLE input, HANDLE output, int argc, wchar_t **argv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_ECHO_MODULE_H */
