/* echo.h -- the default protocol handler: send back exactly what was received.
 *
 * Stateless and reentrant, so a single shared sq_handler value (user == NULL)
 * is safe across every worker thread. */
#ifndef SQ_ECHO_H
#define SQ_ECHO_H

#include "iocpserver/handler.h"

/* Return a handler that echoes its input. */
sq_handler sq_echo_handler(void);

#endif /* SQ_ECHO_H */
