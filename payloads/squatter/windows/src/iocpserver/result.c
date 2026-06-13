#include "iocpserver/result.h"

const char *sq_status_str(sq_status status)
{
    switch (status) {
    case SQ_OK:          return "SQ_OK";
    case SQ_ERR_PARAM:   return "SQ_ERR_PARAM";
    case SQ_ERR_NOMEM:   return "SQ_ERR_NOMEM";
    case SQ_ERR_SYSTEM:  return "SQ_ERR_SYSTEM";
    case SQ_ERR_ADDRESS: return "SQ_ERR_ADDRESS";
    case SQ_ERR_STATE:   return "SQ_ERR_STATE";
    }
    /* No `default:` above: a new enumerator without a case is then a
     * -Wswitch warning (and -Werror) instead of a silent fall-through. */
    return "SQ_ERR_<unknown>";
}
