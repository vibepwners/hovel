#include "iocpserver/echo.h"

#include "base/win.h"

static size_t echo_on_recv(void *user, const unsigned char *in, size_t in_len, unsigned char *out, size_t out_cap)
{
        size_t n = (in_len < out_cap) ? in_len : out_cap;

        (void)user; /* stateless */
        /* in and out are distinct connection buffers, so a straight copy is correct
         * and the non-overlap precondition genuinely holds. */
        if (n > 0)
        {
                CopyMemory(out, in, n);
        }
        return n;
}

sq_handler sq_echo_handler(void)
{
        sq_handler h = {0};

        h.on_recv = echo_on_recv;
        h.user = NULL;
        return h;
}
