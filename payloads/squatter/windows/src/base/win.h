/* win.h -- the *only* place Windows system headers are included.
 *
 * Two things must be true before <windows.h> is pulled in, and getting either
 * wrong produces baffling failures far from the cause:
 *
 *   1. <winsock2.h> must precede <windows.h>. <windows.h> transitively includes
 *      the ancient <winsock.h>, whose definitions collide with Winsock 2. The
 *      classic symptom is a wall of redefinition errors for struct sockaddr et al.
 *
 *   2. _WIN32_WINNT must be set to the minimum OS whose APIs we use *before* any
 *      SDK header is seen, or the prototypes we need (AcceptEx context options,
 *      GetAddrInfo, etc.) are conditionally compiled out.
 *
 * Centralizing the order here means no other translation unit has to remember
 * it. Every module includes "base/win.h" and nothing else Windows-y.
 *
 * _WIN32_WINNT is also pinned on the compiler command line (see the BUILD copts)
 * as a belt-and-suspenders default; the guard below keeps the two from fighting.
 */
#ifndef SQ_WIN_H
#define SQ_WIN_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 /* Windows XP SP3: lab support floor. */
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1 /* Drop GDI/OLE/etc. we never touch. */
#endif

#include <mswsock.h>  /* AcceptEx, GetAcceptExSockaddrs, the WSAID_* GUIDs */
#include <shlwapi.h>  /* wnsprintf/wvnsprintf: bounded, CRT-free formatting */
#include <windows.h>  /* CreateIoCompletionPort, threads, handles */
#include <winsock2.h> /* must be first */
#include <ws2tcpip.h> /* getaddrinfo, getnameinfo, IPv6 sockaddr */

#endif /* SQ_WIN_H */
