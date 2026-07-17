/* Squatter's minimal wolfSSL profile.
 *
 * This is intentionally a payload-owned configuration rather than wolfSSL's
 * desktop-Windows defaults. Squatter is a no-CRT executable with an NT 4.0
 * API floor. It supplies heap allocation and socket I/O while wolfSSL owns the
 * complete TLS protocol and cryptographic implementation.
 */
#ifndef HOVEL_SQUATTER_WOLFSSL_USER_SETTINGS_H
#define HOVEL_SQUATTER_WOLFSSL_USER_SETTINGS_H

#include <time.h>

time_t sq_wolfssl_time(time_t *timer);
struct tm *gmtime_r(const time_t *timer, struct tm *result);

#define WOLFSSL_USER_IO
#define WOLFSSL_NO_MALLOC
#define WOLFSSL_NO_SOCK
#define WOLFSSL_NO_SIGNAL
#define WOLFSSL_NO_THREAD_HELPERS
#define WOLFSSL_NO_TLS12
#define WOLFSSL_TLS13

#define HAVE_AESGCM
#define HAVE_ECC
#define HAVE_HASHDRBG
#define HAVE_HKDF
#define HAVE_SUPPORTED_CURVES
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_BLINDING
#define WC_RSA_PSS

#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define USE_FAST_MATH

#define NO_DES3
#define NO_DH
#define NO_DSA
#define NO_FILESYSTEM
#define NO_INLINE
#define NO_MD4
#define NO_MD5
#define NO_OLD_TLS
#define NO_PSK
#define NO_PWDBASED
#define NO_RC4
#define NO_SESSION_CACHE
#define NO_SHA
#define NO_STDIO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_CLIENT_AUTH
#define NO_ERROR_STRINGS

/* The payload provides these through its NT 4.0 Win32 portability layer. */
#define USER_TIME
#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE
#define XTIME sq_wolfssl_time
#define USE_WOLF_STRCASECMP
#define USE_WOLF_STRNCASECMP
#define CTYPE_USER
#define XTOLOWER(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c))
#define XTOUPPER(c) (((c) >= 'a' && (c) <= 'z') ? ((c) - ('a' - 'A')) : (c))

/* Formatting is only used for optional diagnostics in this profile. Avoid
 * pulling a CRT formatter into the payload. */
#define XSNPRINTF(...) (-1)

/* Keep only the curve used by Hovel's portable TLS server profile. */
#define ECC_USER_CURVES
#define HAVE_ECC256

#endif /* HOVEL_SQUATTER_WOLFSSL_USER_SETTINGS_H */
