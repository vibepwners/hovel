#include "nocrt/api.h"

void *memset(void *dst, int value, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strncpy(char *dst, const char *src, size_t n);
char *strstr(const char *haystack, const char *needle);
size_t wcslen(const wchar_t *s);
void __main(void);
void abort(void);
void exit(int code);
void _exit(int code);
int __mingw_vsnwprintf(wchar_t *buf, size_t cap, const wchar_t *fmt, va_list ap);
void WINAPI ExitProcess(UINT exit_code);
int WINAPI wvnsprintfW(LPWSTR buf, int cap, LPCWSTR fmt, va_list ap);

int _fltused = 0;

void *memset(void *dst, int value, size_t n)
{
        unsigned char *p = (unsigned char *)dst;
        while (n-- != 0)
        {
                *p++ = (unsigned char)value;
        }
        return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
        unsigned char *d = (unsigned char *)dst;
        const unsigned char *s = (const unsigned char *)src;
        while (n-- != 0)
        {
                *d++ = *s++;
        }
        return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
        unsigned char *d = (unsigned char *)dst;
        const unsigned char *s = (const unsigned char *)src;
        if (d < s)
        {
                return memcpy(dst, src, n);
        }
        d += n;
        s += n;
        while (n-- != 0)
        {
                *--d = *--s;
        }
        return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
        const unsigned char *left = (const unsigned char *)a;
        const unsigned char *right = (const unsigned char *)b;

        while (n-- != 0u)
        {
                if (*left != *right)
                {
                        return (int)*left - (int)*right;
                }
                left++;
                right++;
        }
        return 0;
}

size_t strlen(const char *s)
{
        const char *p = s;
        while (*p != '\0')
        {
                p++;
        }
        return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
        while (*a != '\0' && *a == *b)
        {
                a++;
                b++;
        }
        return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
        while (n-- != 0)
        {
                unsigned char ca = (unsigned char)*a++;
                unsigned char cb = (unsigned char)*b++;
                if (ca != cb || ca == '\0')
                {
                        return (int)ca - (int)cb;
                }
        }
        return 0;
}

char *strncpy(char *dst, const char *src, size_t n)
{
        char *result = dst;

        while (n != 0u && *src != '\0')
        {
                *dst++ = *src++;
                n--;
        }
        while (n-- != 0u)
        {
                *dst++ = '\0';
        }
        return result;
}

char *strstr(const char *haystack, const char *needle)
{
        union {
                const char *source;
                char *result;
        } match;
        size_t needle_length = strlen(needle);

        if (needle_length == 0u)
        {
                match.source = haystack;
                return match.result;
        }
        while (*haystack != '\0')
        {
                if (strncmp(haystack, needle, needle_length) == 0)
                {
                        match.source = haystack;
                        return match.result;
                }
                haystack++;
        }
        return NULL;
}

size_t wcslen(const wchar_t *s)
{
        const wchar_t *p = s;
        while (*p != L'\0')
        {
                p++;
        }
        return (size_t)(p - s);
}

void __main(void)
{
}
void abort(void)
{
        ExitProcess(3);
        for (;;)
        {
        }
}

void exit(int code)
{
        ExitProcess((UINT)code);
        for (;;)
        {
        }
}

void _exit(int code)
{
        ExitProcess((UINT)code);
        for (;;)
        {
        }
}
int __mingw_vsnwprintf(wchar_t *buf, size_t cap, const wchar_t *fmt, va_list ap)
{
        return wvnsprintfW(buf, (int)cap, fmt, ap);
}
