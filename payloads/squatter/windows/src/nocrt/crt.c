#include "nocrt/api.h"

void *memset(void *dst, int value, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
size_t strlen(const char *s);
int strncmp(const char *a, const char *b, size_t n);
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
	while (n-- != 0) {
		*p++ = (unsigned char)value;
	}
	return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
	unsigned char *d = (unsigned char *)dst;
	const unsigned char *s = (const unsigned char *)src;
	while (n-- != 0) {
		*d++ = *s++;
	}
	return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
	unsigned char *d = (unsigned char *)dst;
	const unsigned char *s = (const unsigned char *)src;
	if (d < s) {
		return memcpy(dst, src, n);
	}
	d += n;
	s += n;
	while (n-- != 0) {
		*--d = *--s;
	}
	return dst;
}

size_t strlen(const char *s)
{
	const char *p = s;
	while (*p != '\0') {
		p++;
	}
	return (size_t)(p - s);
}

int strncmp(const char *a, const char *b, size_t n)
{
	while (n-- != 0) {
		unsigned char ca = (unsigned char)*a++;
		unsigned char cb = (unsigned char)*b++;
		if (ca != cb || ca == '\0') {
			return (int)ca - (int)cb;
		}
	}
	return 0;
}

size_t wcslen(const wchar_t *s)
{
	const wchar_t *p = s;
	while (*p != L'\0') {
		p++;
	}
	return (size_t)(p - s);
}

void __main(void) {}
void abort(void) { ExitProcess(3); }
void exit(int code) { ExitProcess((UINT)code); }
void _exit(int code) { ExitProcess((UINT)code); }
int __mingw_vsnwprintf(wchar_t *buf, size_t cap, const wchar_t *fmt, va_list ap)
{
	return wvnsprintfW(buf, (int)cap, fmt, ap);
}
