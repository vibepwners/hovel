/*
 * picblobs/log.h — PIC logging facility for debug builds.
 *
 * Usage:
 *   PIC_LOG("stager: connected to port %d\n", port);
 *   PIC_LOG("mmap returned %x\n", (unsigned long)addr);
 *   PIC_LOG("loading %s\n", filename);
 *
 * In debug builds (-DPIC_LOG_ENABLE), PIC_LOG() formats the message and
 * writes it to stderr (fd 2) via the sys_write() syscall. In release
 * builds, PIC_LOG() expands to nothing — zero code, zero strings.
 *
 * IMPORTANT: Include your OS header (e.g., picblobs/os/linux.h) BEFORE
 * this header, since log.h depends on sys/write.h which requires the
 * OS define.
 *
 * Supported format specifiers:
 *   %d  — signed decimal integer (long)
 *   %x  — unsigned hexadecimal integer (unsigned long), no "0x" prefix
 *   %s  — null-terminated string
 *   %%  — literal '%'
 */

#ifndef PICBLOBS_LOG_H
#define PICBLOBS_LOG_H

#ifdef PIC_LOG_ENABLE

#include "picblobs/section.h"
#include "picblobs/sys/write.h"

/*
 * Internal: write a single character to stderr.
 */
PIC_TEXT
static inline void _pic_log_putc(char c) { pic_write(2, &c, 1); }

/*
 * Internal: write a null-terminated string to stderr.
 */
PIC_TEXT
static inline void _pic_log_puts(const char *s)
{
	const char *p = s;
	while (*p) {
		p++;
	}
	if (p != s) {
		pic_write(2, s, (pic_size_t)(p - s));
	}
}

/*
 * Internal: write a signed long as decimal to stderr.
 */
PIC_TEXT
static inline void _pic_log_putd(long val)
{
	char buf[21]; /* enough for -2^63 */
	int pos = sizeof(buf);
	int neg = 0;
	unsigned long uval;

	if (val < 0) {
		neg = 1;
		uval = (unsigned long)(-(val + 1)) + 1;
	} else {
		uval = (unsigned long)val;
	}

	if (uval == 0) {
		buf[--pos] = '0';
	} else {
		while (uval) {
			buf[--pos] = '0' + (char)(uval % 10);
			uval /= 10;
		}
	}

	if (neg) {
		buf[--pos] = '-';
	}

	pic_write(2, buf + pos, (pic_size_t)(sizeof(buf) - pos));
}

/*
 * Internal: write an unsigned long as hex to stderr.
 */
PIC_TEXT
static inline void _pic_log_putx(unsigned long val)
{
	char buf[17]; /* enough for 2^64 - 1 */
	int pos = sizeof(buf);
	const char hex[] = "0123456789abcdef";

	if (val == 0) {
		buf[--pos] = '0';
	} else {
		while (val) {
			buf[--pos] = hex[val & 0xf];
			val >>= 4;
		}
	}

	pic_write(2, buf + pos, (pic_size_t)(sizeof(buf) - pos));
}

/*
 * Internal: minimal printf-style formatter. Supports %d, %x, %s, %%.
 *
 * Uses a variadic macro + __builtin_va_* which GCC supports in
 * freestanding mode.
 */
PIC_TEXT
static inline void _pic_log_fmt(const char *fmt, ...)
{
	__builtin_va_list ap;
	__builtin_va_start(ap, fmt);

	const char *p = fmt;
	const char *span = p;

	while (*p) {
		if (*p != '%') {
			p++;
			continue;
		}

		/* Flush text before '%' */
		if (p > span) {
			pic_write(2, span, (pic_size_t)(p - span));
		}

		p++; /* skip '%' */
		switch (*p) {
		case 'd':
			_pic_log_putd((long)__builtin_va_arg(ap, long));
			break;
		case 'x':
			_pic_log_putx((unsigned long)__builtin_va_arg(
				ap, unsigned long));
			break;
		case 's':
			_pic_log_puts(__builtin_va_arg(ap, const char *));
			break;
		case '%':
			_pic_log_putc('%');
			break;
		case '\0':
			/* Trailing '%' at end of format string. */
			_pic_log_putc('%');
			__builtin_va_end(ap);
			return;
		default:
			/* Unknown specifier — print literally. */
			_pic_log_putc('%');
			_pic_log_putc(*p);
			break;
		}
		p++;
		span = p;
	}

	/* Flush remaining text. */
	if (p > span) {
		pic_write(2, span, (pic_size_t)(p - span));
	}

	__builtin_va_end(ap);
}

#define PIC_LOG(fmt, ...) _pic_log_fmt(fmt, ##__VA_ARGS__)

#else /* !PIC_LOG_ENABLE */

#define PIC_LOG(fmt, ...) ((void)0)

#endif /* PIC_LOG_ENABLE */

#endif /* PICBLOBS_LOG_H */
