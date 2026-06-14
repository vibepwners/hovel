#include "nocrt/api.h"

int wmain(int argc, wchar_t **argv);
void WINAPI ExitProcess(UINT exit_code);
#ifdef _WIN64
void _sq_nocrt_entry(void) __attribute__((noreturn));
#endif

typedef struct _UNICODE_STRING_X {
	WORD Length;
	WORD MaximumLength;
	WCHAR *Buffer;
} UNICODE_STRING_X;

typedef struct _RTL_USER_PROCESS_PARAMETERS_X {
#ifdef _WIN64
	BYTE Reserved1[0x60];
#else
	BYTE Reserved1[0x38];
#endif
	UNICODE_STRING_X ImagePathName;
	UNICODE_STRING_X CommandLine;
} RTL_USER_PROCESS_PARAMETERS_X;

typedef struct _PEB_X {
#ifdef _WIN64
	BYTE Reserved1[0x20];
#else
	BYTE Reserved1[0x10];
#endif
	RTL_USER_PROCESS_PARAMETERS_X *ProcessParameters;
} PEB_X;

static PEB_X *peb(void)
{
	PEB_X *p = NULL;
#ifdef _WIN64
	__asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
#else
	__asm__ volatile("movl %%fs:0x30, %0" : "=r"(p));
#endif
	return p;
}

static int is_space(wchar_t c)
{
	return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
}

static wchar_t *skip_spaces(wchar_t *p)
{
	while (is_space(*p)) {
		p++;
	}
	return p;
}

static wchar_t *parse_quoted_arg(wchar_t *p, wchar_t **out)
{
	p++;
	*out = p;
	while (*p != L'\0' && *p != L'"') {
		p++;
	}
	if (*p == L'"') {
		*p++ = L'\0';
	}
	return p;
}

static wchar_t *parse_bare_arg(wchar_t *p, wchar_t **out)
{
	*out = p;
	while (*p != L'\0' && !is_space(*p)) {
		p++;
	}
	if (*p != L'\0') {
		*p++ = L'\0';
	}
	return p;
}

static int parse_args(wchar_t *cmd, wchar_t **argv, int cap)
{
	int argc = 0;
	wchar_t *p = cmd;

	while (*p != L'\0' && argc < cap) {
		p = skip_spaces(p);
		if (*p == L'\0') {
			break;
		}
		if (*p == L'"') {
			p = parse_quoted_arg(p, &argv[argc++]);
		} else {
			p = parse_bare_arg(p, &argv[argc++]);
		}
	}
	return argc;
}

void sq_nocrt_entry(void)
{
	static wchar_t command_line[1024];
	static wchar_t *argv[32];
	PEB_X *p = peb();
	int argc = 0;
	int code = 1;

	if (p != NULL && p->ProcessParameters != NULL &&
	    p->ProcessParameters->CommandLine.Buffer != NULL) {
		unsigned int chars = p->ProcessParameters->CommandLine.Length / sizeof(wchar_t);
		unsigned int i = 0;
		if (chars >= (sizeof command_line / sizeof command_line[0])) {
			chars = (sizeof command_line / sizeof command_line[0]) - 1;
		}
		for (i = 0; i < chars; i++) {
			command_line[i] = p->ProcessParameters->CommandLine.Buffer[i];
		}
		command_line[chars] = L'\0';
	}
	argc = parse_args(command_line, argv, (int)(sizeof argv / sizeof argv[0]));
	code = wmain(argc, argv);
	ExitProcess((UINT)code);
	for (;;) {
	}
}

#ifdef _WIN64
void _sq_nocrt_entry(void)
{
	sq_nocrt_entry();
}
#endif
