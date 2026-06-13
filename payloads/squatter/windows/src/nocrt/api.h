#ifndef SQ_NOCRT_API_H
#define SQ_NOCRT_API_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifndef WINAPI
#define WINAPI __attribute__((stdcall))
#endif
#ifndef CALLBACK
#define CALLBACK WINAPI
#endif
#ifndef CDECL
#define CDECL __attribute__((cdecl))
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef WORD ATOM;
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned int UINT;
typedef uintptr_t UINT_PTR;
typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *HLOCAL;
typedef void *HGLOBAL;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HMENU;
typedef unsigned int SOCKET;
typedef unsigned int WPARAM;
typedef LONG_PTR LPARAM;
typedef LONG_PTR LRESULT;
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef char CHAR;
typedef CHAR *LPSTR;
typedef const CHAR *LPCSTR;
typedef BYTE *LPBYTE;
typedef DWORD *LPDWORD;
typedef LONG *LPLONG;
typedef ULONG_PTR SIZE_T;
typedef LONG_PTR SSIZE_T;

typedef struct _FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
} FILETIME;

typedef struct _SYSTEMTIME {
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
} SYSTEMTIME;

typedef struct _LARGE_INTEGER {
	union {
		struct {
			DWORD LowPart;
			LONG HighPart;
		};
		long long QuadPart;
	};
} LARGE_INTEGER;

typedef struct _SECURITY_ATTRIBUTES SECURITY_ATTRIBUTES;
typedef SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;
typedef struct _CRITICAL_SECTION CRITICAL_SECTION;
typedef CRITICAL_SECTION *LPCRITICAL_SECTION;
typedef struct _CONSOLE_SCREEN_BUFFER_INFO CONSOLE_SCREEN_BUFFER_INFO;
typedef struct _OVERLAPPED OVERLAPPED;
typedef OVERLAPPED *LPOVERLAPPED;
typedef struct _STARTUPINFOW STARTUPINFOW;
typedef struct _PROCESS_INFORMATION PROCESS_INFORMATION;
typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;
typedef long (WINAPI *PTOP_LEVEL_EXCEPTION_FILTER)(EXCEPTION_POINTERS *);
typedef BOOL (WINAPI *PHANDLER_ROUTINE)(DWORD);
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

struct sockaddr {
	unsigned short sa_family;
	char sa_data[14];
};

struct in_addr {
	union {
		struct {
			BYTE s_b1;
			BYTE s_b2;
			BYTE s_b3;
			BYTE s_b4;
		} S_un_b;
		DWORD S_addr;
	} S_un;
};

struct sockaddr_in {
	short sin_family;
	unsigned short sin_port;
	struct in_addr sin_addr;
	char sin_zero[8];
};

struct addrinfoW {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	SIZE_T ai_addrlen;
	WCHAR *ai_canonname;
	struct sockaddr *ai_addr;
	struct addrinfoW *ai_next;
};

typedef struct sockaddr SOCKADDR;
typedef struct sockaddr *PSOCKADDR;
typedef struct sockaddr *LPSOCKADDR;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct addrinfoW ADDRINFOW;
typedef ADDRINFOW *PADDRINFOW;
typedef struct WSADATA WSADATA;
typedef struct WSABUF WSABUF;
typedef struct WSAOVERLAPPED WSAOVERLAPPED;
typedef WSAOVERLAPPED *LPWSAOVERLAPPED;
typedef void *LPWSAOVERLAPPED_COMPLETION_ROUTINE;
typedef struct GUID GUID;
typedef struct _WSAPROTOCOL_INFOW WSAPROTOCOL_INFOW;

typedef struct _MSG MSG;
typedef struct _RECT RECT;
typedef struct _WNDCLASSEXW WNDCLASSEXW;
typedef LRESULT (CALLBACK *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

enum {
	SQ_AF_INET = 2,
	SQ_SOCK_STREAM = 1,
	SQ_IPPROTO_TCP = 6,
	SQ_EAI_NONAME = 11001,
};

void *sq_resolve_api(const char *dll_name, const char *api_name);
void *sq_try_resolve_api(const char *dll_name, const char *api_name);
void sq_nocrt_entry(void) __attribute__((noreturn));

#endif
