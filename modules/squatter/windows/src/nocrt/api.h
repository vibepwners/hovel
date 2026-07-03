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
typedef unsigned long ULONG;
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
typedef void *SERVICE_STATUS_HANDLE;
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
typedef DWORD *PDWORD;
typedef LONG *LPLONG;
typedef ULONG *PULONG;
typedef ULONG_PTR SIZE_T;
typedef LONG_PTR SSIZE_T;
typedef DWORD LSTATUS;
typedef DWORD REGSAM;
typedef DWORD NET_API_STATUS;
typedef DWORD SECURITY_INFORMATION;
typedef unsigned int ALG_ID;

typedef struct _FILETIME
{
        DWORD dwLowDateTime;
        DWORD dwHighDateTime;
} FILETIME;
typedef FILETIME *PFILETIME;

typedef struct _SYSTEMTIME
{
        WORD wYear;
        WORD wMonth;
        WORD wDayOfWeek;
        WORD wDay;
        WORD wHour;
        WORD wMinute;
        WORD wSecond;
        WORD wMilliseconds;
} SYSTEMTIME;

typedef struct _LARGE_INTEGER
{
        union {
                struct
                {
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
typedef struct _SYSTEM_INFO SYSTEM_INFO;
typedef SYSTEM_INFO *LPSYSTEM_INFO;
typedef struct _OSVERSIONINFOW OSVERSIONINFOW;
typedef OSVERSIONINFOW *LPOSVERSIONINFOW;
typedef struct tagPROCESSENTRY32W PROCESSENTRY32W;
typedef PROCESSENTRY32W *LPPROCESSENTRY32W;
typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;
typedef int COMPUTER_NAME_FORMAT;
typedef int GET_FILEEX_INFO_LEVELS;
typedef HANDLE *PHANDLE;
typedef HANDLE HKEY;
typedef HKEY *PHKEY;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTHASH;
typedef HANDLE HCRYPTKEY;
typedef struct _IP_ADAPTER_INFO IP_ADAPTER_INFO;
typedef IP_ADAPTER_INFO *PIP_ADAPTER_INFO;
typedef void *PSECURITY_DESCRIPTOR;
typedef void *PSID;
typedef void *PACL;
typedef enum _SE_OBJECT_TYPE
{
        SQ_SE_UNKNOWN_OBJECT_TYPE = 0,
        SQ_SE_FILE_OBJECT = 1,
} SE_OBJECT_TYPE;
typedef enum _TOKEN_INFORMATION_CLASS
{
        SQ_TokenPrivileges = 3,
} TOKEN_INFORMATION_CLASS;
typedef enum _TOKEN_TYPE
{
        SQ_TokenPrimary = 1,
        SQ_TokenImpersonation = 2,
} TOKEN_TYPE;
typedef enum _SECURITY_IMPERSONATION_LEVEL
{
        SQ_SecurityAnonymous = 0,
        SQ_SecurityIdentification = 1,
        SQ_SecurityImpersonation = 2,
        SQ_SecurityDelegation = 3,
} SECURITY_IMPERSONATION_LEVEL;
typedef struct _LUID
{
        DWORD LowPart;
        LONG HighPart;
} LUID;
typedef LUID *PLUID;
typedef struct _LUID_AND_ATTRIBUTES
{
        LUID Luid;
        DWORD Attributes;
} LUID_AND_ATTRIBUTES;
typedef struct _TOKEN_PRIVILEGES
{
        DWORD PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES;
typedef TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;
typedef long(WINAPI *PTOP_LEVEL_EXCEPTION_FILTER)(EXCEPTION_POINTERS *);
typedef BOOL(WINAPI *PHANDLER_ROUTINE)(DWORD);
typedef DWORD(WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);
typedef DWORD(WINAPI *LPHANDLER_FUNCTION_EX)(DWORD, DWORD, LPVOID, LPVOID);

typedef struct _SERVICE_STATUS
{
        DWORD dwServiceType;
        DWORD dwCurrentState;
        DWORD dwControlsAccepted;
        DWORD dwWin32ExitCode;
        DWORD dwServiceSpecificExitCode;
        DWORD dwCheckPoint;
        DWORD dwWaitHint;
} SERVICE_STATUS;
typedef SERVICE_STATUS *LPSERVICE_STATUS;
typedef void(WINAPI *LPSERVICE_MAIN_FUNCTIONW)(DWORD, LPWSTR *);
typedef struct _SERVICE_TABLE_ENTRYW
{
        LPWSTR lpServiceName;
        LPSERVICE_MAIN_FUNCTIONW lpServiceProc;
} SERVICE_TABLE_ENTRYW;
typedef SERVICE_TABLE_ENTRYW *LPSERVICE_TABLE_ENTRYW;

struct sockaddr
{
        unsigned short sa_family;
        char sa_data[14];
};

struct in_addr
{
        union {
                struct
                {
                        BYTE s_b1;
                        BYTE s_b2;
                        BYTE s_b3;
                        BYTE s_b4;
                } S_un_b;
                DWORD S_addr;
        } S_un;
};

struct sockaddr_in
{
        short sin_family;
        unsigned short sin_port;
        struct in_addr sin_addr;
        char sin_zero[8];
};

struct addrinfoW
{
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
typedef LRESULT(CALLBACK *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

enum
{
        SQ_AF_INET = 2,
        SQ_SOCK_STREAM = 1,
        SQ_IPPROTO_TCP = 6,
        SQ_EAI_NONAME = 11001,
        SQ_NO_ERROR = 0,
        SQ_ERROR_SERVICE_SPECIFIC_ERROR = 1066,
        SQ_SERVICE_WIN32_OWN_PROCESS = 0x00000010,
        SQ_SERVICE_STOPPED = 0x00000001,
        SQ_SERVICE_START_PENDING = 0x00000002,
        SQ_SERVICE_STOP_PENDING = 0x00000003,
        SQ_SERVICE_RUNNING = 0x00000004,
        SQ_SERVICE_ACCEPT_STOP = 0x00000001,
        SQ_SERVICE_ACCEPT_SHUTDOWN = 0x00000004,
        SQ_SERVICE_CONTROL_STOP = 0x00000001,
        SQ_SERVICE_CONTROL_SHUTDOWN = 0x00000005,
};

void *sq_resolve_api(const char *dll_name, const char *api_name);
void *sq_try_resolve_api(const char *dll_name, const char *api_name);
void sq_nocrt_entry(void) __attribute__((noreturn));

#endif
