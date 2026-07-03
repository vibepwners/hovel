#include "nocrt/api.h"

#define API0(ret, dll, name)                                                                                           \
        typedef ret(WINAPI *name##_fn)(void);                                                                          \
        ret WINAPI name(void);                                                                                         \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(void)                                                                                          \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr();                                                                                   \
        }

#define API0V(dll, name)                                                                                               \
        typedef void(WINAPI * name##_fn)(void);                                                                        \
        void WINAPI name(void);                                                                                        \
        static name##_fn name##_ptr;                                                                                   \
        void WINAPI name(void)                                                                                         \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                name##_ptr();                                                                                          \
        }

#define API1(ret, dll, name, t1)                                                                                       \
        typedef ret(WINAPI *name##_fn)(t1);                                                                            \
        ret WINAPI name(t1);                                                                                           \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1)                                                                                         \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1);                                                                                 \
        }

#define API1V(dll, name, t1)                                                                                           \
        typedef void(WINAPI * name##_fn)(t1);                                                                          \
        void WINAPI name(t1);                                                                                          \
        static name##_fn name##_ptr;                                                                                   \
        void WINAPI name(t1 a1)                                                                                        \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                name##_ptr(a1);                                                                                        \
        }

#define API2(ret, dll, name, t1, t2)                                                                                   \
        typedef ret(WINAPI *name##_fn)(t1, t2);                                                                        \
        ret WINAPI name(t1, t2);                                                                                       \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2)                                                                                  \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2);                                                                             \
        }

#define API3(ret, dll, name, t1, t2, t3)                                                                               \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3);                                                                    \
        ret WINAPI name(t1, t2, t3);                                                                                   \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3)                                                                           \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3);                                                                         \
        }

#define API4(ret, dll, name, t1, t2, t3, t4)                                                                           \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4);                                                                \
        ret WINAPI name(t1, t2, t3, t4);                                                                               \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4)                                                                    \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4);                                                                     \
        }

#define API5(ret, dll, name, t1, t2, t3, t4, t5)                                                                       \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5);                                                            \
        ret WINAPI name(t1, t2, t3, t4, t5);                                                                           \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5)                                                             \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5);                                                                 \
        }

#define API6(ret, dll, name, t1, t2, t3, t4, t5, t6)                                                                   \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6);                                                        \
        ret WINAPI name(t1, t2, t3, t4, t5, t6);                                                                       \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6)                                                      \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6);                                                             \
        }

#define API7(ret, dll, name, t1, t2, t3, t4, t5, t6, t7)                                                               \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6, t7);                                                    \
        ret WINAPI name(t1, t2, t3, t4, t5, t6, t7);                                                                   \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7)                                               \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6, a7);                                                         \
        }

#define API8(ret, dll, name, t1, t2, t3, t4, t5, t6, t7, t8)                                                           \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6, t7, t8);                                                \
        ret WINAPI name(t1, t2, t3, t4, t5, t6, t7, t8);                                                               \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8)                                        \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6, a7, a8);                                                     \
        }

#define API9(ret, dll, name, t1, t2, t3, t4, t5, t6, t7, t8, t9)                                                       \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6, t7, t8, t9);                                            \
        ret WINAPI name(t1, t2, t3, t4, t5, t6, t7, t8, t9);                                                           \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8, t9 a9)                                 \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6, a7, a8, a9);                                                 \
        }

#define API10(ret, dll, name, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10)                                                 \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10);                                       \
        ret WINAPI name(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10);                                                      \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8, t9 a9, t10 a10)                        \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);                                            \
        }

#define API11(ret, dll, name, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11)                                            \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11);                                  \
        ret WINAPI name(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11);                                                 \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8, t9 a9, t10 a10, t11 a11)               \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);                                       \
        }

#define API12(ret, dll, name, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12)                                       \
        typedef ret(WINAPI *name##_fn)(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12);                             \
        ret WINAPI name(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12);                                            \
        static name##_fn name##_ptr;                                                                                   \
        ret WINAPI name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8, t9 a9, t10 a10, t11 a11, t12 a12)      \
        {                                                                                                              \
                if (name##_ptr == NULL)                                                                                \
                {                                                                                                      \
                        union {                                                                                        \
                                void *addr;                                                                            \
                                name##_fn fn;                                                                          \
                        } resolved;                                                                                    \
                        resolved.addr = sq_resolve_api(dll, #name);                                                    \
                        name##_ptr = resolved.fn;                                                                      \
                }                                                                                                      \
                return name##_ptr(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);                                  \
        }

API1(BOOL, "kernel32.dll", CloseHandle, HANDLE)
API2(BOOL, "kernel32.dll", ConnectNamedPipe, HANDLE, LPOVERLAPPED)
API4(HANDLE, "kernel32.dll", CreateEventW, LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR)
API7(HANDLE, "kernel32.dll", CreateFileW, LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
API8(HANDLE, "kernel32.dll", CreateNamedPipeW, LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES)
API4(BOOL, "kernel32.dll", CreatePipe, HANDLE *, HANDLE *, LPSECURITY_ATTRIBUTES, DWORD)
API10(BOOL, "kernel32.dll", CreateProcessW, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
      LPVOID, LPCWSTR, STARTUPINFOW *, PROCESS_INFORMATION *)
API11(BOOL, "advapi32.dll", CreateProcessAsUserW, HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
      BOOL, DWORD, LPVOID, LPCWSTR, STARTUPINFOW *, PROCESS_INFORMATION *)
API4(HANDLE, "kernel32.dll", CreateSemaphoreW, LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR)
API6(HANDLE, "kernel32.dll", CreateThread, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD,
     LPDWORD)
API2(HANDLE, "kernel32.dll", CreateToolhelp32Snapshot, DWORD, DWORD)
API1(BOOL, "kernel32.dll", CancelIo, HANDLE)
API1(BOOL, "kernel32.dll", DeleteFileW, LPCWSTR)
API2(BOOL, "kernel32.dll", TerminateProcess, HANDLE, UINT)
API0V("kernel32.dll", DebugBreak)
API1V("kernel32.dll", DeleteCriticalSection, LPCRITICAL_SECTION)
API1V("kernel32.dll", EnterCriticalSection, LPCRITICAL_SECTION)
API1V("kernel32.dll", ExitProcess, UINT)
API1(BOOL, "kernel32.dll", FlushFileBuffers, HANDLE)
API7(DWORD, "kernel32.dll", FormatMessageW, DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list *)
API2(BOOL, "kernel32.dll", GetComputerNameW, LPWSTR, LPDWORD)
API3(BOOL, "kernel32.dll", GetComputerNameExW, COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD)
API2(BOOL, "kernel32.dll", GetConsoleMode, HANDLE, LPDWORD)
API2(BOOL, "kernel32.dll", GetConsoleScreenBufferInfo, HANDLE, CONSOLE_SCREEN_BUFFER_INFO *)
API0(HANDLE, "kernel32.dll", GetCurrentProcess)
API0(DWORD, "kernel32.dll", GetCurrentProcessId)
API0(DWORD, "kernel32.dll", GetCurrentThreadId)
API3(DWORD, "kernel32.dll", GetEnvironmentVariableW, LPCWSTR, LPWSTR, DWORD)
API3(BOOL, "kernel32.dll", GetFileAttributesExW, LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID)
API2(BOOL, "kernel32.dll", GetFileSizeEx, HANDLE, LARGE_INTEGER *)
API0(DWORD, "kernel32.dll", GetLastError)
API2(DWORD, "kernel32.dll", GetLogicalDriveStringsW, DWORD, LPWSTR)
API1V("kernel32.dll", GetLocalTime, SYSTEMTIME *)
API3(DWORD, "kernel32.dll", GetModuleFileNameW, HMODULE, LPWSTR, DWORD)
API1V("kernel32.dll", GetNativeSystemInfo, LPSYSTEM_INFO)
API4(BOOL, "kernel32.dll", GetOverlappedResult, HANDLE, LPOVERLAPPED, LPDWORD, BOOL)
API2(BOOL, "kernel32.dll", GetExitCodeProcess, HANDLE, LPDWORD)
API0(HANDLE, "kernel32.dll", GetProcessHeap)
API1(HANDLE, "kernel32.dll", GetStdHandle, DWORD)
API0(DWORD, "kernel32.dll", GetTickCount)
API0(DWORD, "kernel32.dll", WTSGetActiveConsoleSessionId)
API1(UINT, "kernel32.dll", GetDriveTypeW, LPCWSTR)
API1(BOOL, "kernel32.dll", GetVersionExW, LPOSVERSIONINFOW)
API3(LPVOID, "kernel32.dll", HeapAlloc, HANDLE, DWORD, SIZE_T)
API3(BOOL, "kernel32.dll", HeapFree, HANDLE, DWORD, LPVOID)
API1V("kernel32.dll", InitializeCriticalSection, LPCRITICAL_SECTION)
API0(BOOL, "kernel32.dll", IsDebuggerPresent)
API1V("kernel32.dll", LeaveCriticalSection, LPCRITICAL_SECTION)
API1(int, "kernel32.dll", lstrlenW, LPCWSTR)
// cppcheck-suppress CastIntegerToAddressAtReturn
API3(LPWSTR, "kernel32.dll", lstrcpynW, LPWSTR, LPCWSTR, int)
API1(HMODULE, "kernel32.dll", GetModuleHandleW, LPCWSTR)
API1(HLOCAL, "kernel32.dll", LocalFree, HLOCAL)
API6(int, "kernel32.dll", MultiByteToWideChar, UINT, DWORD, LPCSTR, int, LPWSTR, int)
API3(HANDLE, "kernel32.dll", OpenProcess, DWORD, BOOL, DWORD)
API1V("kernel32.dll", OutputDebugStringW, LPCWSTR)
API2(BOOL, "kernel32.dll", Process32FirstW, HANDLE, LPPROCESSENTRY32W)
API2(BOOL, "kernel32.dll", Process32NextW, HANDLE, LPPROCESSENTRY32W)
API2(BOOL, "kernel32.dll", ProcessIdToSessionId, DWORD, DWORD *)
API7(BOOL, "kernel32.dll", DuplicateHandle, HANDLE, HANDLE, HANDLE, HANDLE *, DWORD, BOOL, DWORD)
API1(BOOL, "kernel32.dll", ResetEvent, HANDLE)
API3(BOOL, "kernel32.dll", ReleaseSemaphore, HANDLE, LONG, LPLONG)
API1(BOOL, "kernel32.dll", SetEvent, HANDLE)
API5(BOOL, "kernel32.dll", ReadFile, HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
API2(BOOL, "kernel32.dll", SetConsoleCtrlHandler, PHANDLER_ROUTINE, BOOL)
API2(BOOL, "kernel32.dll", SetConsoleTextAttribute, HANDLE, WORD)
API3(BOOL, "kernel32.dll", SetHandleInformation, HANDLE, DWORD, DWORD)
API4(BOOL, "kernel32.dll", SetNamedPipeHandleState, HANDLE, LPDWORD, LPDWORD, LPDWORD)
API1V("kernel32.dll", Sleep, DWORD)
API2(LONG, "kernel32.dll", InterlockedExchange, LPLONG, LONG)
API3(LONG, "kernel32.dll", InterlockedCompareExchange, LPLONG, LONG, LONG)
API1(LONG, "kernel32.dll", InterlockedIncrement, LPLONG)
API4(DWORD, "kernel32.dll", WaitForMultipleObjects, DWORD, const HANDLE *, BOOL, DWORD)
API2(DWORD, "kernel32.dll", WaitForSingleObject, HANDLE, DWORD)
API8(int, "kernel32.dll", WideCharToMultiByte, UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, BOOL *)
API5(BOOL, "kernel32.dll", WriteConsoleW, HANDLE, const void *, DWORD, LPDWORD, LPVOID)
API5(BOOL, "kernel32.dll", WriteFile, HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)

API3(SERVICE_STATUS_HANDLE, "advapi32.dll", RegisterServiceCtrlHandlerExW, LPCWSTR, LPHANDLER_FUNCTION_EX, LPVOID)
API2(BOOL, "advapi32.dll", SetServiceStatus, SERVICE_STATUS_HANDLE, LPSERVICE_STATUS)
API1(BOOL, "advapi32.dll", StartServiceCtrlDispatcherW, const SERVICE_TABLE_ENTRYW *)
API6(BOOL, "advapi32.dll", AdjustTokenPrivileges, HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)
API1(BOOL, "advapi32.dll", CloseEventLog, HANDLE)
API5(BOOL, "advapi32.dll", ConvertSecurityDescriptorToStringSecurityDescriptorW, PSECURITY_DESCRIPTOR, DWORD,
     SECURITY_INFORMATION, LPWSTR *, PULONG)
API5(BOOL, "advapi32.dll", CryptAcquireContextW, HCRYPTPROV *, LPCWSTR, LPCWSTR, DWORD, DWORD)
API5(BOOL, "advapi32.dll", CryptCreateHash, HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *)
API1(BOOL, "advapi32.dll", CryptDestroyHash, HCRYPTHASH)
API5(BOOL, "advapi32.dll", CryptGetHashParam, HCRYPTHASH, DWORD, BYTE *, DWORD *, DWORD)
API4(BOOL, "advapi32.dll", CryptHashData, HCRYPTHASH, const BYTE *, DWORD, DWORD)
API2(BOOL, "advapi32.dll", CryptReleaseContext, HCRYPTPROV, DWORD)
API8(DWORD, "advapi32.dll", GetNamedSecurityInfoW, LPWSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID *, PSID *, PACL *,
     PACL *, PSECURITY_DESCRIPTOR *)
API5(BOOL, "advapi32.dll", GetTokenInformation, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
API2(BOOL, "advapi32.dll", GetUserNameW, LPWSTR, LPDWORD)
API4(BOOL, "advapi32.dll", LookupPrivilegeNameW, LPCWSTR, PLUID, LPWSTR, LPDWORD)
API3(BOOL, "advapi32.dll", LookupPrivilegeValueW, LPCWSTR, LPCWSTR, PLUID)
API2(HANDLE, "advapi32.dll", OpenEventLogW, LPCWSTR, LPCWSTR)
API3(BOOL, "advapi32.dll", OpenProcessToken, HANDLE, DWORD, PHANDLE)
API6(BOOL, "advapi32.dll", DuplicateTokenEx, HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
     TOKEN_TYPE, PHANDLE)
API7(BOOL, "advapi32.dll", ReadEventLogW, HANDLE, DWORD, DWORD, LPVOID, DWORD, DWORD *, DWORD *)
API1(LSTATUS, "advapi32.dll", RegCloseKey, HKEY)
API8(LSTATUS, "advapi32.dll", RegEnumKeyExW, HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME)
API5(LSTATUS, "advapi32.dll", RegOpenKeyExW, HKEY, LPCWSTR, DWORD, REGSAM, PHKEY)
API6(LSTATUS, "advapi32.dll", RegQueryValueExW, HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)

API2(DWORD, "iphlpapi.dll", GetAdaptersInfo, PIP_ADAPTER_INFO, PULONG)

API1(NET_API_STATUS, "netapi32.dll", NetApiBufferFree, LPVOID)
API7(NET_API_STATUS, "netapi32.dll", NetShareEnum, LPWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD)

API3(BOOL, "userenv.dll", CreateEnvironmentBlock, LPVOID *, HANDLE, BOOL)
API1(BOOL, "userenv.dll", DestroyEnvironmentBlock, LPVOID)

API4(LRESULT, "user32.dll", DefWindowProcW, HWND, UINT, WPARAM, LPARAM)
API1(LRESULT, "user32.dll", DispatchMessageW, const MSG *)
API2(BOOL, "user32.dll", GetClientRect, HWND, RECT *)
API4(BOOL, "user32.dll", GetMessageW, MSG *, HWND, UINT, UINT)
API1(int, "user32.dll", GetWindowTextLengthW, HWND)
API2(HCURSOR, "user32.dll", LoadCursorW, HINSTANCE, LPCWSTR)
API6(BOOL, "user32.dll", MoveWindow, HWND, int, int, int, int, BOOL)
API1V("user32.dll", PostQuitMessage, int)
API4(BOOL, "user32.dll", PostMessageW, HWND, UINT, WPARAM, LPARAM)
API1(ATOM, "user32.dll", RegisterClassExW, const WNDCLASSEXW *)
API4(LRESULT, "user32.dll", SendMessageW, HWND, UINT, WPARAM, LPARAM)
API2(BOOL, "user32.dll", SetWindowTextW, HWND, LPCWSTR)
API1(BOOL, "user32.dll", DestroyWindow, HWND)
API1(BOOL, "user32.dll", TranslateMessage, const MSG *)
API12(HWND, "user32.dll", CreateWindowExW, DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE,
      LPVOID)

API4(int, "shlwapi.dll", wvnsprintfW, LPWSTR, int, LPCWSTR, va_list)
int CDECL wnsprintfW(LPWSTR buf, int cap, LPCWSTR fmt, ...);
int CDECL wnsprintfW(LPWSTR buf, int cap, LPCWSTR fmt, ...)
{
        va_list ap;
        int written = 0;

        va_start(ap, fmt);
        written = wvnsprintfW(buf, cap, fmt, ap);
        va_end(ap);
        return written;
}

API0(int, "ws2_32.dll", WSACleanup)
API2(int, "ws2_32.dll", WSAStartup, WORD, WSADATA *)
API0(int, "ws2_32.dll", WSAGetLastError)
typedef void(WINAPI *FreeAddrInfoW_fn)(PADDRINFOW);
typedef int(WINAPI *GetAddrInfoW_fn)(LPCWSTR, LPCWSTR, const ADDRINFOW *, PADDRINFOW *);
static FreeAddrInfoW_fn FreeAddrInfoW_ptr;
static GetAddrInfoW_fn GetAddrInfoW_ptr;
static ADDRINFOW fallback_addrinfo;
static struct sockaddr_in fallback_sockaddr;

void WINAPI FreeAddrInfoW(PADDRINFOW result);
int WINAPI GetAddrInfoW(LPCWSTR node, LPCWSTR service, const ADDRINFOW *hints, PADDRINFOW *result);

static int parse_port(LPCWSTR service, WORD *out)
{
        unsigned long value = 0;

        if (service == NULL || *service == L'\0')
        {
                return 0;
        }
        while (*service != L'\0')
        {
                if (*service < L'0' || *service > L'9')
                {
                        return 0;
                }
                value = value * 10u + (unsigned long)(*service - L'0');
                if (value > 65535u)
                {
                        return 0;
                }
                service++;
        }
        *out = (WORD)value;
        return 1;
}

void WINAPI FreeAddrInfoW(PADDRINFOW result)
{
        if (result == &fallback_addrinfo)
        {
                return;
        }
        if (FreeAddrInfoW_ptr == NULL)
        {
                union {
                        void *addr;
                        FreeAddrInfoW_fn fn;
                } resolved;
                resolved.addr = sq_try_resolve_api("ws2_32.dll", "FreeAddrInfoW");
                FreeAddrInfoW_ptr = resolved.fn;
        }
        if (FreeAddrInfoW_ptr != NULL)
        {
                FreeAddrInfoW_ptr(result);
        }
}

int WINAPI GetAddrInfoW(LPCWSTR node, LPCWSTR service, const ADDRINFOW *hints, PADDRINFOW *result)
{
        WORD port = 0;

        if (GetAddrInfoW_ptr == NULL)
        {
                union {
                        void *addr;
                        GetAddrInfoW_fn fn;
                } resolved;
                resolved.addr = sq_try_resolve_api("ws2_32.dll", "GetAddrInfoW");
                GetAddrInfoW_ptr = resolved.fn;
        }
        if (GetAddrInfoW_ptr != NULL)
        {
                return GetAddrInfoW_ptr(node, service, hints, result);
        }
        if (node != NULL || result == NULL || !parse_port(service, &port))
        {
                return SQ_EAI_NONAME;
        }
        fallback_sockaddr.sin_family = SQ_AF_INET;
        fallback_sockaddr.sin_port = (unsigned short)((port << 8) | (port >> 8));
        fallback_sockaddr.sin_addr.S_un.S_addr = 0;
        fallback_addrinfo.ai_flags = hints != NULL ? hints->ai_flags : 0;
        fallback_addrinfo.ai_family = SQ_AF_INET;
        fallback_addrinfo.ai_socktype = hints != NULL ? hints->ai_socktype : SQ_SOCK_STREAM;
        fallback_addrinfo.ai_protocol = hints != NULL ? hints->ai_protocol : SQ_IPPROTO_TCP;
        fallback_addrinfo.ai_addrlen = sizeof fallback_sockaddr;
        fallback_addrinfo.ai_canonname = NULL;
        fallback_addrinfo.ai_addr = (struct sockaddr *)&fallback_sockaddr;
        fallback_addrinfo.ai_next = NULL;
        *result = &fallback_addrinfo;
        return 0;
}

API3(SOCKET, "ws2_32.dll", accept, SOCKET, struct sockaddr *, int *)
API3(int, "ws2_32.dll", bind, SOCKET, const struct sockaddr *, int)
API1(int, "ws2_32.dll", closesocket, SOCKET)
API3(int, "ws2_32.dll", connect, SOCKET, const struct sockaddr *, int)
API1(WORD, "ws2_32.dll", htons, WORD)
API2(int, "ws2_32.dll", listen, SOCKET, int)
API4(int, "ws2_32.dll", recv, SOCKET, char *, int, int)
API4(int, "ws2_32.dll", send, SOCKET, const char *, int, int)
API5(int, "ws2_32.dll", setsockopt, SOCKET, int, int, const char *, int)
API2(int, "ws2_32.dll", shutdown, SOCKET, int)
API3(SOCKET, "ws2_32.dll", socket, int, int, int)
