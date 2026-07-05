/* Target OS: Windows. Include before any picblobs headers. */
#ifndef PICBLOBS_OS_WINDOWS_H
#define PICBLOBS_OS_WINDOWS_H
#define PICBLOBS_OS_WINDOWS 1
#define PICBLOBS_OS_NAME "windows"

/*
 * PIC_WINAPI — calling convention for Windows API function pointers.
 *
 * On x86_64, Windows uses the Microsoft x64 ABI (rcx, rdx, r8, r9)
 * while our GCC/Linux toolchain defaults to System V (rdi, rsi, rdx, rcx).
 * This attribute ensures the correct convention when calling resolved APIs.
 *
 * On i686, both ABIs pass args on the stack (cdecl), so it's a no-op.
 * On aarch64, the AAPCS calling convention is the same, so it's a no-op.
 */
#if defined(__x86_64__)
#define PIC_WINAPI __attribute__((ms_abi))
#else
#define PIC_WINAPI
#endif

#endif
