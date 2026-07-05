# ADR-025: Windows Calling Convention via ms_abi Attribute

## Status
Accepted

## Context

All blobs are compiled with GCC Linux cross-compilers (ADR-001). On x86_64, GCC defaults to the System V AMD64 ABI (arguments in rdi, rsi, rdx, rcx, r8, r9), but real Windows APIs use the Microsoft x64 ABI (arguments in rcx, rdx, r8, r9, then stack). The ABIs also differ in which registers are non-volatile: SysV preserves rbx, rbp, r12-r15, while MS ABI additionally preserves rdi, rsi, and xmm6-xmm15.

On i686, both ABIs pass arguments on the stack (cdecl), so no translation is needed. On aarch64, the AAPCS calling convention is the same on both Windows and Linux.

When Windows blobs are tested under Wine, the ABI mismatch on x86_64 causes crashes because the blob passes arguments in SysV registers but Wine's real kernel32.dll expects MS ABI registers.

## Decision

Windows API function pointer types in blob source code SHALL use the `PIC_WINAPI` attribute, defined in `picblobs/os/windows.h`:

```c
#if defined(__x86_64__)
#define PIC_WINAPI __attribute__((ms_abi))
#else
#define PIC_WINAPI
#endif
```

Usage in blob source:
```c
typedef void *(PIC_WINAPI *fn_VirtualAlloc)(void *lpAddress, ...);
```

This ensures the compiler generates the correct calling convention for calls through resolved function pointers, without affecting the blob's internal code (which remains SysV ABI).

### Mock Runner Thunks

The mock Linux test runner (`tests/runners/windows/runner.c`) provides mock implementations of Windows APIs using SysV ABI (they call Linux syscalls internally). On x86_64, the PE export trampolines include an ABI translation thunk that converts MS ABI arguments to SysV before calling the mock:

```
Blob (ms_abi call) → Trampoline thunk (ms→sysv) → Mock function (sysv)
```

The thunk:
1. Saves rdi and rsi (non-volatile in MS ABI, volatile in SysV)
2. Remaps arguments: rcx→rdi, rdx→rsi, r8→rdx, r9→rcx, [rsp+0x38]→r8
3. Calls the SysV mock function
4. Restores rdi and rsi
5. Returns to the blob

On i686 and aarch64, trampolines remain simple `jmp` instructions (no ABI translation needed).

## Consequences

- Windows blobs produce correct code for both Wine validation and real Windows execution on x86_64.
- The mock runner faithfully tests the same blob binary that would run on real Windows.
- Wine validation (`tools/validate_wine.py`) can verify x86_64 blobs against real Windows API implementations.
- i686 blobs remain unaffected (PIC_WINAPI is a no-op).
- Any new Windows API function pointer typedef MUST include PIC_WINAPI.

## Alternatives Considered

- **Make mock functions ms_abi**: Annotate mock functions with `__attribute__((ms_abi))` instead of using thunks. Rejected: the mocks call SysV functions (Linux syscalls) internally, and GCC's ms_abi function prologue saves/restores XMM registers, adding ~160 bytes of stack usage per mock function. The thunk approach is smaller and keeps mocks simple.
- **Separate blob builds for mock vs Wine**: Build one set with SysV for testing and another with ms_abi for Wine/production. Rejected: defeats the purpose of testing the same binary.
- **MinGW toolchain for Windows targets**: Would natively produce ms_abi code. Rejected per ADR-001: maintaining separate toolchains per OS adds complexity with no benefit for freestanding blobs.

## Related
- ADR-001 (GCC Linux toolchains for all targets)
- MOD-005 (Windows API resolution architecture)
- ADR-005 (DJB2 hash for Windows resolution)
