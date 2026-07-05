# REQ-001: Single Syscall Assembly Primitive Per Architecture

## Status
Accepted

## Statement

For each supported processor architecture, picblobs SHALL provide exactly one assembly-language function that performs a system call with up to the maximum number of arguments supported by that architecture's syscall ABI. On Linux this is six arguments; on FreeBSD the number varies by architecture but SHALL support at least six where the ABI permits. This function SHALL be the sole piece of assembly in the entire codebase for that architecture. All other OS interaction on Linux and FreeBSD SHALL be implemented in pure C by calling this primitive.

## Rationale

Minimizing assembly to a single function per architecture achieves several goals:
- **Auditability**: The only non-C code in the project is a handful of small, well-defined assembly stubs.
- **Portability**: Adding a new architecture requires writing one function, not reimplementing every OS wrapper.
- **Correctness**: A single, heavily-tested primitive reduces the surface area for encoding or ABI mistakes.
- **Maintainability**: Changes to syscall wrappers (adding new syscalls, fixing argument handling) happen in C, not assembly.

## Derives From
- VIS-001

## Acceptance Criteria

1. Each supported architecture has exactly one header file (`src/include/picblobs/syscall/{arch}.h`) containing one `static inline` function implemented via GCC inline assembly.
2. The function signature accepts a syscall number and up to six integer-width arguments.
3. The function returns the raw syscall return value (not errno-transformed).
4. No other file in the codebase for that architecture contains inline assembly, with the sole exception of architecture-specific register access required for Windows PEB/TEB resolution (see REQ-005) and the MIPS trampoline emitted by `section.h` (see ADR-020).
5. The inline assembly function is callable from C with the platform's standard C calling convention for that architecture.

## Syscall ABI Per Architecture

The assembly stub SHALL implement the following ABI for each architecture:

### x86_64 (Linux)
- Syscall instruction: `syscall`
- Syscall number: `rax`
- Arguments: `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`
- Return: `rax`
- Clobbered: `rcx`, `r11`

### x86_64 (FreeBSD)
- Syscall instruction: `syscall`
- Syscall number: `rax`
- Arguments: `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`
- Return: `rax`; carry flag indicates error
- Clobbered: `rcx`, `r11`

### i686 (Linux)
- Syscall instruction: `int 0x80`
- Syscall number: `eax`
- Arguments: `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`
- Return: `eax`

### i686 (FreeBSD)
- Syscall instruction: `int 0x80`
- Syscall number: `eax`
- Arguments passed on stack (FreeBSD i386 convention): arguments are pushed right-to-left onto the stack, with a dummy word at the top
- Return: `eax`; carry flag indicates error

### aarch64 (Linux and FreeBSD)
- Syscall instruction: `svc #0`
- Syscall number: `x8`
- Arguments: `x0` through `x5`
- Return: `x0`

### armv5 — ARM mode (Linux and FreeBSD)
- Syscall instruction: `svc #0` (or `swi #0`)
- Syscall number: `r7`
- Arguments: `r0` through `r5`
- Return: `r0`

### armv5 — Thumb mode (Linux)
- Syscall instruction: `svc #0`
- Syscall number: `r7`
- Arguments: `r0` through `r5`
- Return: `r0`
- Note: Thumb mode entry requires the function to be entered via a Thumb-mode branch (LSB of function pointer set to 1).

### mipsel32 and mipsbe32 (Linux)
- Syscall instruction: `syscall`
- Syscall number: `$v0`
- Arguments: `$a0` through `$a3`; arguments 5 and 6 are passed on the stack at defined offsets per the o32 ABI
- Return: `$v0`; `$a3` indicates error (non-zero = error)

### mipsel32 and mipsbe32 (FreeBSD)
- Syscall instruction: `syscall`
- Syscall number: `$v0`
- Arguments: `$a0` through `$a3`; arguments 5 and 6 on stack per o32 ABI
- Return: `$v0`; `$a3` indicates error

### s390x (Linux)
- Syscall instruction: `svc 0`
- Syscall number: `r1`
- Arguments: `r2`, `r3`, `r4`, `r5`, `r6`, `r7`
- Return: `r2`

### s390x (FreeBSD) — deferred
- FreeBSD does not officially support s390x. This ABI is documented for completeness but is not implemented in v1 (see ADR-023).
- Syscall instruction: `svc 0`
- Syscall number: `r1`
- Arguments: `r2`, `r3`, `r4`, `r5`, `r6`, `r7`
- Return: `r2`; carry flag equivalent indicates error

## Related Decisions
- ADR-006

## Verified By
- TEST-002
