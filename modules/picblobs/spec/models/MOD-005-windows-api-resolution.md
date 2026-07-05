# MOD-005: Windows API Resolution Architecture

## Status
Accepted

## Description

This model describes the architecture of the Windows PEB/TEB walk and DJB2 hash-based function resolution system used by all Windows-targeting blobs.

## Resolution Flow

```
+===========================================================+
| Blob Entry Point                                          |
|                                                           |
|   1. Needs to call VirtualAlloc, WSASocketA, etc.         |
|   2. Calls resolve_function(dll_hash, func_hash)          |
+===========================================================+
                          |
                          v
+===========================================================+
| resolve_function(dll_hash, func_hash)                     |
|                                                           |
|   1. Check cache: if func pointer already resolved,       |
|      return it immediately.                               |
|   2. Otherwise, call find_module(dll_hash) to get         |
|      the DLL base address.                                |
|   3. Call find_export(dll_base, func_hash) to resolve     |
|      the function within the DLL's export table.          |
|   4. Cache the result.                                    |
|   5. Return the function pointer.                         |
+===========================================================+
              |                           |
              v                           v
+===========================+  +============================+
| find_module(dll_hash)     |  | find_export(base, hash)    |
|                           |  |                            |
| 1. Access TEB:            |  | 1. Parse DOS header at     |
|    x86_64: gs:[0x30]      |  |    base address.           |
|    aarch64: arch-specific  |  | 2. Follow e_lfanew to PE   |
| 2. Read PEB pointer from  |  |    signature.              |
|    TEB (offset 0x60 on    |  | 3. Locate export directory |
|    x86_64).               |  |    from data directories.  |
| 3. Read Ldr pointer from  |  | 4. Walk export name table: |
|    PEB.                   |  |    - Read each name string |
| 4. Get InMemoryOrder-     |  |    - Compute DJB2 hash     |
|    ModuleList head.       |  |    - Compare with target   |
| 5. For each entry:        |  |      func_hash             |
|    - Read BaseDllName     |  | 5. On match: look up       |
|      (Unicode)            |  |    ordinal from ordinal    |
|    - Convert to lowercase |  |    table, then address     |
|    - Compute DJB2 hash    |  |    from address table.     |
|    - Compare with target  |  | 6. Check for forwarded     |
|      dll_hash             |  |    export (address within  |
| 6. On match: return       |  |    export dir range):      |
|    DllBase.               |  |    - Parse "DLL.Function"  |
| 7. If not found: return   |  |    - Recursively resolve   |
|    NULL.                  |  | 7. Return function addr.   |
+===========================+  +============================+
```

## TEB Access Detail

### x86_64

```
(conceptual)
TEB is at gs:[0x30]  (self-pointer in TEB)
PEB is at TEB + 0x60

Accessing TEB requires reading from the gs segment register.
This is a single instruction (mov rax, gs:[0x30]) but cannot
be expressed in portable C. This is the one piece of
architecture-specific inline assembly or accessor function
required for Windows targets, beyond the TEB/PEB offsets
which are C-level struct field accesses.
```

### i686

```
TEB is at fs:[0x18]  (self-pointer in TEB)
PEB is at TEB + 0x30

Accessing TEB requires reading from the fs segment register.
```

### aarch64

```
TEB is read from x18 (the platform register, reserved by AAPCS).
PEB is at TEB + 0x60 (same as x86_64).

The runner sets x18 directly via inline asm before calling the blob.
```

## DJB2 Hash Computation

```
(conceptual algorithm)
hash = 5381
for each byte in input:
    hash = hash * 33 + byte
return hash as uint32

For DLL names: input = lowercase(ascii(BaseDllName))
For function names: input = ascii(export_name) (case-sensitive)
```

## PEB Structure Offsets

All offsets below are relative to the `InMemoryOrderLinks` pointer
(the LIST_ENTRY Flink obtained from `InMemoryOrderModuleList`), NOT
from the start of `LDR_DATA_TABLE_ENTRY`.

### 64-bit (x86_64, aarch64)

```
TEB (Thread Environment Block):
  +0x30: Self pointer (TEB address)
  +0x60: PEB pointer

PEB (Process Environment Block):
  +0x18: Ldr (PEB_LDR_DATA pointer)

PEB_LDR_DATA:
  +0x20: InMemoryOrderModuleList (LIST_ENTRY)

From InMemoryOrderLinks (Flink):
  +0x00: Flink/Blink (LIST_ENTRY, 16 bytes)
  +0x20: DllBase         (struct offset 0x30)
  +0x48: BaseDllName     (struct offset 0x58, UNICODE_STRING)

UNICODE_STRING:
  +0x00: Length (u16, byte count)
  +0x08: Buffer (pointer)
```

### 32-bit (i686)

```
TEB:
  +0x18: Self pointer
  +0x30: PEB pointer

PEB:
  +0x0C: Ldr (PEB_LDR_DATA pointer)

PEB_LDR_DATA:
  +0x14: InMemoryOrderModuleList (LIST_ENTRY)

From InMemoryOrderLinks (Flink):
  +0x00: Flink/Blink (LIST_ENTRY, 8 bytes)
  +0x10: DllBase         (struct offset 0x18)
  +0x28: BaseDllName     (struct offset 0x30, UNICODE_STRING) [*]

UNICODE_STRING:
  +0x00: Length (u16, byte count)
  +0x04: Buffer (pointer)
```

**[*] i686 BaseDllName offset**: Originally set to `0x28` (incorrect),
fixed to `0x24` after Wine validation exposed the discrepancy. The
correct derivation: `BaseDllName` is at struct offset `0x2C`, and
`InMemoryOrderLinks` is at struct offset `0x08`, so the relative
offset is `0x2C - 0x08 = 0x24`. Wine validation now passes on i686.

**Build cache note**: After changing PEB offsets, run
`python tools/extract_release.py` to regenerate the pre-extracted
`.bin` files in `blobs/`. The `get_blob()` API reads from these
release blobs, not directly from the `.so` files in `_blobs/`.

## Export Directory Parsing

```
PE at DllBase:
  +0x00: DOS Header
    +0x3C: e_lfanew (offset to PE signature)

  PE Signature + COFF Header + Optional Header:
    Optional Header Data Directories[0] = Export Directory RVA + Size

Export Directory:
  +0x18: NumberOfNames
  +0x1C: AddressOfFunctions (RVA to address table)
  +0x20: AddressOfNames (RVA to name pointer table)
  +0x24: AddressOfNameOrdinals (RVA to ordinal table)

Resolution:
  For i in 0..NumberOfNames:
    name_rva = AddressOfNames[i]
    name_str = DllBase + name_rva
    if djb2(name_str) == target_hash:
      ordinal = AddressOfNameOrdinals[i]
      func_rva = AddressOfFunctions[ordinal]
      func_addr = DllBase + func_rva
      if func_addr is within export directory range:
        -> forwarded export, parse and recurse
      else:
        return func_addr
```

## Resolved Function Cache

```
(conceptual)
struct win_api_cache {
    void* VirtualAlloc;
    void* VirtualProtect;
    void* VirtualFree;
    void* LoadLibraryA;
    void* GetProcAddress;
    void* ExitProcess;
    // ... per blob type
};

The cache struct is part of the blob's .bss or stack frame.
On first use, each slot is NULL. The resolve_function wrapper
checks the slot before doing a full PEB walk. After resolution,
the pointer is stored in the slot for reuse.
```

## Mock Runner Correctness

### The Self-Consistency Problem

The mock runner constructs fake TEB/PEB/PE structures and provides
mock API implementations. Because the blob and mock are compiled from
the same headers and offsets, bugs in those offsets are invisible to
mock-based tests — both sides read/write at the wrong offset
consistently. This class of bug can only be caught by running the
blob against a real Windows implementation.

### Wine Validation

`tools/validate_wine.py` wraps blobs in a minimal PE (built in pure
Python, no toolchain) and runs them under Wine. It compares stdout and
exit code against the mock runner. This catches offset/ABI bugs that
mock self-consistency hides.

Limitations:
- **x86_64**: Fully validated. Requires `PIC_WINAPI` (ms_abi) on
  function pointer types and ABI thunks in the mock runner trampolines.
- **i686**: Fully validated. Calling convention is the same (cdecl).
- **aarch64**: Cannot validate (Wine doesn't run ARM64 PEs on x86
  hosts). Offsets are correct by structural analysis (same 64-bit
  layout as x86_64, validated via Wine). TEB access via x18 is
  correct per Windows ARM64 ABI but untested against real Windows.

### Bugs Found and Fixed

**i686 BaseDllName offset** (peb.h + runner.c): Was `0x28`, should
be `0x24`. The mock used the same wrong offset so tests passed.
Wine crashed reading from the wrong PEB offset. Root cause: the
offset was calculated from the struct start rather than from the
`InMemoryOrderLinks` pointer (which is at struct offset `0x08`).
Correct derivation: struct `0x2C` - InMemoryOrderLinks `0x08` = `0x24`.

**aarch64 TEB register** (teb.h + runner.c): Used `tpidr_el0`
(Linux thread pointer), should be `x18` (Windows ARM64 platform
register). The mock set `tpidr_el0` and the blob read `tpidr_el0`,
so tests passed. Fixed to `x18` per the Windows ARM64 ABI. GCC
reserves x18 and never uses it as a scratch register, so this is
safe in freestanding code.

**x86_64 calling convention** (os/windows.h, blobs, runner.c):
Blobs compiled with GCC default to SysV ABI (args in rdi, rsi, rdx).
Real Windows APIs expect MS x64 ABI (args in rcx, rdx, r8, r9).
The mock functions also used SysV, so tests passed. Fixed by adding
`PIC_WINAPI` (`__attribute__((ms_abi))`) to function pointer types
and ABI translation thunks in the mock PE trampolines. See ADR-025.

### Debugging Build Cache Issues

When changing PEB offsets or calling conventions, stale binaries can
mask fixes. The build has three cache layers:

1. **Bazel action cache**: `bazel clean --expunge` clears it, but
   genrule-based blob builds may not track header changes. Touch the
   `.c` source file to force recompilation.
2. **Staged .so files** (`_blobs/`): Rebuilt by `stage_blobs.py`.
   After building blobs, stage them BEFORE building the runner (the
   runner build changes the `bazel-bin` symlink to a different
   platform config).
3. **Pre-extracted release blobs** (`blobs/*.bin`): `get_blob()` reads
   from these, NOT from `_blobs/*.so`. Run `python tools/extract_release.py`
   after staging to regenerate them.

If a fix "doesn't work", check all three layers. The symptom is
usually that `objdump` of the `.so` shows the fix but `get_blob()`
returns old code.

## Derives From
- REQ-005
- REQ-006
