# TEST-003: Windows PEB Walk and DJB2 Resolution Verification

## Status
Accepted

## Verifies
- REQ-005
- REQ-006

## Goal

Demonstrate that the PEB/TEB walk correctly locates loaded DLLs and resolves exported functions on Windows x86_64 and aarch64, and that the DJB2 hash implementation is correct across C and Python.

## Preconditions

- QEMU user-static is installed for x86_64 and aarch64.
- Per ADR-010: No real Windows environment is required. All Windows blob tests use a Linux test harness that constructs a mock TEB/PEB in memory with mock module entries and mock API functions. Tests verify control flow — that the blob resolves the correct DJB2 hashes and calls the correct functions in the correct order with plausible arguments.
- The DJB2 test vectors are defined.
- See MOD-006 for mock TEB/PEB setup details.

## Procedure

### Test 3.1: DJB2 Hash Test Vectors

1. Compute DJB2 hashes for a set of known strings in both the C implementation and the Python implementation.
2. Test vectors SHALL include at minimum:
   - "kernel32.dll" (lowercased) → expected hash value
   - "ntdll.dll" (lowercased) → expected hash value
   - "ws2_32.dll" (lowercased) → expected hash value
   - "VirtualAlloc" → expected hash value
   - "GetProcAddress" → expected hash value
   - "LoadLibraryA" → expected hash value
   - "WSAStartup" → expected hash value
   - "ExitProcess" → expected hash value
   - Empty string → expected hash value (5381)
   - Single character "A" → expected hash value
3. Verify all C and Python outputs match.

### Test 3.2: Module Enumeration

Using the mock TEB/PEB test runner (x86_64, under QEMU user-static):

1. Build and run a test blob that walks the PEB InMemoryOrderModuleList and outputs the BaseDllName and DllBase for each loaded module.
2. Verify that the blob finds mock entries for kernel32.dll and ntdll.dll in the mock module list.
3. Verify the reported DllBase addresses match the mock module base addresses.

### Test 3.3: Function Resolution — kernel32.dll

Using the mock TEB/PEB test runner (x86_64):

1. Build and run a test blob that resolves the following functions from kernel32.dll via DJB2 hash matching:
   - VirtualAlloc
   - VirtualProtect
   - VirtualFree
   - LoadLibraryA
   - GetProcAddress
   - ExitProcess
2. Verify the blob resolves each function to the corresponding mock implementation (verify via the mock verification log that the correct DJB2 hashes were looked up against the mock export table).
3. For each resolved function, verify the blob calls it (mock implementations log the call and return canned success values).

### Test 3.4: Function Resolution — ntdll.dll

Using the mock TEB/PEB test runner (x86_64):

1. Verify the blob resolves `NtAllocateVirtualMemory` from the mock ntdll.dll module via DJB2 hash matching.
2. Verify the mock verification log records the resolution and subsequent call.

### Test 3.5: Dynamic DLL Loading and Resolution

Using the mock TEB/PEB test runner (x86_64):

1. Build a test blob that:
   a. Resolves LoadLibraryA from mock kernel32.dll.
   b. Calls mock LoadLibraryA("ws2_32.dll") — the mock records the DLL name and returns a handle to a pre-registered mock ws2_32.dll module entry.
   c. Walks the PEB again and finds the mock ws2_32.dll entry.
   d. Resolves WSAStartup from mock ws2_32.dll via export table parsing.
   e. Calls mock WSAStartup — the mock records the call and returns success.
2. Verify the mock verification log confirms the full resolution chain in the correct order.

### Test 3.6: Forwarded Export Handling

Using the mock TEB/PEB test runner (x86_64):

1. Configure a mock export entry that contains a forwarder string (e.g., "ntdll.RtlAllocateHeap") instead of a direct function address.
2. Verify the blob's export parser detects the forward, locates the target mock module (ntdll.dll), and resolves the forwarded function from the target module's mock export table.
3. Verify the mock verification log records the forwarded resolution chain.

### Test 3.7: Windows aarch64

Repeat Tests 3.2 through 3.5 using the mock TEB/PEB test runner compiled for aarch64 (under QEMU aarch64-static).
Verify that the blob accesses the TEB via the x18 register and the mock TEB/PEB is correctly traversed on this architecture.

## Expected Results

- DJB2 hashes match between C and Python for all test vectors.
- Mock PEB walk finds kernel32.dll and ntdll.dll mock module entries.
- All standard function DJB2 hashes are correctly resolved against mock export tables.
- Forwarded exports are followed through the mock forwarding chain.
- The mechanism works on both x86_64 and aarch64 (under QEMU user-static with mock TEB/PEB per ADR-010).
