# REQ-006: DJB2 Hash-Based Function Name Resolution

## Status
Accepted

## Statement

The Windows PEB walk (REQ-005) SHALL identify DLL names and exported function names by comparing DJB2 hashes of the names against precomputed hash values. The blob SHALL NOT contain plaintext DLL or function name strings for resolution purposes. Hash values for all required functions SHALL be precomputed at build time and embedded in the blob's config struct or as compile-time constants.

## Rationale

Using hashes instead of plaintext strings provides two benefits:
1. **Size reduction**: A 32-bit hash is smaller than a variable-length ASCII/Unicode function name string.
2. **Standardization**: DJB2 is the most widely recognized hash in shellcode contexts, making the blobs interoperable with existing tooling and analysis workflows.

Note: Hash-based resolution is NOT intended as an evasion technique (see VIS-002 non-goals). It is a size and convention choice.

## Derives From
- REQ-005

## Detailed Requirements

### Hash Algorithm

The hash algorithm SHALL be DJB2 as originally defined by Daniel J. Bernstein:

- Initial value: 5381
- For each byte of the input: `hash = hash * 33 + byte`
- The hash is computed over the ASCII bytes of the function name (case-sensitive for export names, case-insensitive for DLL names).

For DLL name hashing:
- The name SHALL be converted to lowercase before hashing (DLL names are case-insensitive on Windows).
- The Unicode BaseDllName from the PEB SHALL be narrowed to ASCII (or hashed as UTF-16LE, with the convention documented) before applying DJB2.

For function name hashing:
- The name SHALL be hashed as-is in ASCII (export names are case-sensitive).

### Hash Width

The hash SHALL be 32 bits (unsigned 32-bit integer). While DJB2 collisions are possible in 32 bits, the probability within the set of Windows API function names actually used by a single blob is negligible. If a collision is detected for a specific function pair in the future, the resolution logic SHALL fall back to comparing additional bytes or using a secondary hash, and this SHALL be documented as an exception.

### Precomputed Hash Tables

At build time, a tool or script SHALL compute DJB2 hashes for:

1. All DLL names the blob needs to locate (e.g., hash of "kernel32.dll", "ntdll.dll", "ws2_32.dll").
2. All function names the blob needs to resolve (e.g., hash of "VirtualAlloc", "GetProcAddress", etc.).

These precomputed hashes SHALL be embedded in the C source as compile-time constants and/or included in the config struct definition so that the Python side can also compute and supply hashes for user-specified function names.

### Python-Side Hash Computation

The Python API SHALL expose a utility function that computes the DJB2 hash of a given string using the same algorithm and conventions as the C side. This allows consumers to compute hashes for additional functions they want the blob to resolve.

## Acceptance Criteria

1. The DJB2 implementation in C and Python produce identical hashes for the same input string.
2. The blob resolves all required functions using hash comparison only — no plaintext name strings appear in the blob binary.
3. The hash computation is documented with test vectors (e.g., DJB2("VirtualAlloc") = expected value).
4. DLL name hashing correctly handles case-insensitive comparison.

## Related Decisions
- ADR-005

## Verified By
- TEST-003
