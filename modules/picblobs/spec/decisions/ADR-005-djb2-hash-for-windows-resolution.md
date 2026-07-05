# ADR-005: DJB2 Hash for Windows API Function Resolution

## Status
Accepted

## Context

Windows PIC blobs resolve API functions at runtime by walking the PEB and comparing function names against known values. Storing full function name strings in the blob increases its size and makes the blob's API dependencies trivially readable. A hash-based approach reduces size and is the established convention in shellcode.

## Decision

Windows API function names and DLL names SHALL be identified by their DJB2 hash (32-bit). The blob compares hashes during PEB walk and export table parsing, never plaintext strings.

DJB2 was chosen because:
1. It is the most widely recognized hash algorithm in shellcode/PIC contexts.
2. It is trivial to implement (under 10 instructions in assembly, a few lines in C).
3. Its behavior is well-documented with extensive test vectors available in the security research community.
4. Collision probability within the set of Windows API names used by a single blob is negligible in 32 bits.

## Alternatives Considered

- **CRC32**: Equally small, but slower to compute and no more collision-resistant in this context. Less conventional in shellcode. Rejected.
- **ROT13/ROR13 hash**: Common alternative in some shellcode families. Equivalent in properties to DJB2 but less widely standardized. Rejected for lack of clear advantage.
- **Full string comparison**: Store plaintext function names in the blob and compare directly. Larger blob size but simpler and more debuggable. Rejected as default, but could be offered as a debug variant in the future.
- **Custom/proprietary hash**: Better hash properties are unnecessary given the small input set. Using a non-standard hash makes the blobs harder to analyze with existing tools. Rejected.

## Consequences

- DLL name hashing requires case normalization (lowercase) before hashing, since DLL names are case-insensitive on Windows.
- The Python API must implement the same DJB2 algorithm for computing hashes of user-specified function names.
- If a DJB2 collision is discovered between two function names used by the same blob, a mitigation strategy (secondary hash, partial string check) must be added — but this is extremely unlikely in practice.

## Related Requirements
- REQ-006
