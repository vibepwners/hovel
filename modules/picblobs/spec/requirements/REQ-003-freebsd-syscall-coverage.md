# REQ-003: Complete FreeBSD Syscall Header and Source Coverage

## Status
Accepted

## Statement

picblobs SHALL provide a C header and source system that exposes every FreeBSD system call as a callable C function. Each wrapper function SHALL accept typed arguments matching the FreeBSD kernel's expected types and SHALL invoke the syscall assembly primitive (REQ-001) with the correct syscall number for the target architecture. The syscall number tables SHALL be derived from authoritative FreeBSD kernel sources.

## Rationale

FreeBSD is a first-class target. The same design rationale as REQ-002 applies: blobs interact with the kernel exclusively through syscalls, and complete coverage ensures any blob type can use any FreeBSD syscall without new assembly work. FreeBSD's syscall table differs significantly from Linux — different numbers, different semantics for some calls, and FreeBSD-specific calls that have no Linux equivalent.

## Derives From
- VIS-001
- REQ-001

## Detailed Requirements

### Header Organization

The headers SHALL be organized by functional group, mirroring FreeBSD's syscall groupings. The following groups are REQUIRED (non-exhaustive — the full set SHALL cover every syscall in FreeBSD's `syscalls.master`):

1. **Memory management**: mmap, munmap, mprotect, madvise, minherit, msync, mlock, munlock, mlockall, munlockall, mincore, shm_open, shm_open2, shm_unlink, shm_rename, memfd_create, etc.
2. **File operations**: open, openat, close, read, write, pread, pwrite, lseek, readv, writev, sendfile, stat, fstat, lstat, fstatat, access, faccessat, truncate, ftruncate, rename, renameat, unlink, unlinkat, mkdir, mkdirat, rmdir, link, linkat, symlink, symlinkat, readlink, readlinkat, chmod, fchmod, fchmodat, chown, fchown, fchownat, utimensat, futimens, etc.
3. **Process control**: fork, vfork, rfork, execve, fexecve, exit, wait4, waitid, kill, getpid, getppid, getuid, getgid, geteuid, getegid, setuid, setgid, setsid, getpgrp, setpgid, jail, jail_get, jail_set, jail_remove, procctl, etc.
4. **Socket operations**: socket, bind, listen, accept, accept4, connect, sendto, recvfrom, sendmsg, recvmsg, shutdown, setsockopt, getsockopt, getpeername, getsockname, socketpair, sendmmsg, recvmmsg, sctp_generic_sendmsg, sctp_generic_recvmsg, etc.
5. **File descriptor operations**: dup, dup2, fcntl, ioctl, poll, select, pselect, kqueue, kevent, pipe, pipe2, closefrom, close_range, etc.
6. **Signal handling**: sigaction, sigprocmask, sigreturn, sigpending, sigtimedwait, sigwaitinfo, sigqueue, sigsuspend, sigaltstack, etc.
7. **Time and clock**: clock_gettime, clock_settime, clock_getres, nanosleep, gettimeofday, settimeofday, ktimer_create, ktimer_settime, ktimer_gettime, ktimer_getoverrun, ktimer_delete, etc.
8. **Filesystem and mount**: mount, nmount, unmount, chroot, statfs, fstatfs, getfsstat, sync, fsync, fdatasync, etc.
9. **FreeBSD-specific**: capsicum syscalls (cap_enter, cap_getmode, cap_rights_limit, cap_rights_get, cap_ioctls_limit, cap_ioctls_get, cap_fcntls_limit, cap_fcntls_get), __sysctl, sysctlbyname, aio_read, aio_write, aio_return, aio_error, aio_waitcomplete, aio_suspend, etc.
10. **Thread and umtx**: thr_new, thr_exit, thr_kill, thr_self, _umtx_op, etc.

### Syscall Number Tables

For each supported architecture, picblobs SHALL maintain a table mapping each FreeBSD syscall name to its numeric value. Unlike Linux, FreeBSD's syscall numbers are largely architecture-independent (the same number table across architectures), but the assembly calling convention differs per architecture (see REQ-001).

The tables SHALL be:

1. Derived from FreeBSD's `sys/kern/syscalls.master` or equivalent generated header.
2. Stored as C header files with preprocessor defines.
3. Version-pinned to a specific FreeBSD release, documented in the file header.

### FreeBSD-Specific Calling Convention Notes

FreeBSD differs from Linux in several important ways that the wrapper layer SHALL account for:

1. **Error indication**: FreeBSD uses the processor carry flag (x86) or register convention (other architectures) to indicate error, rather than Linux's negative-return-value convention. The raw return value SHALL be returned to the caller; error convention documentation SHALL be provided but no errno emulation SHALL be performed.
2. **i686 stack-based arguments**: FreeBSD i386 passes syscall arguments on the stack (not in registers like Linux i386). The assembly stub and wrappers SHALL account for this.
3. **64-bit arguments on 32-bit architectures**: FreeBSD's handling of 64-bit arguments (e.g., off_t in lseek) on 32-bit architectures follows specific alignment and padding rules that SHALL be documented and correctly implemented in the wrapper layer.

### Wrapper Function Conventions

Same conventions as REQ-002: typed arguments, raw return values, `-ffunction-sections` for dead-code elimination, no errno emulation.

## Acceptance Criteria

1. For each supported FreeBSD architecture, there exists a complete set of headers covering every syscall in FreeBSD's syscall master list for that architecture.
2. Each wrapper function correctly invokes the syscall primitive with the right number and argument mapping.
3. FreeBSD-specific calling convention differences (stack-based args on i686, carry-flag errors) are correctly handled.
4. Unused syscall wrappers do not appear in final blob binaries.
5. Syscall number tables cite their source FreeBSD version.

## Related Decisions
- ADR-006

## Modeled By
- MOD-004

## Verified By
- TEST-002
