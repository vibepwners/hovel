# The squatter C style guide

A C style guide for humans and for agents. It is deliberately strict. The target
reader is the kind of engineer who maintained a UNIX in the 1990s, reads the
architecture manual for fun, and treats undefined behavior as a personal insult.
If a rule here feels excessive, that is the rule working as intended.

The codebase this guide governs is a Win32 network codebase (a multiplexed
stream/module server, an IOCP server library, a logging library) built with
MinGW-w64 and Bazel. Two themes run through everything:

1. **Totality.** Every error code is checked. Every variable is initialized.
   Every function says what it does and does exactly that. There are no paths
   the author "didn't think about" — the type system and the control flow are
   arranged so the compiler will not let you forget one.
2. **Use the platform.** This is Windows code. Prefer the Win32 API over the C
   runtime as a rule of thumb — there is better, more explicit, more
   controllable machinery in the API. `HeapAlloc`, not `malloc`. `WriteFile`,
   not `printf`. `CreateThread`, not `_beginthreadex`. `wnsprintf`, not
   `snprintf`. See [§9](#9-prefer-win32-avoid-the-c-runtime).

The rules are numbered so code review can cite them: "S3.2" is a complete
sentence in a pull request.

---

## 0. The non-negotiables (read this if you read nothing else)

- **0.1** Check the return value of every call that can fail. No exceptions. If
  you are intentionally ignoring one, cast it to `(void)` and be ready to defend
  it. ([§2](#2-error-handling))
- **0.2** Initialize every variable at the point of declaration. No declaration
  without an initializer. ([§3](#3-initialization))
- **0.3** Never invoke undefined behavior. When in doubt, look it up in the
  standard; do not guess. ([§4](#4-undefined-behavior))
- **0.4** Every function has one job, a prototype with explicit parameter types,
  and a documented contract. ([§5](#5-functions))
- **0.5** The build runs with `-Werror` and the warning set in
  [§10](#10-the-build). Warnings are errors because a warning is the compiler
  telling you it found a bug you have not noticed yet.

---

## 1. Files, modules, and naming

- **1.1 One module = one `.h` + one `.c`.** The header is the contract; the
  source is the implementation. A consumer reads only the header.
- **1.2 Header guards** are `SQ_<NAME>_H`, matching the file. No `#pragma once`
  (it is not in the standard and the guard costs one line).
- **1.3 Include order, most-specific first:** the module's own header, then other
  project headers, then the platform/stdlib headers, each group separated by a
  blank line and alphabetized within the group. The module's own header coming
  first means it is compiled standalone at least once per build, which proves it
  has no hidden include dependencies.
- **1.4 All Windows headers come from one shim, [`base/win.h`](../src/base/win.h).**
  Header ordering on Windows is load-bearing (`<winsock2.h>` *must* precede
  `<windows.h>`), and `_WIN32_WINNT` must be set before any SDK header. Centralize
  it once; never include `<windows.h>` or `<winsock2.h>` directly elsewhere.
- **1.5 Public names are prefixed `sq_`** (functions, types) or `SQ_` (macros,
  enumerators). The prefix is the namespace C does not give you. Internal
  (file-local) functions take no prefix and **must** be `static`.
- **1.6 `static` is the default linkage.** A function or file-scope datum is
  `static` unless it is deliberately part of a module's public surface. The
  linker should be able to confirm your encapsulation.
- **1.7 Types are `lower_snake_case`**, macros and enumerators are
  `UPPER_SNAKE_CASE`. No Hungarian notation on our own identifiers (the Win32
  API has its own conventions; do not fight them when calling it, do not adopt
  them for our code).

---

## 2. Error handling

> A function that can fail has two jobs: do the thing, and tell the truth about
> whether it did.

- **2.1 One total status type.** Fallible functions return
  [`sq_status`](../src/iocpserver/result.h). Success is `SQ_OK == 0`. The canonical
  check is `if (st != SQ_OK)`. Do not overload integers, pointers, or `errno`
  to carry success/failure across module boundaries.
- **2.2 Check every error code.** Every call that reports failure has its result
  inspected on the same logical line of reasoning that follows it. This includes
  calls people habitually skip: `closesocket`, `CloseHandle`, `setsockopt`,
  `WSACleanup`. If one genuinely cannot be acted on, log it — do not drop it.
- **2.3 To ignore a result, say so in code.** Prefix the call with `(void)`.
  This is a written assertion: "I considered this return value and I am
  discarding it on purpose." A bare ignored return is a bug until proven
  otherwise. Example: `(void)fflush_equivalent(...)`.
- **2.4 Record the system error at the failure site.** The small `sq_status`
  returned upward is a *category*; the actionable detail (the
  `GetLastError()` / `WSAGetLastError()` value, decoded) is logged exactly where
  it happened, via `SQ_LOG_SYS`. Capture the error into a `const` local
  *immediately* after the failing call, before any other call can clobber the
  thread's last-error:

  ```c
  if (bind(s, ai->ai_addr, (int)ai->ai_addrlen) != 0) {
      int const err = WSAGetLastError();   /* captured first */
      SQ_LOG_SYS((unsigned long)err, "bind failed");
      return SQ_ERR_ADDRESS;
  }
  ```

- **2.5 Clean up on every exit path.** A function that acquires resources and
  then hits an error must release what it acquired. Use the single-exit
  `goto fail;` ladder for anything past one acquisition; it is the idiom C was
  given `goto` for, and it keeps the cleanup in one place, in reverse order of
  acquisition. See [`sq_server_create`](../src/iocpserver/server.c).
- **2.6 Out-parameters are written exactly once, and defined on failure.** Set
  every out-parameter to a safe sentinel (`INVALID_SOCKET`, `NULL`, `AF_UNSPEC`)
  at the top, before anything can fail. A caller must never read an
  indeterminate value out of a function that returned an error.
- **2.7 Validate preconditions and return `SQ_ERR_PARAM`.** A `NULL` mandatory
  pointer or a nonsense argument is a programming error; report it, do not
  dereference it.

---

## 3. Initialization

- **3.1 Every variable is initialized where it is declared.** `int n = 0;`, not
  `int n;`. Aggregates use `= {0}`. This is mechanical, it is checkable, and it
  closes off an entire class of "indeterminate value" UB.
- **3.2 Declare at first use, narrowly scoped.** Do not hoist a pile of
  declarations to the top of a function. A variable that lives only inside a loop
  body is declared inside the loop body. Narrow scope plus mandatory initializer
  means a variable is never visible in a state where it has no meaningful value.
- **3.3 Zero-initialize structures destined for the OS**, then set the fields you
  mean to set by name: `WSADATA wsa = {0};`, `struct addrinfo hints = {0};`.
  Designated initialization of the named fields documents intent; the `{0}`
  guarantees the rest is not garbage.
- **3.4 `OVERLAPPED` is re-zeroed before every overlapped operation.** A reused
  `OVERLAPPED` carries stale state (notably the internal pointers and the event);
  `ZeroMemory(&ov, sizeof ov)` immediately before each `WSARecv`/`WSASend`/
  `AcceptEx` is mandatory, not optional.
- **3.5 `const` everything that does not change.** A local that is assigned once
  is `const`. It tells the reader "this will not move" and lets the compiler
  hold you to it. `int const err = WSAGetLastError();`.

---

## 4. Undefined behavior

UB is not a performance feature you are borrowing against; it is a landmine with
your name on it. The rules below are the ones that actually bite in this kind of
code.

- **4.1 No reads of indeterminate values.** Covered by [§3](#3-initialization);
  it is repeated here because it is the most common UB in practice.
- **4.2 No signed integer overflow.** Do arithmetic that can overflow in an
  unsigned type, or check before you compute. The argument parser checks
  `v > (0xFFFFFFFFUL - digit) / 10UL` *before* multiplying — it never forms the
  overflowing value. ([`parse_uint`](../examples/iocp_echo_server.c))
- **4.3 Mind the integer conversions.** `-Wconversion` and `-Wsign-conversion`
  are on. Every narrowing or sign-changing conversion is written as an explicit
  cast so the reader sees it and the compiler stops warning. Be especially careful
  with the Win32 width mismatches: `SOCKET` is a pointer-sized unsigned; `recv`
  returns `int`; lengths are `DWORD`/`ULONG`; `size_t` is not `int`.
- **4.4 No strict-aliasing violations.** Access an object only through a
  compatible type. The `CONTAINING_RECORD(ov, sq_conn, overlapped)` pattern is
  legal precisely because the `OVERLAPPED` is the genuine first member of a real
  `sq_conn` and we read it back as the `sq_conn` it actually is.
- **4.5 No data races.** Shared mutable state is either (a) guarded by a
  `CRITICAL_SECTION`, (b) touched only with `Interlocked*`, or (c) an aligned,
  pointer-or-smaller scalar used as a one-way flag. Document which, at the field.
  See [§7](#7-concurrency).
- **4.6 No out-of-bounds, no off-by-one.** Buffer sizes are named constants;
  indices are checked against them; `lstrcpynA` and `wnsprintfA` are given the
  real capacity so they cannot run past the end.
- **4.7 Pointer lifetime is explicit.** A pointer never outlives the object it
  points into. Ownership transfer is commented at the transfer site (e.g. "owner
  transferred to caller" when a socket handle moves out of a local).
- **4.8 Do not depend on evaluation order** of function arguments or of
  side effects between sequence points.

---

## 5. Functions

- **5.1 Strict prototypes, always.** A no-argument function is `f(void)`, never
  `f()`. `-Wstrict-prototypes` and `-Wmissing-prototypes` enforce this.
- **5.2 One responsibility.** If you need the word "and" to describe what a
  function does, it is two functions. `post_recv` posts a receive. It does not
  also decide what to do when the receive completes — that is
  `on_recv_complete`.
- **5.3 Document the contract above the definition (or in the header).** State
  preconditions, what the return value means, what happens to out-parameters on
  failure, and any ownership or threading constraints. The reader should not
  have to infer the contract from the body.
- **5.4 Keep functions short enough to hold in your head.** There is no hard line
  count, but if a function does not fit on a screen, it is hiding a smaller
  function inside it. Extract it.
- **5.5 `switch` over an enum has no `default`.** Handle every enumerator
  explicitly; omitting `default` turns a newly-added, unhandled enumerator into a
  `-Werror` warning instead of a silent fall-through. Put the
  unreachable/fallback return *after* the `switch`. ([`sq_status_str`](../src/iocpserver/result.c))
- **5.6 Validate, act, report.** The body shape is: check arguments, do the work,
  return a truthful status. Out-parameters get their failure sentinel before the
  first thing that can fail.
- **5.7 No magic numbers.** A literal with meaning gets a named constant or an
  `enum`. Buffer sizes, backlog defaults, completion keys — all named.

---

## 6. Types, memory, and resources

- **6.1 Fixed, bounded buffers.** No VLAs (`-Wvla`). Sizes are compile-time
  constants. A connection's buffers are members of the connection struct, sized
  by `enum`, so allocation is one `HeapAlloc` and lifetime is the connection's.
- **6.2 One owner per resource.** Every socket, handle, lock, and allocation has
  exactly one owner responsible for releasing it, and one release path. In this
  codebase a connection owns its socket and its memory; `conn_free` is the one
  place both are released.
- **6.3 Acquire and release symmetrically.** `WSAStartup`/`WSACleanup`,
  `CreateEvent`/`CloseHandle`, `InitializeCriticalSection`/`DeleteCriticalSection`,
  `HeapAlloc`/`HeapFree` — pair them, and pair them in mirror order during
  teardown.
- **6.4 Null out freed pointers and invalidated handles** when the containing
  object outlives the free, so a stale use is a clean `NULL`/`INVALID_SOCKET`
  rather than a use-after-free. `conn_free` sets `sock = INVALID_SOCKET` before
  the structure goes away; `stop()` sets it before closing so the later drain
  does not double-close.
- **6.5 Teardown tolerates partial construction.** A destroy/cleanup routine must
  cope with a half-built object: guard every handle against its
  `NULL`/`INVALID_*` sentinel. This is what lets `sq_server_create` clean up by
  simply calling `sq_server_destroy` on the partially-built server.

---

## 7. Concurrency

This is multithreaded IOCP code; the concurrency model is part of the design, not
an afterthought.

- **7.1 State an invariant that removes the need for a lock, or take the lock.**
  The whole connection state machine rests on one written invariant: *a
  connection has exactly one I/O operation outstanding at any instant*, so only
  one worker ever touches it. That sentence is load-bearing and is documented at
  the `sq_conn` definition. If you cannot write such a sentence, you need a lock.
- **7.2 Shared structures get exactly one lock, and it is named for what it
  guards.** The live-connection list is guarded by `list_lock`. Hold it for the
  list mutation and nothing more.
- **7.3 Single-value cross-thread flags use `Interlocked*` or a one-way aligned
  scalar.** `stopping` and `outstanding` are `volatile LONG` touched with
  `InterlockedExchange`/`InterlockedIncrement`/`InterlockedDecrement`. Naturally
  aligned word-sized reads are atomic on Windows targets; we rely on that only
  for coherent single reads, never for read-modify-write.
- **7.4 Never block holding a lock**, and never call back into unknown code
  (a handler, an allocator that might log) while holding one if you can avoid it.
- **7.5 Shutdown is a protocol, not a `kill`.** Cancelling I/O (by closing the
  socket), draining the resulting completions, freeing each connection on the
  worker that dequeues its final completion, and only then releasing the workers
  — that ordering is what makes shutdown leak-free. Do not "simplify" it by
  exiting workers while completions are still in flight. ([`sq_server_stop`](../src/iocpserver/server.c))
- **7.6 `volatile` is not a synchronization primitive.** It prevents the compiler
  from caching a load; it does not order memory or make compound operations
  atomic. Where ordering or atomicity matters, use the `Interlocked*` family.

---

## 8. Comments

- **8.1 Comment *why*, and *what is not obvious from the code*.** The code already
  says what it does. Comments earn their place by explaining a constraint the
  code cannot express: why `<winsock2.h>` is first, why `winpthreads` precedes
  `libgcc`, why an `OVERLAPPED` must be re-zeroed, why the lock is held across the
  whole list walk.
- **8.2 Document invariants where they live.** The "one op in flight" rule is
  commented at the struct it constrains, not in a far-away design doc.
- **8.3 No noise.** Do not write `i++ // increment i`. Do not narrate the
  obvious. A comment that restates the next line is a comment that will rot.
- **8.4 A `/* fallthrough */` in a `switch` is mandatory** when one case
  deliberately falls into the next.

---

## 9. Prefer Win32, avoid the C runtime

This is Windows code. The Win32 API is the platform; the C runtime is a thin,
lowest-common-denominator layer on top of it. As a rule of thumb, reach for the
API.

| Need                | Use (Win32)                          | Not (CRT)              |
|---------------------|--------------------------------------|------------------------|
| Heap memory         | `HeapAlloc` / `HeapFree`             | `malloc` / `free`      |
| Zero / copy memory  | `ZeroMemory` / `CopyMemory`          | `memset` / `memcpy`    |
| Threads             | `CreateThread`                       | `_beginthreadex`       |
| Console / log output| `WriteFile` to a std handle          | `printf` / `fwrite`    |
| Bounded formatting  | `wnsprintfW` / `wvnsprintfW` (shlwapi)| `snprintf` / `vsnprintf` |
| String length/compare/copy | `lstrlenW` / `lstrcmpW` / `lstrcpynW` | `strlen` / `strcmp` / `strncpy` |
| Error text          | `FormatMessageW`                     | `strerror`             |
| Numeric parsing     | hand-rolled, or `StrToIntExW` (shlwapi)| `strtol` / `atoi`     |
| UTF-8 <-> UTF-16    | `MultiByteToWideChar` / `WideCharToMultiByte` | `mbstowcs` / `wcstombs` |

- **9.1 Use the bounded formatter.** `wvsprintf`/`wsprintf` have **no length
  bound** and can overrun. Use the `wnsprintf`/`wvnsprintf` family from
  `shlwapi`, which take a capacity and NUL-terminate within it.
- **9.2 Know the wsprintf format dialect.** It is *not* C `printf`. Supported:
  `%c %d %i %u %x %X %s` with the `l` and `I64` length modifiers. **Zero-padding
  is a precision**, e.g. `%.2u`, because there is no `0` flag. There are no float
  specifiers and no `%z`/`%ll`. Because our formatting goes through this dialect,
  our logging functions deliberately carry **no** `__attribute__((format(printf)))`
  — we do not want the compiler checking our strings against C `printf` rules.
- **9.3 The honest boundary.** Standard program startup (`mainCRTStartup`) and a
  few compiler-emitted intrinsics (`memcpy`/`memset` may bottom out in libgcc or
  the CRT) still pull a sliver of the CRT into the final image — you will see
  `api-ms-win-crt-*` imports. Removing even that requires `-nostdlib` and a custom
  entry point, which is out of scope here. "Avoid the CRT" is a rule of thumb for
  *the code you write*, applied with judgment, not a freestanding mandate.
- **9.4 Calling the Win32 API, follow its conventions.** Check its documented
  failure return (often `NULL`, `INVALID_HANDLE_VALUE`, `SOCKET_ERROR`, or a
  nonzero error), retrieve detail with the matching
  `GetLastError`/`WSAGetLastError`, and respect its types (`BOOL` is not `bool`;
  compare against `FALSE`/`TRUE`).
- **9.5 This is a wide (UTF-16) application — every Win32 call is the `...W`
  form.** We build with `-DUNICODE -D_UNICODE` (see
  [`bazel/copts.bzl`](../bazel/copts.bzl)), so the generic macros (`CreateFile`,
  `wnsprintf`, `WNDCLASSEX`, ...) already resolve to their `W` variants. Never
  reach for an `A` (ANSI) entry point: no `CreateFileA`, `lstrcmpA`,
  `wnsprintfA`, `GetAddrInfoA`. Strings the Win32 API touches are `wchar_t` and
  literals are `L"..."`. Entry points are `wmain(int argc, wchar_t **argv)` (link
  with `-municode`) — never `main`. The seams to the outside world are explicit:
  the wire protocol and on-disk bytes are **UTF-8**, so convert at the boundary
  with `MultiByteToWideChar(CP_UTF8, ...)` on the way in and
  `WideCharToMultiByte(CP_UTF8, ...)` on the way out (e.g. the wire UTF-8 args
  become wide `argv` in `runtime/session.c`; a module's reply is widened-then-
  encoded). A byte that never reaches the Win32 API — a protobuf field, a wire
  buffer — stays a `char` and is handled with a **hand-rolled** byte loop, not an
  `A`-suffixed call (see `runtime/module.c`'s `name_equal`,
  `wire/control_codec.c`'s `copy_bounded`): that keeps the narrow WinAPI out of
  the build entirely rather than mixing widths.
- **9.6 The wsprintf width specifiers flip under `UNICODE`.** In a wide
  `wnsprintfW`/`wvnsprintfW`, **`%s` is a wide (`wchar_t*`) string and `%S` is a
  narrow (`char*`) one** — the reverse of a narrow build. So a `const char*` from
  a narrow source (a status string, a nanopb field) must be printed with `%S`
  into a wide format string. Our logging format strings are `L"..."` for exactly
  this reason; see `sqlog/sqlog.h`.

---

## 10. The build

- **10.1 Warnings are errors.** `-Werror`. A warning is a latent bug.
- **10.2 The warning set** (see [`src/BUILD.bazel`](../src/BUILD.bazel)) is, at
  minimum: `-std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
  -Wshadow -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
  -Wmissing-declarations -Wredundant-decls -Wpointer-arith -Wwrite-strings
  -Wundef -Wvla -Wstrict-overflow=5`. Add to it; do not subtract without a
  written reason.
- **10.3 Strictness applies to our code, not the SDK.** Platform headers arrive
  through the toolchain's *builtin* (angle-bracket) include dirs, which the
  compiler treats as system headers and exempts from these diagnostics. That is
  exactly why we can be this strict without patching `<windows.h>` — so include
  Windows headers with `<...>` (via the shim), never with `"..."`.
- **10.4 Pin the toolchain.** The compiler is a pinned release artifact (URL +
  SHA256); the Starlark that wires it is pinned to a commit. A build is a
  function of its inputs or it is not reproducible. See the root
  [`README.md`](../README.md) and [`MODULE.bazel`](../MODULE.bazel).
- **10.5 `-std=c11`, and mean it.** ISO C plus the documented Win32 surface.
  GNU extensions in *our* code are a `-Wpedantic` error; the extensions the SDK
  itself uses are fine because the SDK headers are system headers (10.3).

---

## 11. A worked checklist for a new function

Before you call a function done, confirm:

1. Prototype is strict (`(void)` if nullary); it is `static` unless public.
2. Every parameter that must be non-NULL is checked; bad input returns
   `SQ_ERR_PARAM`.
3. Every local is initialized at declaration; one-shot locals are `const`.
4. Every out-parameter is set to its failure sentinel before anything can fail.
5. Every fallible call's result is checked or explicitly `(void)`-discarded.
6. System errors are captured into a `const` local immediately and logged.
7. Every resource acquired is released on every exit path (`goto fail;` ladder).
8. No conversion is implicit that `-Wconversion` would flag.
9. The contract — preconditions, return meaning, ownership, threading — is
   written down.
10. It builds clean under the full [§10](#10-the-build) warning set, for **both**
    `--config=win64` and `--config=win32`.

If all eleven sections agree with your function, the graybeards are, grudgingly,
content.
