---
name: c-cpp-review
description: Systematic C/C++ security review with a coverage ledger. Use when auditing native C/C++ userspace — daemons, services, parsers, libraries — for memory, integer, string, lifetime, return-value, concurrency, C++ and Windows-specific bugs. Carries the class catalog and the per-unit review questions. Not for kernel code.
---

# SKILL: C/C++ Security Review

Reading C for bugs is a **coverage** exercise partitioned by *location*, not a scanning exercise
partitioned by bug class. The class catalog below is a completeness sweep laid on top of that, not
the primary partition — a class-per-pass review re-reads the same file twenty times and still
misses the function nobody opened.

Out of scope here: kernel drivers and modules (`kernel-exploitation`), managed languages, and
bare-metal code with no libc. Bug classes in the abstract live in `bug-class-catalog`; this skill
is the C-specific *semantics* — the library contracts that surprise people, and the shapes that
are false positives.

## The Unit Ledger

Partition the tree into **review units**: one function, or a syntactic slice of a function larger
than ~150 lines. Then, for every unit, answer the six questions below and **record a row** — even
when the answer is "nothing here". The ledger is what makes a coverage claim checkable; findings
without it are an anecdote.

| Question | What it asks |
|---|---|
| `bounds` | Spatial safety at every **write**: what bounds each destination, and can the index or length reach past it? High-yield shape: a size computed for one buffer applied to another. |
| `integer` | Width, signedness and wrap at every conversion and at every expression that becomes a size or an index. Unsigned subtraction that can go below zero is the quiet one — it wraps to a value that passes every upper-bound check. |
| `alloc-lifetime` | Allocation/release pairing: single owner, freed once, never used after, no surviving copy of a `realloc`'d pointer, released on **every** error path. |
| `return-values` | Every call whose failure matters: is the result checked, and against the convention *that function actually uses*? |
| `initialisation` | Every field of every caller-provided out-parameter and every local returned through: written on every path before anything reads it? `malloc` does not zero and neither does the stack. |
| `caller-contract` | What the unit assumes its caller guarantees about each parameter — and whether **every** caller actually guarantees it. Check the callers; do not assume. Function-like macros belong here too: a macro is textual, unscoped and untypechecked, so an invariant it relies on is invisible at the expansion site and can hold at four sites and not the fifth. |

Ledger rules that decide whether the review is honest:

1. **List every site you found, not just the ones you filed at.** "12 write sites, all indexed by
   `i` bounded at line 411, except 418 which uses `n` from the header — filed" is a real row.
2. **A finding does not close the unit or the question.** A function with one bug is *more* likely
   to hold another; keep reading.
3. **`not-applicable` is honest only when the population is empty.** No writes → `bounds` is N/A.
   Writes you did not examine → that is not N/A, it is unreviewed.
4. **`needs-human` beats a false clean**, and is not cheaper: still list every site and say what
   you could not resolve.
5. **Never trim a site to make a count agree.** A count you cannot reconcile is information — say
   so and leave the extra line in. Trimming to the number is exactly how a real thirteenth write
   site stops being examined.

## Threat Model First

Two settings gate whole class groups, so fix them before reading code:

- **`REMOTE`** — an off-box attacker. Drops `privilege-drop` and `envvar` as out of scope.
- **`LOCAL_UNPRIVILEGED`** — a local user. The **environment is attacker data**, temp-file races
  are live, and `setuid` handling matters.

Also detect, from *actual API usage* rather than file extension: is any translation unit really
C++ (not just C behind `extern "C"`)? Is it POSIX? Is it Windows? A class gated off by platform is
reported as *out of scope by configuration* — a different statement from *swept and found nothing*,
and a third from *nothing looked*. Keep the three apart in the report.

## Class Catalog

Each brief carries only what is not obvious: the surprising library semantics, the specific
invariant, and what makes a sighting a false positive.

### Memory bounds

- **`buffer-overflow` — out-of-bounds write.** Index arithmetic, loop bounds, size computations
  reaching a fixed or heap buffer. The high-yield shape is a size **computed correctly for one
  buffer and used against another**, or a bound re-derived rather than reused. Not a finding when
  the index is provably constrained at every caller — say *where*.
- **`oob-read`.** Distinct class, because the above is explicitly the *write*. Shapes: an index
  validated against the wrong buffer's length; a loop reading one element past its bound; a length
  taken from the data rather than from the allocation; back-references or window offsets in a
  decompressor pointing *behind* the buffer start. Impact is disclosure or a crash — a real
  vulnerability even where nothing is written.
- **`memcpy-size` — bad third argument.** Signed subtraction that can go negative and then converts
  to a huge `size_t`; a syscall return used without an error check; unsigned subtraction that
  wraps. `sizeof` on the **pointer** rather than the pointee is the classic silent one.
- **`overlapping-buffers`.** `memcpy`, `strcpy`, `sprintf` and the `str*cat` family are **undefined**
  when the regions overlap; only `memmove` is defined. Aliasing arrives through two pointers into
  one allocation (`buf` and `buf+k`), rarely through literally identical arguments.
- **`flexible-array`.** A trailing `data[0]`/`data[1]` member sized with `sizeof(struct)` instead of
  `offsetof(struct, data)` allocates one element too few or too many. The `[1]` form is the
  dangerous one — `sizeof` already counts that element, so the arithmetic silently disagrees with
  the C99 `data[]` form other code assumes.

### String handling

- **`string-bounds-and-termination`.** One bug with three faces. `malloc(strlen(s))` then `strcpy`
  writes one byte past the allocation — but only a bug when the destination is later used as a C
  string; a raw copy of exactly `strlen` bytes is fine. `strncpy` **does not NUL-terminate** when
  the source is ≥ n bytes: look for the missing `buf[n-1] = 0`, and for that assignment existing
  on only one branch. `strncat`'s third argument is **how many bytes to append**, not the
  destination size, and it always writes one more for the NUL — so `sizeof(dst)` is wrong by
  `strlen(dst)+1`, and that one is almost always a real overflow wherever it appears.
- **`string-issues` — encoding, locale, multibyte.** Byte length confused with character length
  across a conversion boundary. Locale-dependent case folding used for a *security* comparison
  (Turkish dotless i is the standing example). Missing UTF-8/UTF-16 validation where downstream
  code assumes well-formedness. Surrogate pairs and overlong encodings. Encoding-invariant
  violations are a real class in parsers, not cosmetics.

### Format and input APIs

- **`format-string`.** A non-literal format argument anywhere in the `printf`/`syslog` family; `%n`
  as a write primitive; argument/specifier type mismatches. Also **variadic wrappers that forward
  to `v*printf` without `__attribute__((format))`** — that turns off every compiler check at every
  call site.
- **`snprintf-retval`.** `snprintf` returns the length the output **would** have had, which can
  exceed the buffer; it is *not* bytes written. So `buf[n] = 0` with `n` from the return can write
  out of bounds, `ptr += snprintf(...)` can run past the end, and `remaining = size - snprintf(...)`
  can go negative. `asprintf` returns −1 and leaves the pointer **indeterminate** on failure.
- **`scanf-uninit`.** On a partial or failed match the `*scanf` family leaves later targets
  untouched, so an uninitialized local is read as if parsed. The return value is the number of
  items assigned; ignoring it is what makes this exploitable. `%s` with no field width is a
  separate unbounded write.
- **`banned-api-with-attacker-data`.** `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `tmpnam`,
  `tempnam`, `mktemp`, `strtok`, `alloca`, `putenv`, `rand` for security, width-less `%s`,
  `stpcpy`, `atoi` and friends with no error channel. **The evidence bar is a flow, not a name:**
  report one as a vulnerability only with a traced attacker-influenced value or size reaching it,
  naming source, sink, and what validates between. A call whose inputs are provably bounded
  internal constants is a *hardening observation* — you may still report it, but label it as one.
  Check for a project-local macro or wrapper shadowing the libc name before concluding anything.

### Object lifecycle

- **`uninitialized-data`.** Locals read on a path that skips their assignment; arrays partially
  filled then used at full length. **The disclosure half matters as much as the use half**: struct
  padding and tail bytes leaked over a socket or into a file are an information leak even when
  nothing misbehaves.
- **`null-deref`.** Unchecked allocation returns and unchecked lookup failures. The subtle variant
  is a check placed **after** a dereference: the compiler may delete the check, because the earlier
  deref already proved the pointer non-null — so the guard you can see is not the guard that runs.
- **`use-after-free`.** A pointer outliving its allocation: freed on an error path and used by the
  caller; freed twice through two owners; invalidated by a `realloc` whose old value some other
  variable still holds. **Realloc aliasing is the one most often missed** — every copy of the old
  pointer is dangling after a successful `realloc`.
- **`memory-leak`.** Matters here when the leaking path is **attacker-repeatable**: an error branch
  reachable from untrusted input is a remote memory-exhaustion primitive. A leak reachable once at
  startup is not. File descriptors, sockets and locks count. These live on cold error paths — and
  cold error paths are exactly what an attacker-reachability prior deprioritises, so read them
  deliberately.
- **`state-field-invariant`.** A field or flag of a long-lived struct carries a rule that must hold
  across every reset, allocation, refill and free path, and one path breaks it. C-specific by
  construction: `malloc` does not zero, lifetime is manual, and the struct is threaded through a
  state machine where no single function owns the field. **This is not a label to grep for** — used
  as a search term it reproduces the failure it describes. It is the output of an *invariant
  audit*: enumerate the fields, find every writer and every reader, prove the rule at each.

### Integer safety

- **`integer-overflow`.** Size and length arithmetic is the payload: `n * sizeof(T)` with no
  overflow check; `a + b` compared against a bound *after* the addition already wrapped; a 64-bit
  length truncated into an `int`; a signed value going negative and converting to a huge `size_t`.
  Signed overflow is **undefined**, so a post-hoc check like `if (a + b < a)` may be **deleted by
  the compiler** — a bug even where the wrap would have been benign. Growth patterns that double a
  size, or add a header to a body length, are where this reaches memory corruption. **Unsigned
  subtraction is the quiet one**: `a - b` where `b` can exceed `a` wraps to a near-`SIZE_MAX` value
  that passes every upper-bound check written for the non-wrapping case.
- **`oob-comparison`.** `memcmp`/`strncmp`/`bcmp` with a length taken from the **longer** operand;
  and the three-iterator `std::equal`, which reads from the second range without knowing its end.
  Also: `memcmp` is not constant-time, so using it on a secret is a separate timing problem worth
  noting (`crypto-side-channel-audit`).
- **`unit-and-scale-mismatch`.** Two quantities in the same expression measured in different units
  and never converted: **bytes vs elements** (`memcpy(dst, src, n)` where `n` counts elements),
  ticks vs milliseconds, bits vs bytes, a sensor raw value vs its scaled form, a fixed-point value
  at the wrong decimal scale. Addition and subtraction require *identical* units; multiplication
  and division change them. When a function's arguments include both a count and a size, check
  which one each call site supplies.

### Conversions, precedence and UB

- **`operator-precedence`.** Shift binds looser than addition; bitwise and/or bind looser than
  comparison; the ternary binds looser than assignment. Security-relevant shapes: a mask test
  written without parentheses, and a size expression whose intended grouping differs from the
  parsed one.
- **`type-confusion`.** A buffer cast to a struct **larger than the allocation** is the
  memory-corrupting form — look for numbered or "extended" struct variants where the choice of
  variant comes from the data. Also: union members read under the wrong tag; `void*` callback
  payloads cast back to the wrong type; C++ downcasts via `static_cast` where the dynamic type is
  attacker-influenced. In a **variadic (or K&R) call the compiler cannot convert `0` to a null
  pointer**, so `execl(path, arg, 0)` passes an `int` where a `char*` terminator is required — on
  LP64 that is 32 bits of zero followed by whatever is next. `0` in a *prototyped* pointer
  parameter is fine.
- **`undefined-behavior` the optimizer can weaponize.** Shifts by a negative amount or by ≥ the
  promoted width; misaligned loads via a cast; strict-aliasing violations that are not `char*`,
  `memcpy` or a union; unsequenced modification of one object. What makes these *security* bugs is
  that the optimizer may assume they never happen and delete the surrounding check. So the
  consequences belong here too: a `memset` of a secret before the object dies is
  **dead-store-eliminated** unless `explicit_bzero`/`memset_s`/`SecureZeroMemory`/a volatile access
  is used; security checks inside `assert()` **vanish under `NDEBUG`**; a null check placed after a
  deref is removable; and constant-time code written in plain C is not constant-time after
  optimization.

### Return values and errno

- **`error-handling`.** Ignoring the return of an allocation, an open, a **crypto verify**, or a
  write. Comparing against the wrong success convention — a function returning 1 on success tested
  with `!= 0`, or −1 on error tested with `!= 1`. A failure logged but not propagated leaves the
  caller acting on invalid state. Three shapes travel with this class:
  - **Negative returns.** `read`/`write`/`recv`/`send`/`snprintf` return negative on error;
    assigned into a `size_t`, −1 becomes `SIZE_MAX`, after which `n == -1` against an unsigned type
    is **never true** — the check reads as present but never fires.
  - **`errno`.** Meaningful only after a call that failed. Functions with a legitimate sentinel
    (`strtol` returning 0 or `LONG_MAX`, `getpwnam` returning NULL) need `errno = 0` **before** the
    call. And `errno` is clobbered by intervening library calls — **including the logging call in
    the error branch itself**.
  - **`EINTR`.** Blocking syscalls must be retried unless `SA_RESTART` covers every installed
    handler. `close()` is the exception: on Linux the descriptor is *already released* when it
    returns `EINTR`, so retrying can close an unrelated descriptor. A retry loop that restarts a
    partial read from the beginning is also wrong.

### Files and sockets

- **`open-issues`.** `access()` then `open()` is a **symlink race** whenever the directory is
  attacker-writable — and `access()` answers for the **real** uid, not the effective one.
  `O_NOFOLLOW` refuses a symlink only as the **final** component; every directory in the path is
  still followed, so the real fix is `openat2` with `RESOLVE_NO_SYMLINKS`, or component-by-component
  `openat`. Missing `O_CLOEXEC` leaks descriptors across `exec`.
- **`filesystem-issues`.** Predictable temp names (`tmpnam`/`tempnam`/`mktemp`, or a PID-derived
  name) in a shared directory. A path prefix check defeated by `..`, a symlink, a trailing slash,
  or a case-insensitive filesystem. Unicode normalization applied *after* the check rather than
  before. **The recurring bug is a prefix test comparing strings rather than resolved paths.**
- **`socket-state`.** `connect()` with `sa_family = AF_UNSPEC` **dissolves an already-connected
  socket**, after which it can be reconnected elsewhere — so if any part of a `sockaddr` reaching
  `connect()` is attacker-influenced, the association a sandbox or peer identity relies on can be
  dropped. This has been used for sandbox escapes. Separately, `shutdown(fd, SHUT_WR)` leaves the
  socket **readable** and `SHUT_RD` leaves it **writable**, so a state machine treating "peer
  closed" as "connection over" keeps processing data arriving in the half-closed window, or frees
  per-connection state a later read still touches — and a peer that half-closes rather than closing
  can hold a connection slot open indefinitely.

### Concurrency

- **`race-condition`.** Check-then-act on anything another actor can change between the two steps: a
  filesystem path, a shared counter, a cached pointer. **Double-fetch** is the memory version —
  reading an attacker-writable location twice and assuming the reads agree, so the validated value
  is not the used value. Also lock scope ending before the compound operation does.
- **`thread-safety`.** `gethostbyname`, `inet_ntoa`, `strtok`, `strerror`, `localtime`, `gmtime`,
  `ctime`, `asctime`, `getpwnam`, `getgrnam` and `readdir` return pointers to **static storage** the
  next call from *any* thread overwrites — the bug is not the call, it is the window between the
  call and the consumption of the result. `pthread_spinlock_t` has **no static initializer**, so a
  spinlock reached on a path that skipped `pthread_spin_init` (or whose init return was ignored) is
  used uninitialized; same shape for a mutex whose `pthread_mutex_init` failed unchecked. Only
  relevant if the process actually creates threads.
- **`signal-handler`.** A handler may call only async-signal-safe functions. `malloc`/`free`
  reentered from a handler corrupts the allocator; stdio reentered corrupts its lock and buffers;
  `longjmp` out of a handler leaves everything indeterminate. A handler must also **save and restore
  `errno`**. The safe shapes are: set a `volatile sig_atomic_t` flag, or `write()` one byte to a
  self-pipe.

### Ambient state and DoS

- **`access-control`.** An operation that changes state or returns data on behalf of a principal
  with no check that the principal is entitled — or a check performed on a **different value** than
  the one used. Includes capability and descriptor leaks across a privilege boundary.
- **`privilege-drop`** (`LOCAL_UNPRIVILEGED`). `setuid()` from a non-root effective uid can **fail
  while returning a value nobody checks**, leaving the process privileged. `seteuid()` alone leaves
  the saved-set-uid, so privileges can be regained; `setresuid(uid,uid,uid)` is the complete form.
  Groups must be dropped **before** the user, and `setgroups()` must be called to clear the
  supplementary set. Verify by reading the ids back.
- **`envvar`** (`LOCAL_UNPRIVILEGED`). A privileged process trusting a variable for a path or a
  library location. A secret in the environment, where any process that can read
  `/proc/<pid>/environ` sees it. `setenv` leaving the previous value reachable. A child inheriting
  an environment never sanitized.
- **`time-issues`.** Wall-clock time used to measure a duration — an expiry or rate limit the clock
  stepping backwards defeats. 32-bit `time_t` overflow. Comparisons assuming 86400-second days
  across a DST or leap-second boundary. Only report where the wrong answer has a security
  consequence.
- **`dos`.** Unbounded allocation, unbounded recursion, superlinear algorithms driven by input size.
  **Recursion depth is the highest-yield one in parsers**: a depth counter that exists but is never
  compared against a limit; a limit counting only one of several recursive paths; an amplification
  guard a linear chain slips under. Hash-collision floods and regex backtracking belong here.
  This is a **countable population** — enumerate *every* recursive construct before writing the
  class off; filing one stack-exhaustion bug does not cover the class, because the same file can
  hold others.

### Build hardening

- **`exploit-mitigations`.** Read the actual build files. The interesting failure is not an absent
  flag but a **misspelled** one — `_FORTIFY_SORUCE`, `-fstack-protector-stong`,
  `_GLIBCXX_ASSERTONS` — because a typo in a `-D` or `-f` flag is accepted **silently** and the
  mitigation is simply off while the build looks hardened. Also check the flag reaches the shipped
  target, not only a sample or test build. Confirm the result on the binary with `checksec`.

### Library API contract misuse

- **`qsort`.** glibc `qsort` trusted its comparator to be a valid ordering; an inconsistent one
  walks the merge **past the array** (CVE-2023-6246 family, Qualys 2024). Inconsistency sources:
  subtracting `int`s, which overflows; comparing only a prefix or one field of a record; floating
  point, where NaN makes every comparison false; and a multi-key comparator returning 0 for
  distinct records. The safe form is `(a > b) - (a < b)`. Note `qsort`/`bsearch` are ISO C, not
  POSIX — do not gate this class on a POSIX check.
- **`regex-issues`.** Backtracking blowup from nested or overlapping quantifiers on attacker input.
  Bypasses: an **unanchored** pattern used as if it were a whole-string test, and POSIX `regexec`
  matching per line unless `REG_NEWLINE` semantics are considered — so an embedded newline can hide
  the rest of the input from a check.
- **`va-start-end`.** Every `va_start` and every `va_copy` needs a matching `va_end` before return,
  **including on early-error paths**. Reusing a `va_list` after one `v*printf` consumed it is
  undefined; a second consumer needs `va_copy`.

### Logic, protocol and crypto

- **`logic-flaw`.** Everything memory-safety taxonomies do not name — and often the highest-yield
  class, because it catches the bugs that fit no other label. Namespace or **delimiter injection**,
  where a separator the format reserves is accepted inside a value and re-emitted, so the two ends
  parse it differently. Protocol state machines accepting a message in a state that skips
  authentication or size negotiation, or returning success on a path meant to signal "need more
  input". Deserialization letting input choose a type or a size. Off-by-one in an
  index-to-identity mapping. Two named patterns worth hunting explicitly:
  **validated-value substitution**, where one value is checked and a *different*, unchecked one
  reaches the sink (validation applied to a normalized copy while the raw value is used downstream
  is the same shape); and **call-site invariant**, where a shared macro or helper enforces a
  well-formedness rule at *some* expansion sites and not all, so one path admits input the others
  reject. Also: a value read out of a header or length field and stored into state without being
  checked against the bound the rest of the code assumes. These are found by reading what a value is
  **allowed** to be, then asking what the code does with a value one step outside that.
- **`crypto-misuse`.** Correct primitives assembled wrongly. A nonce or IV reused across two
  messages under one key, or derived from a counter that resets when the process does. One key
  serving two purposes, or a long-term key where an ephemeral one belongs. Secrets, MACs or tags
  compared with `memcmp`/`strcmp`, which returns early and leaks position. Ciphertext decrypted
  before its tag is checked, or a tag never checked. ECB, or any unauthenticated mode over
  attacker-influenced plaintext. Keys or salts from `rand`/`srand`, `time`, a PID, or a hardcoded
  constant instead of a CSPRNG. A KDF with no salt or a trivial iteration count. Padding or
  signature verification whose failure path returns the **same value** as success. Judge the
  construction against what the primitive requires **of its caller**, not against whether the
  primitive is sound.

### C++ lifetime (gate: real C++)

- **`smart-pointer`.** Two independent `shared_ptr` control blocks built from **one raw pointer**
  (double free); a raw pointer or reference handed out of a `unique_ptr` and outliving it;
  `shared_ptr` cycles; a `weak_ptr::lock()` result used without checking.
- **`move-semantics`.** A moved-from object is valid but **unspecified**. Security-relevant shape: a
  buffer or key moved out and then read as if it still held the data; and a `std::move` inside a
  loop moving the same object every iteration.
- **`lambda-capture`.** A lambda stored in a callback, a thread, or a coroutine that captured a local
  by reference — or captured `this` — and now outlives it. `[=]` on a member function captures
  `this` **by value, not the members**, which is a common surprise.
- **`iterator-invalidation`.** Any `vector`/`string` growth invalidates **every** iterator, pointer
  and reference into it, including one held across a function call that appends. Erasing inside a
  loop without taking the returned iterator. `unordered_` containers invalidate iterators on rehash
  but keep **references** valid — the asymmetry causes real bugs.

### C++ class semantics (gate: real C++)

- **`init-order`.** A namespace-scope object in one TU whose constructor reads one defined in another
  has **no defined order**. Member initializers run in **declaration** order, not the order written
  in the list. Observable failure: a security check reading a not-yet-initialized table.
- **`virtual-function`.** A virtual call in a constructor or destructor dispatches to the class being
  constructed, **not** the derived override — so a derived-class invariant check silently does not
  run. Deleting through a base pointer with no virtual destructor. Object slicing on assignment to
  a base value.
- **`exception-safety`.** A resource acquired between a `try` and the RAII wrapper that would release
  it; a destructor that can throw (`terminate` during unwind); a `noexcept` function whose callee
  throws. Security shape: a lock or a privilege left held, or a half-updated invariant observed
  after the handler.

### Windows (gate: Windows)

- **`createprocess`.** An **unquoted** `lpApplicationName`/`lpCommandLine` path with spaces lets
  `C:\Program.exe` run instead of the intended target. `bInheritHandles = TRUE` hands **every**
  inheritable handle to the child.
- **`cross-process`.** `OpenProcess`/`ReadProcessMemory`/`WriteProcessMemory` against a **recyclable**
  PID, or a handle obtained without verifying the target's identity. Duplicating a handle into a
  lower-privileged process with more access than intended.
- **`token-privilege`.** Impersonation not reverted on **every** path, error paths included.
  `ImpersonateNamedPipeClient` without first checking the client is who is expected. Privileges
  enabled and left enabled. A `SECURITY_DESCRIPTOR` with a **NULL DACL**, which grants everyone full
  control — not the same as an *empty* DACL, which grants no one.
- **`service-security`.** A service binary or its directory writable by non-admins; a service ACL
  allowing `SERVICE_CHANGE_CONFIG` to a non-admin (the binary path can then be rewritten); an
  unquoted `ImagePath` with spaces.
- **`dll-planting`.** `LoadLibrary` with a bare name, or an implicit import of a DLL not present in
  System32, resolves through a search order that includes the application directory and — without
  `SetDefaultDllDirectories` — the current directory. Use a fully qualified path or
  `LOAD_LIBRARY_SEARCH_SYSTEM32`.
- **`windows-path`.** Path checks defeated by 8.3 short names, alternate data streams, a trailing dot
  or space the filesystem strips, the `\\?\` prefix that **skips normalization**, device names
  (`CON`, `NUL`), and UNC paths reaching a check written for local paths. Case-insensitivity plus
  Unicode folding defeats string prefix tests.
- **`installer-race`.** A privileged installer writing to or executing from a user-writable
  directory, or extracting to a temp directory **before** setting its ACL. The window between
  create and ACL-set is the bug.
- **`named-pipe`.** A server that does not create the pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` can be
  **squatted** by a client that created the name first. A server impersonating a client without
  validating it, or a client connecting without
  `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, can be impersonated by a malicious server.
- **`windows-crypto`.** Deprecated CryptoAPI with weak algorithms; a static or zero IV; RSA without
  OAEP; a key derived from a password with no KDF; `CryptGenRandom` replaced by `rand`. Also
  `CryptProtectData` used for data crossing a trust boundary it does not protect.
- **`windows-alloc`.** Mixing allocator families (`HeapAlloc` freed with `free`, `LocalAlloc` freed
  with `HeapFree`, `CoTaskMemAlloc` freed with `delete`). Size arithmetic that can overflow before
  `HeapAlloc`. `HEAP_ZERO_MEMORY` assumed but not passed.

## Enumeration Commands

```bash
# Units and denominator (a coverage claim needs one)
tokei . ; rg -c '^\w[\w \*]*\([^;]*\)\s*\{?\s*$' --glob '*.c' --glob '*.cpp' | sort -t: -k2 -rn | head

# Platform and dialect, from API usage rather than extension
rg -l 'pthread_|<unistd\.h>|sys/socket\.h' ; rg -l 'windows\.h|CreateProcess|HeapAlloc'
rg -l 'std::|template\s*<|namespace\s+\w+\s*\{' --glob '*.cpp' --glob '*.cc' --glob '*.hpp'

# Class-evidence sweeps (does a candidate site exist at all?)
rg -n '\b(strcpy|strcat|sprintf|vsprintf|gets|stpcpy|alloca|putenv|mktemp|tmpnam|tempnam|strtok)\s*\('
rg -n '\b(snprintf|vsnprintf|asprintf)\s*\(' ; rg -n '\b(scanf|sscanf|fscanf)\s*\('
rg -n '\bmemcpy\s*\(|\bmemmove\s*\(|\bmemset\s*\(' ; rg -n '\bstrncpy\s*\(|\bstrncat\s*\('
rg -n '\brealloc\s*\(' ; rg -n '\bqsort\s*\(|\bbsearch\s*\('
rg -n '\baccess\s*\(|\bopen\s*\(|\bopenat\s*\(|\bcreat\s*\('
rg -n '\bsignal\s*\(|\bsigaction\s*\(' ; rg -n '\bva_start\b|\bva_copy\b'
rg -n '\bsetuid\b|\bseteuid\b|\bsetresuid\b|\bsetgid\b|\bsetgroups\b|\bgetenv\b'
rg -n '\bconnect\s*\(|\bshutdown\s*\('
rg -n 'struct\s+\w+\s*\{[^}]*\b\w+\s*\[\s*[01]\s*\]\s*;\s*\}' -U     # flexible-array/struct-hack
rg -n '_FORTIFY|stack-protector|relro|_GLIBCXX_ASSERT|-fPIE|-Wl,-z' -g 'Makefile*' -g '*.cmake' -g 'CMakeLists.txt' -g 'meson.build' -g 'configure*'

# Syntax-aware, where grep cannot reach (weggli is installed)
weggli '{ char $b[_]; strcpy($b, _); }' .
weggli '{ $len = _; memcpy(_, _, $len); }' .
weggli -u '{ malloc($n * _); }' .
weggli '{ free($p); not: $p = _; _($p); }' .
weggli '{ $n = strlen(_); malloc($n); }' .
```

Then escalate exactly as far as the question needs — `rg` → `weggli` → Semgrep → CodeQL/joern —
per `source-audit`. All of it produces **hypotheses**; none of it produces findings.

## Severity and False-Positive Discipline

- A **banned-API sighting with no traced flow** is a hardening note, not a vulnerability.
- A **SAST hit with no backward taint walk** is not a candidate yet.
- A bug in **validation or bounds-checking code itself**, in error handling, in cleanup, or in a
  `#[cfg(test)]`-equivalent test/debug-only path is almost always a false positive — verify the
  path ships.
- A vulnerable-looking site whose **reachability conditions mathematically prevent** the vulnerable
  case is a false positive with an *algebraic* refutation: `buffer[length-4]` is safe if the site is
  only reachable when `length > 12`. Write the algebra down.
- **Do not claim TOCTOU without proving the checked value can change**, and do not claim a race in a
  single-threaded or fully synchronised context.
- Understand the **API contract** before claiming an overflow — some APIs cannot write beyond the
  buffer regardless of the parameters.

Run every candidate through `false-positive-refutation` before it enters the report.

## Cross-references

- Whole-tree audit workflow, tool escalation, taint tracing, coverage ledger → `source-audit`
- Understanding the code before hunting in it → `audit-context-building`
- Refuting a candidate → `false-positive-refutation`
- The other instances of a confirmed bug → `variant-analysis`
- Instrumented builds, ASan/UBSan/MSan/TSan, coverage → `sanitizers-and-coverage`
- A harness for a parser you just mapped → `fuzzing-harness-design`; crash triage → `fuzzing-triage`
- Runtime proof of a traced path → `dynamic-verification`
- Class → exploit primitive → technique → `bug-class-catalog`, then `exploit-dev`
- Timing channels and secrets left in memory → `crypto-side-channel-audit`
- Footgun APIs and fail-open defaults in the code you are reviewing → `sharp-edges-and-insecure-defaults`
- Rust peer of an FFI boundary → `rust-security-audit`
