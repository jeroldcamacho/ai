---
name: rust-security-audit
description: Rust security review across the safe/unsafe boundary — unsafe-block memory safety, panic-driven DoS, concurrency and data races, FFI, and trait-contract bugs. Use when auditing a Rust crate, binary, or workspace, or when deciding whether a memory-corruption claim in safe Rust is real.
---

# SKILL: Rust Security Audit

Rust review is not C review with different syntax. The compiler removes whole bug classes, so a
finding must first survive the question **"what did the type system already prevent?"** — and the
bugs that remain cluster in five specific places: `unsafe` blocks, panic paths, concurrency
primitives, FFI boundaries, and hand-written trait impls.

Language-specific *reachability* is the discriminator. In C every write is suspect. In Rust the
suspect set is small and enumerable, so this skill is organised as a gated sweep: establish which
gates are open, then work only the clusters those gates unlock.

## The Rejection Rule (apply before filing anything)

**Memory corruption in safe Rust is a false positive.** Before filing UAF, double free, OOB
write, uninitialized read, or type confusion, prove one of:

- the site is inside an `unsafe` block or an `unsafe fn`, or
- it is a **safe caller of an unsafe primitive** whose arithmetic the unsafe block trusts, or
- it crosses FFI (`extern`, `bindgen`, `cbindgen`, JNI, PyO3, napi-rs, cgo peer), or
- it is a shared-memory mapping another process can write (`MAP_SHARED`, `shm_open`, `memfd`), or
- you are claiming a compiler/`std` soundness hole, which needs a rustc issue number.

None of those hold → the claim is rejected, and the rejection is the result. Say so explicitly;
"safe Rust, borrow checker prevents this" is a complete refutation and costs one line.

What *does* remain in safe Rust: **panic-DoS, logic bugs, resource exhaustion, TOCTOU, path
traversal, deadlock, information disclosure, and every injection class.** Those are the safe-code
findings, and they are where a Rust audit that only greps `unsafe` finds nothing.

## Phase 0 — Gates

Run these first; each one turns whole clusters on or off. A cluster whose gate is closed is
reported as *out of scope by construction*, not as *swept clean*.

```bash
tokei .                                                   # crate size, so scope is honest
rg -n --stats 'unsafe\s*(\{|fn|impl)'                     # gate: has_unsafe
rg -n 'extern\s+"(C|system|stdcall|cdecl|win64|sysv64|aapcs|fastcall|thiscall|vectorcall|efiapi)(-unwind)?"|extern\s*\{|\bextern\s+fn\b'
rg -n 'bindgen|cbindgen|pyo3|napi|jni|cxx::|\bcc::Build\b' --glob '!target'   # gate: has_ffi
rg -n '\basync\s+fn\b|\.await\b|tokio::|futures::'        # gate: has_async
rg -n 'thread::spawn|rayon::|Atomic(Bool|Usize|U\d+|I\d+|Isize|Ptr)|static\s+mut' # gate: has_concurrency
rg -n '#\[repr\([^\]]*packed'                             # gate: has_packed
rg -n 'MAP_SHARED|shm_open|memfd_create'                  # gate: has_shmem
rg -n 'no_std|#!\[no_std\]'                               # changes panic and alloc behaviour
```

Then read the manifest, because two settings change the severity of every panic finding and one
changes the severity of every arithmetic finding:

```bash
rg -n 'panic\s*=|overflow-checks|debug-assertions|\[profile\.release\]|\[lints\]|opt-level' Cargo.toml
cat Cargo.toml | rg -n '^\[dependencies|^\[dev-dependencies|^\[build-dependencies' -A 40
```

| Manifest fact | What it changes |
|---|---|
| `panic = "abort"` in release | `catch_unwind` is a **no-op**: every reachable panic is a whole-process DoS, and an "it's guarded" refutation fails |
| `panic = "unwind"` (default) | `catch_unwind` counts as recovery — *except* across FFI, and never for stack overflow |
| `overflow-checks = true` in release | integer overflow is a panic → DoS; false → silent wrap → corruption. Both are findings, at different severities |
| `debug-assertions = false` (release default) | `debug_assert!` is inert; do not file it. `assert!`/`unreachable!`/`todo!` still fire |
| `#![no_std]` | allocation failure can unwind; `Drop`-panic reasoning changes |

Establish the toolchain too: `rustc --version`, and the crate's MSRV (`rust-version` in
Cargo.toml). Several of the rules below are version-gated — see **Version Gates**.

## Cluster 1 — Memory safety (gate: `has_unsafe`)

One mental model covers all of it: **for each unsafe block, who owns the memory, when does it
Drop, and who else points at it?** Empirically, production Rust memory-safety bugs all propagate
across the safe/unsafe boundary — the unsafe block is where it detonates, the safe arithmetic
above it is usually where it is wrong.

| ID | Shape | Gates that must all pass |
|---|---|---|
| `UAF` | Raw pointer extracted with `.as_ptr()`/`.as_mut_ptr()`/`transmute`, source Dropped at end of scope (temporaries in `match` arms and `if let` bindings are the classic), pointer dereferenced after | extraction; the backing allocation is freed; deref is chronologically after the free; no `mem::forget`/`ManuallyDrop`/`Box::leak` neutralised the Drop |
| `DFREE` | `ptr::read` makes a **bitwise copy without moving** the source. For an owning type (`String`, `Vec`, `Box`, `Rc`, any `Drop`) there are now two owners and the destructor runs twice | both copies reach a Drop; no `mem::forget` on either |
| `INVFREE` | `alloc()` returns uninitialised memory; `*ptr = new_val` Drops the *previous* value to avoid a leak — and the previous value is garbage bytes | assignment through a raw pointer into uninitialised storage of a `Drop` type; use `ptr::write` instead |
| `UNINITREAD` | `MaybeUninit::assume_init`/`assume_init_ref`/`assume_init_mut` before every field is written. Also `mem::uninitialized::<T>()`, UB for essentially every `T` — **integers included** (rustc's `invalid_value` lint: "integers must be initialized"). `mem::zeroed` is a *different* bug: invalid-value for `NonNull`, references, most enums — but sound for `bool`, whose all-zero byte is `false` | at least one field/byte unwritten on some path before the read |
| `SETLEN` | `Vec::set_len`, `spare_capacity_mut` + `set_len`, or `Vec::from_raw_parts` commits a `len` counting uninitialised slots; the vector's *safe* API then treats them as valid `T` | `new_len > old_len`; a slot in `old_len..new_len` has no dominating init on all paths; slots reachable through safe code (slice deref, indexing, `Drop`, `io::Read` into `&mut vec[..]`, or a `pub` return) |
| `BOF` | Safe code computes an offset/size/index and hands it to `get_unchecked(_mut)`, `copy_nonoverlapping`, `ptr::write`, or a raw-pointer `.add()`/`.offset()`/`.sub()`. The unsafe block trusts the boundary; the safe arithmetic is wrong | the computed value can exceed the allocation; nothing between clamps it |
| `UNIONUB` | Reading a union field other than the last written reinterprets the active variant's bits as the read type. Worst form: a `&T` field read after a `u64` write yields a possibly-dangling reference | the write/read pair is reachable with mismatched tags |
| `PANICUNWIND` | A safe-facing type keeps `len`/capacity/init-count updated through `unsafe`; a panic mid-mutation unwinds while the invariants still describe the pre-mutation layout, so a later `Drop`/`clear`/`into_iter` revisits freed slots → double free or UAF | a panic is reachable inside the window; no unwind guard commits the invariant first |

Notes that decide the label: `.as_ptr()`/`.as_mut_ptr()`/`transmute` leave the source alive and
let scope-exit `Drop` free it; `Box::into_raw` / `Vec::into_raw_parts` **consume** the source and
*suppress* that Drop, so a UAF on an `into_raw` pointer needs an explicit later
`from_raw`/`dealloc`. A leaked `into_raw` that is never re-owned is a leak, not a UAF; re-owned
*twice* is `DFREE`. `offset`/`add`/`sub`/`read`/`write` are **methods** on raw pointers —
`ptr::offset` and `ptr::add` do not exist, so grep the method form.

```bash
rg -n '\.(as_ptr|as_mut_ptr)\(' ; rg -n '\b(Box|CString)::into_raw\b|Vec::into_raw_parts|\btransmute\b'
rg -n 'ptr::(read|write|copy(_nonoverlapping)?|drop_in_place)|\.(offset|add|sub|read|write)\s*\('
rg -n '\bset_len\s*\(|\bfrom_raw_parts\s*\(|\bspare_capacity_mut\s*\('
rg -n 'MaybeUninit|assume_init|mem::(uninitialized|zeroed)'
rg -n '\bget_unchecked(_mut)?\s*\(|\bunion\b'
```

## Cluster 2 — Panic-driven DoS (no gate; this is the safe-code cluster)

A reachable panic on attacker input is a real availability finding, and it is the highest-yield
class in safe Rust. Severity is set by the `panic` profile from Phase 0.

- **`UNWRAP`** — `.unwrap()` / `.expect()` / `.unwrap_err()` on a `Result`/`Option` produced by
  parsing, decoding, or looking up external input (HTTP body, file content, IPC, CLI arg, env
  var, serde). Reject when the producing path is statically infallible (a hardcoded `&str`), when
  it is in `#[cfg(test)]`, or when an `is_ok()`/`is_some()` check immediately precedes it.
  `catch_unwind` counts as recovery **only** under `panic = "unwind"` and only when the panic does
  not cross FFI.
- **`ARITHOFL`** — `+ - * << >>` and unary `-` on an integer derived from external input with no
  `checked_*`/`saturating_*`/`wrapping_*`/`overflowing_*` wrapper; plus truncating `as` casts
  (`u64 as u32`). Separately and **independently of `overflow-checks`**: `/` and `%` with an
  attacker-reachable zero divisor, and `i::MIN / -1`. Those panic in *every* profile, and
  `wrapping_div`/`saturating_div`/`overflowing_div` (and the `_rem` forms) **still panic on zero**
  — only `checked_div`/`checked_rem` are safe.
- **`OOBIDX`** — bracket indexing `v[i]` on `Vec`/slice/array where `i` comes from untrusted
  input with no reachable `i < len` guard, or where the guard arithmetic itself can overflow.
  `.get(i)` is the fix.
- **`RECURSEDES`** — a recursive type deserialised from untrusted input with no depth limit:
  `serde_json`/`serde_yaml`/`toml`/`ron`/`ciborium`/`bincode`/`postcard` entry points, or a
  `#[derive(Deserialize)]` type reached through `axum::Json`, `actix_web::web::Json`,
  `rocket::serde::json::Json`, `warp::body::json`, or `prost` decode. Library recursive types
  count: `serde_json::Value`, `serde_yaml::Value`, `toml::Value`, `ron::Value`, `syn::*`.
- **`RECURSEDROP`** — the Rust footgun most audits miss. Dropping a `Box<Self>`/`Vec<Self>`-chained
  structure of depth N consumes N stack frames **after the function returns** — the overflow
  happens at the closing brace, often in a request handler, far from any visible recursion, and
  **even for a request that was rejected and errored out**. Stack overflow is not catchable:
  `catch_unwind` does not trap it and `panic = "unwind"` does not help. Gate: type is recursive,
  has no hand-written *iterative* `Drop`, is reachable from untrusted input, and nothing caps
  depth before storage. (rust-lang/rust#58068, still open.)
- **`RECURSEFMT`** — the same shape through a recursive `Display`/`Debug` impl.
- **`REFCELLPANIC`** — `RefCell::borrow`/`borrow_mut` (usually behind `Rc<RefCell<_>>`) panics when
  an incompatible borrow is live. Reentrancy through callbacks, observers, recursion, or a `Drop`
  running while a borrow is held — with attacker-controlled call ordering — turns a logic slip
  into a DoS.
- **`ASSERTREACH`** — `assert!`/`assert_eq!`/`panic!`/`unreachable!`/`unimplemented!`/`todo!`
  reachable from a `pub fn` or trait impl, or whose condition untrusted input can falsify. Not
  gated by `#[cfg(test)]`/`#[cfg(debug_assertions)]`. Skip `debug_assert!` unless
  `debug-assertions = true` in the profile you are auditing.
- **`DROPPANIC`** — a panic inside `impl Drop`: `.unwrap()`, arithmetic, indexing, `assert!`. If it
  fires during unwinding from another panic the process **aborts**; if it fires holding a
  `MutexGuard` the mutex is **poisoned** and every downstream `.lock().unwrap()` panics too — a
  propagating DoS. Allocation is *not* a panic source under `std` + the default allocator
  (allocation failure calls `handle_alloc_error`, which aborts without unwinding); under `no_std`
  or a custom alloc-error hook it is.
- **`CLOSUREPANIC`** — a library that invokes a caller-supplied closure *between* two unsafe
  operations (`ptr::read` … `f(x)` … `ptr::write` completing the move). A panic in `f` leaves
  duplicated ownership or a poisoned invariant. Fix with `scopeguard::guard` +
  `ScopeGuard::into_inner` (dismiss-on-success) or `ManuallyDrop` — **not** bare
  `scopeguard::defer!`, which runs on success too and double-completes the move.
- **`RESEXHAUST`** — availability loss without a panic: attacker-controlled `n` driving unbounded
  iteration, O(n²) amplification, uncapped allocation, or unbounded channel growth.
- **`DROPSKIP`** — `process::exit`, `mem::forget`, or `ManuallyDrop` bypassing a `Drop` that does
  security-relevant cleanup (commit/rollback, flush, unlock, close).
- **`BUFFLUSH`** — a `BufWriter` dropped without an explicit `flush()`; the implicit flush in
  `Drop` discards its error, so a write failure is silently swallowed.

## Cluster 3 — Concurrency

**Locking** (gate: any `Mutex`/`RwLock`). Per the empirical study, **30 of 38** Rust deadlocks are
double-lock caused by misunderstanding `MutexGuard` lexical scope — a guard lives to the end of
its enclosing block, so a second `lock()` on the same mutex in that block self-deadlocks. Then:
ABBA ordering across two locks, condvar misuse (no predicate loop → spurious-wakeup bug),
channel starvation, and `Once` reentrancy. Build the lock map once, then check each acquisition
against it.

**Data races** (gate: `has_concurrency`). A large share of these are entirely in **safe code**:

- **`ATOMICRACE`** — `let v = a.load(..); if v == X { a.store(Y, ..); }` is two independent
  operations, and another thread races the gap. Needs `compare_exchange`/`fetch_update`. Reject
  when only one thread ever stores (single-writer), when the pair sits inside a held lock, or when
  a CAS already does the update.
- **`UNSAFESYNC`** — a manual `unsafe impl Send`/`Sync for W {}` over a payload that is not
  thread-safe (raw pointer, `UnsafeCell`, a handle to single-threaded foreign state). Unsound
  through *either* unsynchronised interior mutation via `&self` **or** simply making the payload
  transferable with no Rust-side mutation at all.
- **`SENDSYNCBOUND`** — distinct from the above and much narrower. A direct
  `thread::spawn`/`tokio::spawn`/`rayon::spawn` already requires `Send + 'static`, so a wrapper
  that "forgets" the bound simply does not compile — **not a bug**. The unsound shapes launder
  the bound through `unsafe`: raw `thread::Builder` + `transmute`, an FFI thread-create,
  `thread::scope` misuse, or a `transmute` fabricating the bound.
- **`STATICMUT`** — `static mut` is one process-wide alias with no borrow checking; any concurrent
  access without `Mutex`/`RwLock`/`Atomic*`/`Once` is a data race and immediate UB. Rust 2024's
  `static_mut_refs` lint (deny-by-default) blocks `&FOO`/`&mut FOO` and method autoref only — it
  does **not** make `&raw mut`, `addr_of_mut!`, `ptr::read`, or `ptr::write` access sound.
- **`SHMRACE`** (gate: `has_shmem`) — Rust's aliasing model assumes the process owns its address
  space. A region mapped `MAP_SHARED` with another process makes ordinary `&mut T` borrows unsound
  regardless of intra-process synchronisation. The only sound pattern is raw pointers or
  `UnsafeCell` plus atomics, with a `// SAFETY:` comment naming the peer and its protocol.

**Async** (gate: `has_async`):

- **`ASYNCBLOCK`** — a blocking call inside `async fn`: `std::sync::{Mutex,RwLock}::lock`,
  `std::fs::*`, `thread::sleep`, `std::net::*`, a blocking channel `recv()`. Two caveats that
  break the obvious refutation: `block_in_place` **panics** on a `current_thread` runtime, so it
  is not a universal clear; and neither `spawn_blocking` nor `block_in_place` fixes a
  `std::sync` guard held *across* an `.await` — the guard is `!Send` and its lifetime spanning the
  await *is* the defect. Fix that one with `tokio::sync::Mutex` or by dropping the guard first.
- **`CANCELSAFETY`** — `state.partial_write(); some_async().await; state.commit();` — cancellation
  at the `.await` (a `select!` losing branch, a dropped future, a timeout) leaves state
  half-written. Anything inside a `tokio::select!` branch must be cancel-safe.
- **`SELECTBIAS`** — `select!` polls in a fixed or biased order; a always-ready branch starves the
  others.

## Cluster 4 — FFI (gate: `has_ffi`)

- **`CSTRDANGLE`** — `let p = CString::new("x")?.as_ptr(); c_fn(p);` — the `CString` temporary
  Drops at the end of the `let` statement, so `p` dangles at the call. Bind the `CString` first.
- **`ABIMISMATCH`** — the `extern "C"` declaration's types or arity disagree with the actual C
  header (find it via the `bindgen` build script, a vendored `.h`, or a comment). Not a finding
  for `c_int` vs `i32` on common targets, or `*mut T` vs `*mut c_void` in a handle pattern.
- **`REPRCPAD`** — a `#[repr(C)]` struct crossing FFI whose padding or field order does not match
  the peer's layout, so reads land on the wrong bytes.
- **`DYNFFI`** — `&dyn Trait`, `Box<dyn Trait>`, `&[T]`, `&str` are **fat pointers**
  (data + vtable, or data + len) with `#[repr(Rust)]` layout that is not an ABI guarantee: it can
  change between compiler versions and cannot be reconstructed on the C side. Passing one through
  `extern "C" fn` or storing one in a `#[repr(C)]` struct that crosses FFI is unsound.
- **`OPAQUEPTR`** — a handle allocated and owned by the C side is used after the matching
  `lib_free`/`lib_destroy` ran, or handed to the free function twice. Use-after-free of the
  *handle identity*, with no Rust-allocated memory involved. Refuted when the handle is held in
  `Option<NonNull<_>>` and `take()`n on free.
- **`FOREIGNDROP`** — a Rust `Drop` (or auto-derived `Box`/`Vec` ownership) routes a pointer from a
  **foreign allocator** — `libc::malloc`, `g_malloc`, `CFAllocator`, `LocalAlloc`,
  `CoTaskMemAlloc`, `cudaMalloc`, PyO3/napi-rs/JNI VM allocators — through the *Rust* global
  allocator via `Box::from_raw` / `Vec::from_raw_parts` / `dealloc`. Invalid free at the allocator
  level.
- **`CLOSUREFFI`** — a Rust closure registered as a C callback. A panic unwinding across
  `extern "C"` was UB before rustc 1.81 and is a process **abort** since (a *compiler* version
  change, not an edition change — edition-2021 code on rustc ≥ 1.81 already aborts), which is
  still a server DoS. Two derivatives: captured `&'a T` outliving its scope when C invokes the
  callback later, and a `Box<dyn FnMut>` `into_raw`'d as user-data with no paired `from_raw` in
  the deregister path.
- **`RAWFD`** — `RawFd` is a bare `i32`; ownership is convention, not type. Double-close (two
  `from_raw_fd` owners, or an `as_raw_fd()` borrow fed to `from_raw_fd`) makes the second `close`
  hit a *recycled* fd number now naming an unrelated resource. Missing-close leaks the fd table
  to exhaustion. Same reasoning for Windows `RawHandle`/`RawSocket`.
- **`PACKEDREF`** (gate: `has_packed`) — `#[repr(packed)]` removes padding, so a field with
  alignment > 1 can be misaligned; Rust requires every `&T` to be aligned *at creation*, not only
  at deref. `&s.field`, `println!("{}", s.field)`, a `&self` method call on the field, and
  `match &s.field` all borrow implicitly and are UB. Modern rustc rejects these as hard error
  `E0793` — the old `unaligned_references` lint *became* that error, so `#[allow(...)]` is now a
  no-op. These survive only in macro-generated borrows and pre-error snapshots.

## Cluster 5 — Logic, correctness and disclosure (no gate)

- **`ORDEQHASH`** — a hand-written `Ord`/`PartialOrd`/`Eq`/`PartialEq`/`Hash` that violates
  `a == b ⟹ hash(a) == hash(b)`, total-order consistency, reflexivity/symmetry/transitivity, or
  NaN handling. Consequence: `HashMap`/`BTreeMap` corruption — missing keys, permanent leaks,
  infinite loops in std internals. Watch for a hand/derive **split** across these traits.
- **`KEYMUT`** — a key already inside a `HashMap`/`HashSet`/`BTreeMap`/`BinaryHeap` mutated so its
  `Hash`/`Eq`/`Ord` changes, via interior mutability in the key (`Cell`, `RefCell`, `Mutex`,
  atomics). Note `BinaryHeap::peek_mut` re-sifts on drop, so an ordinary `peek_mut` mutation is
  safe — corruption needs `mem::forget` on the `PeekMut` guard.
- **`TRAITADV`** — an **adversarial trait impl**. A library takes `T: Read`, sizes a buffer from
  `T::read()`'s reported count, and writes through unchecked unsafe; a hostile
  `impl Read for Evil` over-reports and produces an OOB write. Any generic API that trusts a
  user-supplied impl's return value for a size, length, or bound is this bug.
- **`STRCMP`** — `starts_with`/`ends_with`/`contains` where `==` was required, so `"/admin"`
  matches `"/admin-public"`; or case-sensitive `==` mixed with `eq_ignore_ascii_case` across the
  same value class (host, path, extension).
- **`PATHJOIN`** — `Path::join`/`PathBuf::push` **silently replaces the whole path** when the
  argument is absolute, and `..` components escape the base. Both are traversal with
  attacker-controlled arguments.
- **`TOCTOU`** — `exists`/`metadata`/`symlink_metadata`/permission test followed by a separate
  `File::open`/`create`/`remove_file` on the same path; the window admits a symlink swap.
- **`LOSSYSTR`** — `from_utf8_lossy` / `to_string_lossy` / `to_str().unwrap_or_default()` substitute
  U+FFFD instead of failing. When the bytes come from a filesystem entry, `args_os`, `var_os`, or
  the network and the result then drives a filesystem operation, an allowlist, a dedup key, or an
  auth token, divergence from the real bytes is the bug. Display-only use is a false positive.
- **`LOSSYFROM`** — a narrowing `From`/`as` conversion (narrower int, signed→unsigned,
  float→int) on a length field, capability check, token, or ID lookup. `TryFrom` is the fix.
- **`FLOATEDGE`** — `f32`/`f64` on input data whose result becomes a length, an index via
  `as usize`, an authorization comparison, or a serialization size, with no
  `is_finite()`/`is_nan()` guard. `f64 as usize` has been a **defined saturating cast** since Rust
  1.45 (NaN→0, +Inf→`usize::MAX`, negatives→0) — not UB. The hazard is the silent saturation: a
  zero-length buffer, or an allocation of `usize::MAX`.
- **`NONDET`** — logic that must be deterministic (consensus, replicated state, a signature or
  hash over serialized data, reproducible output) iterating a `HashMap`/`HashSet`. Traversal order
  is randomised **per instance** — two maps built identically in the *same* process iterate
  differently. Float bit patterns, pointer addresses, and `usize`/`c_char` width also leak in.
- **`SERFIELDS`** — a manual `Serialize` whose declared count disagrees with the fields emitted on
  some path. The impact is **format-dependent**: for `serialize_seq`/`serialize_map`, bincode
  writes the declared `Some(N)` as the element-count prefix, so a wrong `N` misframes the payload;
  for `serialize_struct`/`serialize_tuple`, bincode and postcard **ignore** the count (arity comes
  from the type), so it is inert there and only corrupts formats that emit a per-struct header —
  MessagePack (`rmp-serde`) and CBOR (`ciborium`, `serde_cbor`). Name the format or the finding is
  unfalsifiable.
- **`PTREXPOSE`** — a runtime address from `ptr as usize`, `{:p}` formatting, `.addr()`, or
  `.expose_provenance()` reaching a shipped log, an HTTP response, serialized output, or an error
  string returned to a remote party. Defeats ASLR and supplies layout for any co-present
  corruption bug.
- **`RESDISC`** — `let _ = fallible();` discarding a `Result` whose failure matters.
- **`CARGOLINT`** — hygiene, gated on a real code condition. `deny(unsafe_code)` only for crates
  meant to be unsafe-free (denying it in a crate that legitimately uses `unsafe` just breaks the
  build). `clippy::undocumented_unsafe_blocks` and `clippy::missing_safety_doc` only when the
  crate contains `unsafe` (the latter is already warn-by-default — the gap is not escalating to
  `deny`). `unused_must_use` is warn-by-default, so its absence is normal; only an explicit
  `allow` is noteworthy. `clippy::pedantic` and `missing_docs` are style, not security — do not
  file them.

## Version Gates

State the rustc version and MSRV with any finding that depends on one:

| Change | Version |
|---|---|
| Panic across `extern "C"` became `abort` instead of UB | rustc **1.81** (compiler version, not edition) |
| `f64 as usize` became a defined saturating cast | rustc **1.45** |
| `mem::uninitialized` deprecated in favour of `MaybeUninit` | rustc **1.39** |
| `unaligned_references` lint became hard error `E0793` | rust-lang/rust#82523 |
| `static_mut_refs` deny-by-default (references only) | Rust **2024** edition |
| Recursive `Drop` stack overflow | still open, rust-lang/rust#58068 |

## Tooling — and what it does not do

```bash
cargo build 2>&1 | tail -40                # must build before any tool is meaningful
cargo tree --duplicates                    # two versions of one crate = two copies of its bugs
cargo tree -e features                     # a feature flag can turn `unsafe` on
rg -n --stats 'unsafe' --glob '!target'    # the honest denominator for a coverage claim
semgrep --config auto --include='*.rs' .   # cheap first pass; hypothesis generator only
joern-parse . -o cpg.bin                   # no Rust frontend — do not pretend otherwise
```

**Do not trust a remembered tool inventory — including the one this skill used to carry.** Rust
tooling here lives outside `$PATH` (`~/.cargo/bin`), `miri` is nightly-only so its availability
depends on which toolchains are installed, and all of it changes. Run
`./ginger-setup.sh --verify-tools` (in `~/.claude/agents/`) for the current state; it probes every
tool below, resolves the off-`PATH` ones, and reports whether `cargo +<tc> miri` actually runs.

Two facts about `miri` that do **not** change and that set the evidence bar:

- It is **nightly-only**. `rustup component add miri` against a stable toolchain fails by design —
  it needs `--toolchain nightly`.
- **`cargo +nightly` only works through the rustup shim.** Where a distro `cargo` is first on
  `PATH` (here `/usr/bin/cargo`, Debian's), `cargo +nightly …` dies with
  `error: no such command: '+nightly'` — distro cargo has no toolchain-override support. Invoke
  the shim by path: `~/.cargo/bin/cargo +nightly miri test`. This is the single most common way a
  correct-looking miri command fails.
- Even when available it only sees what a test **executes**, and it does not cover FFI or inline
  assembly. So it confirms findings; it never clears an unsafe block it did not reach.

Where `miri` runs, an `unsafe` finding should be confirmed with it — it detects the `UAF` shape in
this skill directly (extract a raw pointer with `.as_ptr()`, let the source drop, deref) and
reports `constructing invalid value: encountered a dangling reference (use-after-free)`. Where it
does not, say in the report which unsafe blocks went **unverified at runtime** rather than
implying they were cleared.

What each tool can and cannot conclude:

| Tool | Concludes | Does not |
|---|---|---|
| `cargo clippy` | idiomatic and some correctness lints | soundness of `unsafe` |
| `~/.cargo/bin/cargo +nightly miri test` | **actual UB** in `unsafe` executed by a test — the strongest evidence available | anything a test does not reach; no FFI, no inline asm |
| `cargo-fuzz` + `arbitrary` | panic and UB reachability on generated input | anything the harness does not call |
| `cargo audit` / `cargo deny` | advisories against the lockfile | whether the vulnerable path is reachable |
| ASan (`RUSTFLAGS="-Zsanitizer=address" ~/.cargo/bin/cargo +nightly test`) | heap corruption in `unsafe`/FFI | safe-code logic |
| grep for `unsafe` | where to look | that the safe caller above it is correct |

Miri unavailable is the common case. Then the bar for an `unsafe` finding is the **static proof**
standard: the unsafe block quoted, the safe caller computing the bad value quoted, every gate in
the table above enumerated and shown to pass, and the triggering input described concretely.
Anything less stays a hypothesis with "what would confirm it: `~/.cargo/bin/cargo +nightly miri test` on <test name>"
attached.

## Reporting

Structure findings as GINGER's normal output format, plus three Rust-specific fields:

- **Cluster and ID** (e.g. `UAF-001`, memory-safety cluster) — so variants group.
- **Safety boundary** — is the defect inside the `unsafe` block, or in the safe code the block
  trusts? Name both lines. This is the whole point: the fix usually belongs in the safe half.
- **Profile dependence** — for any panic or arithmetic finding, which `panic`/`overflow-checks`
  setting the severity assumes.

And report gates explicitly: `has_unsafe=false` means the memory-safety cluster is **out of scope
by construction**, which is a stronger and more useful statement than "no memory-safety findings".

## Cross-references

- Whole-tree audit workflow, attack-surface enumeration, coverage ledger → `source-audit`
- Refuting a candidate before filing it → `false-positive-refutation`
- The other instances of a confirmed bug → `variant-analysis`
- Fuzz harness for a Rust target (`fuzz_target!`, `arbitrary`) → `fuzzing-harness-design`
- Sanitizer builds and coverage measurement → `sanitizers-and-coverage`
- Secrets left in memory, non-constant-time comparison → `crypto-side-channel-audit`
- Advisory sweep of the lockfile → `supply-chain-audit`
- Exploiting a confirmed heap primitive from an `unsafe` bug → `heap-exploitation`, `exploit-dev`
- C/C++ peer of an FFI boundary → `c-cpp-review`
