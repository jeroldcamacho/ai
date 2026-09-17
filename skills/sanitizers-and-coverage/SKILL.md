---
name: sanitizers-and-coverage
description: Build instrumented targets and measure what testing actually reached. Use when choosing among ASan, UBSan, MSan, TSan and LSan, when reading a sanitizer report, when a sanitizer build will not link or silently detects nothing, or when measuring coverage with llvm-cov to judge whether a harness or test suite is effective.
---

# SKILL: Sanitizers & Coverage

Two jobs that always travel together. A **sanitizer** turns silent corruption into a loud,
classifiable, attributable crash — it is how a hypothesis becomes a finding. **Coverage** tells you
whether the code you were auditing was ever executed — it is how "no crashes found" becomes an
honest statement instead of a vacuous one.

Both are evidence infrastructure. Neither finds bugs on its own.

## Choosing a Sanitizer

| Sanitizer | Finds | Cost | Notes |
|---|---|---|---|
| **ASan** `-fsanitize=address` | heap/stack/global overflow, UAF, double free, invalid free, container overflow | 2–4x CPU, ~3x RSS, **20 TB virtual** | First choice. Reserves shadow memory over a huge virtual range |
| **LSan** (in ASan by default on Linux) | memory leaks at exit | negligible on top of ASan | `detect_leaks=1`; standalone via `-fsanitize=leak` |
| **UBSan** `-fsanitize=undefined` | signed overflow, shift-out-of-range, misaligned load, bad cast, null deref, `-fsanitize=integer` for unsigned wrap | ~20% | Cheap. Composes with ASan. Add `-fno-sanitize-recover=all` or it only *warns* |
| **MSan** `-fsanitize=memory` | reads of uninitialized memory | 3x | **Requires every dependency instrumented**, libc++ included. Any uninstrumented library produces false positives. Highest setup cost, unique class of finding |
| **TSan** `-fsanitize=thread` | data races, lock-order inversions | 5–15x CPU, 5–10x RSS | Only reports races it *observes* — needs the racing schedule to actually occur |
| **CFI** `-fsanitize=cfi` | indirect-call type violations | small | Needs LTO. A mitigation you are testing, not a bug finder |

Mutually exclusive: **ASan + MSan + TSan cannot be combined.** ASan+UBSan+LSan compose fine, and
that trio is the default build for bug hunting. Run MSan and TSan as separate builds.

```bash
# The default hunting build
clang -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
      -fno-sanitize-recover=all -o target_asan target.c

# libFuzzer + ASan + UBSan
clang -g -O1 -fsanitize=fuzzer,address,undefined -o target_fuzz harness.c target.c

# AFL++ (env vars, not flags — the wrapper adds -g itself)
AFL_USE_ASAN=1 afl-clang-fast -O2 -o target_afl target.c
AFL_USE_UBSAN=1 afl-clang-fast -O2 -o target_ubsan target.c
AFL_USE_MSAN=1  afl-clang-fast -O2 -o target_msan target.c

# Separate builds for the incompatible ones
clang -g -O1 -fsanitize=memory -fsanitize-memory-track-origins=2 -o target_msan target.c
clang -g -O2 -fsanitize=thread -o target_tsan target.c

# Rust — sanitizers are nightly-only; verify the toolchain with ./ginger-setup.sh --verify-tools
RUSTFLAGS="-Zsanitizer=address" ~/.cargo/bin/cargo +nightly test --target x86_64-unknown-linux-gnu
```

`-O1` with `-fno-omit-frame-pointer` is the sweet spot: enough optimization that the code resembles
what ships, enough frame pointers that the stack trace is readable. `-O0` changes behaviour too
much (stack layout, no inlining) and `-O2` can hide the frames you need.

**Check availability with `./ginger-setup.sh --verify-tools`, not from memory.** One structural
point worth carrying: where `valgrind` is absent, **Memcheck is not an ASan fallback** — if the
target cannot be rebuilt with ASan, say so and fall back to debugger-based triage
(`dynamic-verification`) rather than assuming Valgrind is there. Rust sanitizers and
`cargo fuzz coverage` are nightly-only regardless of what else is installed.

## Runtime Configuration

Options are colon-separated in the matching environment variable.

```bash
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:symbolize=1:print_stacktrace=1:\
strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:\
malloc_context_size=30:log_path=/tmp/asan
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
export MSAN_OPTIONS=poison_in_dtor=1
export LSAN_OPTIONS=suppressions=lsan.supp:print_suppressions=0
export ASAN_SYMBOLIZER_PATH=$(command -v llvm-symbolizer)
```

The ones that change what you find, not just how it prints:

- **`abort_on_error=1`** — makes ASan `SIGABRT` instead of `_exit(1)`, so a debugger and a fuzzer
  both see a crash. Without it, AFL++ can miss ASan detections entirely.
- **`detect_stack_use_after_return=1`** — a whole extra bug class, off by default.
- **`strict_string_checks=1`** — catches `strlen`/`strcpy` on a non-NUL-terminated buffer, which
  is exactly the `strncpy` bug from `c-cpp-review`.
- **`check_initialization_order=1`** — the C++ static-init-order class.
- **`detect_leaks=0`** — turn LSan *off* while fuzzing a target with known benign leaks, or every
  iteration reports.
- **`malloc_context_size=30`** — deeper allocation stacks, which is what makes a UAF report
  actually attributable.

**Fuzzer memory limits must be disabled** or ASan's 20 TB reservation trips them: libFuzzer
`-rss_limit_mb=0`, AFL++ `-m none`. This is not optional — it is the most common reason an
ASan+AFL++ build appears to find nothing.

## Reading a Report

An ASan report has four parts, and each answers a different question:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118
                                  ^ the class — decides the bug class and the primitive
WRITE of size 8 at 0x602000000118 thread T0
^^^^^ direction and width — WRITE is corruption, READ is disclosure
    #0 0x4f1a2b in parse_record parser.c:142:5        <- the bug site
    #1 0x4f0c11 in handle_packet net.c:88:9           <- the reachability chain
0x602000000118 is located 0 bytes to the right of 24-byte region [0x602000000100,0x602000000118)
                          ^^^^^^^^^^^^^^^^^^^^^^ offset and object size — is the overflow controllable?
allocated by thread T0 here:
    #0 malloc ; #1 0x4f0b90 in alloc_record parser.c:120   <- where the size came from
```

What each line lets you claim:

| Report field | Claim it supports |
|---|---|
| Error class (`heap-buffer-overflow`, `use-after-free`, `double-free`, `stack-buffer-overflow`, `global-buffer-overflow`, `SEGV`) | the bug class and CWE |
| `WRITE` vs `READ` | corruption vs disclosure — a very different severity |
| size of the access | how much you control per operation |
| `N bytes to the right of` | the offset; adjacency to the next object |
| region size | the allocation, which pairs with the allocation site to explain *why* it is too small |
| allocation stack | the size computation to audit — usually where the real bug is |
| **free** stack (UAF/double-free) | the lifetime bug: which path freed it |
| thread IDs | whether it is also a concurrency bug |

**A `SEGV on unknown address 0x000000000000` from ASan is a null dereference, not corruption** —
different class, usually much lower severity. And `SEGV` on a wild non-null address means ASan did
*not* catch the overflow that produced the pointer; the corruption happened somewhere ASan does
not instrument (an uninstrumented library, inline asm, or a `mmap`'d region).

UBSan reports name the exact rule: `signed integer overflow: 2147483647 + 1 cannot be represented
in type 'int'`. Treat it as a *finding* only after asking the `c-cpp-review` question — does the
wrapped value then reach an allocation size, an index, or a loop bound? Many UBSan hits are real
UB with no security consequence, and reporting them all as vulnerabilities is the fastest way to
lose a report's credibility.

## When the Sanitizer Reports Nothing

Before concluding the code is clean, rule out the three ways a sanitizer stays silent on a bug
that is genuinely there. The first is the one that wastes the most time and it is invisible:

**1. The optimizer deleted the bug.** A write into a buffer that is never subsequently read is a
dead store, and at `-O1` and above the compiler removes it — so there is no access for ASan to
instrument. Verified: this harness reports nothing at `-O1`, and its assembly contains **zero**
copy instructions:

```c
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {
    char b[8];
    if (s > 0 && s < 64) memcpy(b, d, s);   /* overflows b[8] — and is optimized away */
    return 0;                                /* b is never read, so the store is dead */
}
```

Two ways to expose it, and they agree:

```bash
clang -O1 -S -o - h.c | rg -c 'memcpy|movups|rep movs'   # 0 = the store is gone; the test is a lie
```

- **Make the value escape** — consume the parse result, or pass the buffer to a
  `__attribute__((noinline))` sink. Then ASan reports `stack-buffer-overflow / WRITE of size 32`
  at `-O1` as expected.
- **Re-check at `-O0`**, where no elimination happens. If `-O0` reports and `-O1` does not, the
  optimizer is the reason — not the absence of a bug.

This is also a **harness** defect, not only a build one: a harness that parses into a buffer and
discards it lets the compiler delete the work it was written to exercise
(`fuzzing-harness-design`).

**2. The runtime never armed.** ASan linked but silent usually means `abort_on_error` was left
default so the fuzzer never saw a crash, or the sanitizer runtime was not linked into the final
binary (link *with* `-fsanitize=...`, not just compile with it). Confirm with
`nm <binary> | rg -c '__asan'` — a few hundred symbols means it is in.

**3. The code never ran.** The reason coverage lives in this skill. Measure before believing a
clean result.

## What a Sanitizer Does Not Prove

- **A clean sanitizer run over a test suite proves nothing about uncovered code.** This is why
  coverage is in the same skill. Always pair the claim with the number.
- **ASan does not catch every overflow.** Intra-object overflows (one field of a struct into the
  next) need `-fsanitize=address -fsanitize-address-field-padding=1` and a full rebuild of
  everything sharing those types; overflows within a single allocation are invisible by default.
- **ASan and MSan do not see inside uninstrumented libraries.** A bug in a prebuilt `.so` is a blind
  spot — the corruption surfaces later, attributed to your code.
- **TSan only reports races it observes.** No report means that schedule did not occur, not that
  the code is race-free.
- **A sanitizer crash is not an exploitability verdict.** It is the evidence that makes the bug
  real; the verdict comes from crash triage (`fuzzing-triage`, `dynamic-verification`) and the
  primitive analysis in `exploit-dev`.
- **Never ship a sanitizer build.** ASan is an attack surface of its own (`log_path`, symbolizer
  invocation) and disables hardening.

Troubleshooting the silent failures: an ASan build that links but never reports usually means the
runtime was not linked into the final binary (link *with* `clang -fsanitize=address`, not just
compile with it), or `LD_PRELOAD` ordering is wrong for a shared-library target, or
`detect_leaks`/`abort_on_error` defaults are hiding the result from the harness. A UBSan build that
only prints and continues is missing `-fno-sanitize-recover=all`. An MSan build drowning in false
positives has an uninstrumented dependency — including libstdc++, which needs
`-stdlib=libc++` with an MSan-built libc++.

## Coverage: Building It

Coverage answers one question: **did the testing reach the code I claimed to audit?**

```bash
# Clang / LLVM (source-based, precise, per-region)
clang -fprofile-instr-generate -fcoverage-mapping -O2 -g -o target_cov main.c harness.c
LLVM_PROFILE_FILE=run-%p.profraw ./target_cov corpus/*
llvm-profdata merge -sparse run-*.profraw -o merged.profdata
llvm-cov report ./target_cov -instr-profile=merged.profdata
llvm-cov show   ./target_cov -instr-profile=merged.profdata -format=html -output-dir=cov-html/
llvm-cov show   ./target_cov -instr-profile=merged.profdata -name=parse_record   # one function

# GCC / gcov
g++ -ftest-coverage -fprofile-arcs -O2 -g -o target_gcov main.c harness.c
./target_gcov corpus/* && gcovr --html-details -o coverage.html

# Rust
~/.cargo/bin/cargo +nightly fuzz coverage <target>   # nightly + llvm-tools.
#   NOTE: a distro `cargo` first on PATH rejects `+nightly` — use the rustup shim by path.
```

For a **libFuzzer harness**, the harness has no `main`, so build a small replay runtime that reads
each corpus file and calls `LLVMFuzzerTestOneInput` once — then coverage is measured over the
corpus rather than over a live fuzzing session:

```c
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t);
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
        uint8_t *b = (uint8_t*)malloc(n ? n : 1);
        if (fread(b, 1, n, f) == (size_t)n) LLVMFuzzerTestOneInput(b, n);
        free(b); fclose(f);
    }
    return 0;
}
```

**Measure over the post-campaign corpus, not from the fuzzer's live statistics.** The corpus is a
reproducible artifact; the fuzzer's own edge counter is not comparable across tools or runs.

## Coverage: Using It

The workflow is a loop, and each outcome routes somewhere specific:

```
campaign / test run → corpus → coverage report
   ├─ coverage increased      → keep fuzzing with the larger corpus
   ├─ coverage decreased      → the harness or the SUT changed; find out which
   └─ coverage plateaued      → read the uncovered regions and diagnose
```

Reading an uncovered region is the actual skill. For each one, name the reason:

| Why it is uncovered | Fix |
|---|---|
| Guarded by a magic value or keyword | dictionary (`fuzzing-harness-design`) |
| Guarded by a checksum or signature | patch behind a fuzzing build flag |
| Needs a structurally valid input the mutator cannot build | seeds, or structure-aware fuzzing |
| Needs a second input, a sequence, or prior state | interleaved / sequence harness |
| The harness never calls into that subsystem at all | new harness — this is the most common and the most valuable finding |
| Genuinely dead code, or a different `#ifdef` configuration | record it; it is a coverage *boundary*, not a gap |

Then use coverage to make the audit's honesty checkable. Three numbers worth reporting:

1. **Function coverage over the attack-surface set** — not over the whole tree. "37 of 41 functions
   reachable from `handle_packet` were executed" is a claim a reviewer can check; "62% line
   coverage" is not.
2. **The uncovered functions, by name**, in the entry-point table from `source-audit`. An uncovered
   function in a remote-unauth path is a hole in the audit, and it belongs in the coverage section
   of the report rather than being quietly absent.
3. **Which build configuration** produced the number. Coverage under `#ifdef DEBUG` or with a
   feature flag off describes a different program.

**Coverage is a proxy, not a goal.** It reliably tells you whether a harness works; it does not
measure fuzzer quality, and driving it up by covering error-return paths finds nothing. 100%
coverage with no oracle (no sanitizer, no assertion, no differential comparison) finds nothing
either — coverage says the code *ran*, the sanitizer says it *misbehaved*, and you need both.

## Cross-references

- Designing the harness whose coverage you are measuring → `fuzzing-harness-design`
- Running campaigns, dedup, minimisation, exploitability triage → `fuzzing-triage`
- Debugger-driven verification when a rebuild is impossible → `dynamic-verification`
- Interpreting the class the sanitizer named → `bug-class-catalog`, `c-cpp-review`
- Rust sanitizer and Miri caveats → `rust-security-audit`
- Build-hardening flags (and silently misspelled ones) → `c-cpp-review`, `binary-protection-bypass`
- Reporting coverage as part of audit scope → `source-audit`
