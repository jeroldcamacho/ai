---
name: fuzzing-harness-design
description: Design fuzz harnesses and unblock a stuck campaign. Use when writing a first LLVMFuzzerTestOneInput or fuzz_target!, when a campaign finds nothing or plateaus, when crashes will not reproduce, when a checksum or magic value blocks progress, or when choosing among AFL++, libFuzzer, honggfuzz, cargo-fuzz, atheris and go test -fuzz.
---

# SKILL: Fuzz Harness Design

The harness decides what the campaign can find. A fuzzer plateauing after an hour is almost never
a fuzzer problem — it is a harness that never reaches the interesting code, a corpus with no
structure, or a checksum the mutator cannot guess.

This skill is the *design and unblocking* half. Running campaigns, crash dedup, minimisation, and
exploitability triage live in `fuzzing-triage`; instrumented builds and coverage measurement live
in `sanitizers-and-coverage`.

## Choosing a Fuzzer

| Target | Fuzzer | Why |
|---|---|---|
| C/C++ library, quick setup, one core | libFuzzer (`-fsanitize=fuzzer`) | lowest setup cost; starts from an empty corpus |
| C/C++, multi-core, plateaued libFuzzer, mature codebase | **AFL++** | diverse mutators, parallel `-M`/`-S`, mature tooling |
| C/C++ with no source | AFL++ QEMU mode (`afl-fuzz -Q`) | no instrumentation needed; much slower |
| C/C++, want hardware feedback / no-source Intel PT | honggfuzz | different feedback model finds different bugs |
| Custom fuzzer, novel feedback, research | LibAFL | Rust framework; highest setup cost |
| Rust | `cargo fuzz` (wraps libFuzzer) + `arbitrary` | derive structured inputs directly |
| Python, incl. C extensions | Atheris | coverage-guided Python; ASan for the extension |
| Ruby, incl. C extensions | Ruzzy | libFuzzer-backed |
| Go | `go test -fuzz` (stdlib) | native, no extra tooling |
| Java/JVM | Jazzer | libFuzzer-backed JVM instrumentation |

**Check availability with `./ginger-setup.sh --verify-tools` rather than from memory** — this
paragraph has been wrong twice. What is structural rather than incidental:

- **honggfuzz ships its instrumenting compiler wrappers separately from the fuzzer binary**, and
  they land in the source tree, not on `PATH`: `hfuzz-clang`, `hfuzz-clang++`, `hfuzz-gcc` (all
  symlinks to `hfuzz-cc`) under `<honggfuzz>/hfuzz_cc/` — here `/opt/honggfuzz/hfuzz_cc/`. Build
  with the wrapper, then run the fuzzer:

  ```bash
  /opt/honggfuzz/hfuzz_cc/hfuzz-clang -o target harness.c    # instrumented
  honggfuzz --run_time 300 -i seeds -o findings -- ./target   # persistent mode is
  #   selected automatically when the harness exports LLVMFuzzerTestOneInput
  ```

  Run the bare `honggfuzz` against an **un**instrumented binary and you get ptrace-only feedback —
  a far weaker campaign that looks like it is working.
- **`cargo-fuzz` needs a nightly toolchain** even when the binary is installed: `~/.cargo/bin/~/.cargo/bin/cargo +nightly fuzz run <target>`. Same for `cargo fuzz coverage`, which additionally needs `llvm-tools`.
- `atheris`, `ruzzy`, `jazzer` and LibAFL each need an install; ask first, prefer isolated installs.

## The Harness Rules

Violate one of these and the campaign is wasted rather than slow. They apply to the **whole
system under test**, not just the harness — when the SUT breaks one, patch the SUT (see
**Obstacles**).

| Rule | Why |
|---|---|
| **Handle every input size** — empty, 1 byte, megabytes | The fuzzer will send all of them. Guard before touching `data`. A crash *in the harness* is not a finding |
| **Never call `exit()`** | It stops the fuzzer process. Use `abort()` if the SUT must die |
| **Join every thread each iteration** | The iteration must complete before the next begins, or crashes are attributed to the wrong input |
| **Be fast — hundreds to thousands of exec/sec** | No logging, no I/O, no sleeps. Throughput *is* coverage |
| **Be deterministic** | Same input, same behaviour, or crashes will not reproduce |
| **Reset or avoid global state** | Global state makes a bug appear after N iterations rather than on an input — the classic non-reproducible crash |
| **Free everything you allocate** | Otherwise the campaign dies of resource exhaustion, not of a bug |
| **One format per harness** | Do not fuzz PNG and TCP in one target — the shared corpus is useless to both |
| **Consume the result** | A parse into a buffer nobody reads is a **dead store**, and at `-O1`+ the compiler deletes it — so the sanitizer has nothing to detect and the campaign reports clean. Return a checksum of the output, pass it to a `noinline` sink, or otherwise make it escape. Verify with `clang -O1 -S -o - harness.c \| rg -c 'memcpy\|movups\|rep movs'`: zero means the work was optimized away (`sanitizers-and-coverage`) |

The single most common harness bug: **not validating `size` before reading `data`**, producing a
"crash" in the harness on the fuzzer's very first empty input.

## Minimal Harnesses

```c
/* C/C++ — libFuzzer / AFL++ (-fsanitize=fuzzer with afl-clang-fast) */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < MIN_INPUT_SIZE) return 0;      /* reject the meaningless */
    target_parse(data, size);
    return 0;                                  /* non-zero is reserved */
}
```

```c
/* AFL++ persistent mode — 10-100x throughput when the parser is re-entrant */
int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();                              /* defer past expensive setup */
#endif
    unsigned char buf[MAX_SIZE];
    while (__AFL_LOOP(10000)) {
        ssize_t len = read(0, buf, sizeof(buf));
        if (len <= 0) break;
        target_parse(buf, len);
    }
    return 0;
}
```

```rust
// Rust — cargo-fuzz
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = my_crate::parse(data); });
```

```python
# Python — Atheris. instrument_imports must wrap the import, before Setup.
import sys, atheris
with atheris.instrument_imports():
    import target_module
def TestOneInput(data: bytes):
    try:
        target_module.parse(data)
    except (ValueError, TypeError):     # expected exceptions only — never bare except
        pass
atheris.Setup(sys.argv, TestOneInput); atheris.Fuzz()
```

```go
// Go — stdlib
func FuzzParse(f *testing.F) {
    f.Add([]byte("valid-seed"))
    f.Fuzz(func(t *testing.T, data []byte) { _ = Parse(data) })
}
```

## Mapping Bytes onto an API

The fuzzer hands you a byte string; the target wants typed arguments. Three escalating options.

**1. Fixed-layout cast** — when the target takes a couple of primitives:

```c
if (size != 2 * sizeof(uint32_t)) return 0;
uint32_t num = *(uint32_t*)data, den = *(uint32_t*)(data + sizeof(uint32_t));
divide(num, den);
```

Every 8-byte input is valid, so every bit flip produces a new interesting input. The fuzzer learns
the length constraint in seconds.

**2. `FuzzedDataProvider`** — when the target takes several values of mixed type. Ship
`FuzzedDataProvider.h` from `compiler-rt/include/fuzzer/`:

```cpp
#include <fuzzer/FuzzedDataProvider.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    size_t alloc = fdp.ConsumeIntegral<size_t>();
    auto s1 = fdp.ConsumeBytesWithTerminator<char>(32, 0xFF);
    auto s2 = fdp.ConsumeRemainingBytesAsString();
    char *r = concat(s1.data(), s1.size(), s2.data(), s2.size(), alloc);
    free(r);
    return 0;
}
```

Consume **fixed-width fields first and the variable-length remainder last** — otherwise a
one-byte length change reshuffles every subsequent field and the fuzzer's mutations stop
correlating with behaviour.

**3. Structure-aware.** For Rust, derive `Arbitrary`:

```rust
#[derive(Debug, arbitrary::Arbitrary)]
struct Req { method: u8, path: String, headers: Vec<(String, String)> }
fuzz_target!(|r: Req| { handle(&r); });
```

`arbitrary` has **no reverse serialization**, so you cannot hand-craft a byte array that maps to a
chosen struct. That is fine for libFuzzer (starts from empty) and awkward for AFL++ (wants seeds).

For deeply structured formats in C++, `libprotobuf-mutator` with a `.proto` describing the format
makes the fuzzer mutate *message contents* rather than the encoding — more setup, but it stops the
fuzzer wasting its whole budget on inputs the parser rejects at byte 3.

## Interleaved Fuzzing

One harness, several related operations, selected by the first byte:

```c
uint8_t op = data[0];
switch (op % 4) {
  case 0: add(a, b); break;
  case 1: sub(a, b); break;
  case 2: mul(a, b); break;
  case 3: divide(a, b); break;
}
```

Worth it when the operations share input types and are logically related (arithmetic, CRUD, a
state machine's transitions) — one shared corpus means an interesting input for one operation
seeds the others, and it finds bugs in the *interaction*. A natural extension is an **operation
sequence**: consume a list of `(op, args)` tuples and replay them against one object, which is how
you find use-after-free and state-machine bugs that a single call can never reach.

Not worth it across unrelated formats — that is the "one format per harness" rule.

## Corpus

Structure beats volume: **20 valid-ish samples outperform 10,000 random bytes.**

1. **Seed** from real samples — the project's own `tests/` and `testdata/` directories first, then
   format specs, protocol captures found during RE, and strings pulled from the binary (`izz`).
   AFL++ requires at least one non-empty seed; libFuzzer does not.
2. **Minimise before launching**, so the fuzzer is not re-deriving coverage you already have:

```bash
afl-cmin -i seeds -o seeds_min -m none -t 1000 -- ./target_fuzz @@   # coverage-dedup the set
afl-tmin -i one_input -o one_min -m none -- ./target_fuzz @@         # shrink one input
./target_fuzz -merge=1 corpus_min corpus seeds                        # libFuzzer equivalent
```

3. Use format knowledge from `re-tools` — magic bytes, length fields, checksum locations — to
   build seeds that pass the first three validation layers by construction.

## Dictionaries

A dictionary hands the mutator the tokens it would otherwise have to guess. It is the cheapest
possible coverage win on any text or tagged-binary format.

```bash
./fuzz -dict=./tokens.dict corpus/         # libFuzzer
afl-fuzz -x ./tokens.dict -i seeds -o out -- ./fuzz @@   # AFL++
cargo fuzz run tgt -- -dict=./tokens.dict  # cargo-fuzz
```

Sources, in order of yield: the format spec's keyword list; string literals in the parser itself
(`rg -o '"[^"]{3,32}"' parser.c | sort -u`); `strings ./binary` filtered to plausible tokens; the
`.dict` files shipped in AFL++'s `dictionaries/` and OSS-Fuzz projects. Entry format is
`name="token"` or bare `"token"`, one per line; `\xNN` escapes work for binary magic.

## Obstacles: When the Fuzzer Cannot Get Past a Check

Coverage shows a large region behind one branch and the corpus never crosses it. Diagnose which
obstacle it is, because the responses differ:

| Obstacle | Response |
|---|---|
| Magic bytes / fixed keywords | **Dictionary or a valid seed** — do not patch. The fuzzer learns 4-byte comparisons quickly |
| CRC / checksum / cryptographic hash over the input | **Patch it out** behind a build flag. Guessing a hash is astronomically unlikely |
| Signature verification | **Patch it out**, and note that everything found downstream requires a signing oracle to be a real finding |
| Time-, PID-, or `/dev/urandom`-seeded state | **Patch to a fixed seed** — this is a determinism bug, not just a coverage one |
| Complex multi-field validation | Try structure-aware fuzzing first; patch only if that fails |
| Network / disk I/O in the parse path | Mock it to an in-memory buffer |

Patch via conditional compilation so production behaviour is untouched. Use the standard flag name
— libFuzzer, AFL++, honggfuzz and LibAFL all define it:

```c
if (computed_crc != header_crc) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return ERROR_BAD_CRC;      /* enforced only in production builds */
#endif
}
process(data, size);
```

```rust
if checksum != expected {
    if !cfg!(fuzzing) { return Err(Error::Checksum); }   // cfg!(fuzzing) is set by cargo-fuzz
}
```

Then **rebuild, run briefly, and compare coverage against the unpatched version** — a patch that
does not move coverage was the wrong diagnosis.

### The False Positives a Patch Introduces

Skipping a check can create program states that are impossible in production, and every crash in
those states is a false positive that costs real triage time:

```c
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (!validate_config(&cfg)) return -1;   /* this guaranteed cfg.x != 0 */
#endif
    int r = 100 / cfg.x;                     /* division by zero, fuzzing only */
```

Before patching, ask: **does the code after the check assume a property the check established?**
If yes, the patch must preserve that property while removing the barrier — bypass the *comparison*
but keep the *clamp*:

```c
if (computed_crc != header_crc) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return ERROR_BAD_CRC;
#else
    header_crc = computed_crc;   /* make the record self-consistent instead */
#endif
}
```

**Record every patch with the finding.** A crash reachable only in a patched build is a
*hypothesis about the production build* until you either re-derive it with a correctly checksummed
input or show the attacker can produce one. Say which, in the report.

## Diagnosing a Campaign That Is Not Working

| Symptom | Likely cause | Action |
|---|---|---|
| Low exec/sec (< ~100) | logging, I/O, setup per iteration, oversized inputs | profile the harness; `__AFL_INIT()` after setup; persistent mode; `-max_len` |
| Coverage flat from minute one | harness never reaches the parser | verify by hand with a known-good input; measure coverage (`sanitizers-and-coverage`) |
| Coverage climbs then stops hard | a magic value or checksum wall | dictionary, then seeds, then patch |
| `stability` well below 100% (AFL++) | non-determinism: globals, time, threads, ASLR-dependent behaviour | reset globals; fix the seed; join threads |
| Corpus not growing | inputs over-constrained by the harness's own size checks | loosen the guard; use `FuzzedDataProvider`; structure-aware |
| Crashes will not reproduce | global state, or a crash after N iterations | reset state per iteration; re-run the single input on a fresh process |
| Fuzzer exits immediately | the SUT calls `exit()`, or the harness crashes on empty input | patch `exit()`→`abort()`; guard `size` |
| OOM / RSS limit | leak in harness or SUT | `-rss_limit_mb=0` with ASan, `-m none` for AFL++, then fix the leak with LeakSanitizer |

**Verify the harness by hand before starting a campaign**: build it, run it on one known-good
input, and confirm it parses. Then measure coverage on the seed corpus and confirm the functions
you meant to target are actually hit. A campaign launched without those two checks can burn hours
covering `main`.

## Cross-references

- Instrumented builds, ASan/UBSan/MSan/TSan, coverage measurement → `sanitizers-and-coverage`
- Running campaigns, crash dedup, minimisation, exploitability triage → `fuzzing-triage`
- Format and protocol structure to seed the corpus with → `re-tools`
- Which parser to target first, and why → `source-audit`, `audit-context-building`
- Turning a triaged crash into a primitive → `exploit-dev` and its depth skills
- Rust-specific harnessing (`arbitrary`, panic vs UB as the oracle) → `rust-security-audit`
