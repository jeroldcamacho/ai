---
name: fuzzing-triage
description: Running fuzzing campaigns and triaging what comes out. Use when launching AFL++, libFuzzer or honggfuzz, seeding and minimizing corpora, parallelizing across cores, deduplicating crashes by PC and backtrace, minimizing reproducers, classifying a crash as exploitable, or deciding when a campaign is done. Harness design lives in fuzzing-harness-design; instrumented builds and coverage in sanitizers-and-coverage.
---

# SKILL: Fuzzing & Crash Triage

Fuzz when static review is inconclusive or the target is a parser. Goal: unique, minimized,
*classified* crashes — not crash volume.

This skill is the **campaign and triage** half. Two companions carry the rest, and reaching for
this one without them is the usual reason a campaign finds nothing:

- **`fuzzing-harness-design`** — harness rules, mapping bytes onto an API, dictionaries,
  structure-aware input, and patching past a checksum or magic-value wall. Go there **first** if
  you are writing the harness, or if coverage is flat.
- **`sanitizers-and-coverage`** — instrumented builds, the sanitizer matrix, `ASAN_OPTIONS`,
  reading a report, and measuring whether the campaign reached the code you were auditing.

## When to Fuzz

- Parser/decoder code (file formats, network protocols, deserializers) — highest yield.
- Static analysis found suspicious bounds handling but couldn't confirm reachability.
- After protocol/format recovery (see the `re-tools` skill) — use the recovered structure to build the corpus.

## Instrumented Builds (summary — depth in `sanitizers-and-coverage`)

Sanitizers turn silent corruption into loud, classifiable crashes. Build a separate fuzzing binary:

```bash
AFL_USE_ASAN=1 afl-clang-fast -g -O1 -o target_fuzz target.c        # AFL++ with ASan
clang -g -O1 -fsanitize=fuzzer,address,undefined -o target_fuzz harness.c   # libFuzzer + ASan + UBSan
AFL_USE_UBSAN=1 afl-clang-fast -g -O1 -o target_ubsan target.c      # integer/UB bugs
```

- **ASan** first choice (heap/stack overflow, UAF, double free) — and set
  `ASAN_OPTIONS=abort_on_error=1`, or AFL++ can miss the detection entirely.
- **UBSan** for integer, signedness and UB-form OOB; add `-fno-sanitize-recover=all` or it only warns.
- **MSan** for uninitialized reads — needs *every* dependency instrumented.
- **ASan, MSan and TSan are mutually exclusive**; run them as separate builds.
- No source? AFL++ QEMU mode (`afl-fuzz -Q`) — slower, no instrumentation needed.

`valgrind` is **not installed** in this environment, so Memcheck is not an ASan fallback here.

## Harness — What Matters Here

Full design guidance is `fuzzing-harness-design`. The rules a campaign dies without:

- **Stdin/argv-driven targets** fuzz as-is with `@@`: `afl-fuzz -i seeds -o out -- ./target @@`.
- **Library/parser**: read the input, call the parse function once, exit. Deterministic — no
  randomness, no network, no timestamps, no logging.
- **Guard `size` before touching `data`**, or the first empty input "crashes" in your harness.
- **Never `exit()`** (it stops the fuzzer), join every thread, free everything.
- **Persistent mode** (AFL++ `__AFL_LOOP(1000)`) for 10–100x when the parser is re-entrant.
- **Verify the harness by hand on one known-good input before launching a campaign.**

## Corpus

1. **Seed** from real samples: files/protocol captures found during RE, strings in the binary (`izz`), test files in the repo, format specs.
2. **Minimize** before launching:

   ```bash
   afl-cmin -i seeds -o seeds_min -m none -t 1000 -- ./target_fuzz @@   # coverage-dedup
   afl-tmin -i crash_or_seed -o min_input -- ./target_fuzz @@           # shrink one input
   ```

3. Structure beats volume: 20 valid-ish samples outperform 10,000 random bytes. Use format knowledge from `re-tools` (magic bytes, length fields, checksums).

## Running

```bash
afl-fuzz -i seeds_min -o findings -m none -t 1000+ -- ./target_fuzz @@
```

- `-m none` is required with ASan (its memory appetite breaks AFL's default limits).
- Time-box campaigns (hours, not days) unless coverage is still climbing — check the fuzzer stats.
- honggfuzz alternative: `honggfuzz -i seeds -o findings -- ./target_fuzz @@`. **Installed at `~/.local/bin/honggfuzz`** and verified working — it is a different feedback model, so it is worth a run when AFL++ plateaus. (It is not on the default `PATH` in every shell; invoke it by full path rather than concluding it is missing.)
- libFuzzer targets run standalone: `./target_fuzz seeds/ -max_total_time=3600 -artifact_prefix=crashes/`.

**Parallel** (AFL++) — one main instance does deterministic mutation, the secondaries do havoc.
They share `findings/`, so coverage found by one seeds the others:

```bash
afl-fuzz -i seeds_min -o findings -m none -M main -- ./target_fuzz @@ &
for i in $(seq 1 $(($(nproc) - 1))); do
  afl-fuzz -i seeds_min -o findings -m none -S "sec$i" -- ./target_fuzz @@ &
done
afl-whatsup findings          # aggregate status across every instance
```

Run one secondary with a *different* sanitizer build (UBSan instead of ASan) and one under
`-Q` QEMU mode if the target has uninstrumented dependencies — diversity of oracle beats another
core on the same build.

## Reading the Campaign

The four numbers that tell you what to do next. Check them within the first ten minutes, not at
the end.

| Stat | Healthy | What it means when it isn't |
|---|---|---|
| **execs/sec** | 100s–1000s | Slow harness: logging, I/O, per-iteration setup, oversized inputs. Fix the harness before spending cores |
| **stability** | ~100% | Non-determinism — globals, time, threads, uninitialized reads. Crashes will not reproduce. Fix this first, it invalidates everything else |
| **corpus count / new paths** | still climbing | Flat from the start = the harness never reaches the parser. Flat after a rise = a magic value or checksum wall (`fuzzing-harness-design`) |
| **cycles done** | 0–2 while productive | Many cycles with no new paths means the fuzzer has exhausted this corpus and harness. More time will not help |

`findings/default/` layout: `crashes/`, `hangs/`, `queue/` (the coverage-distinct inputs — this is
the corpus to keep and to measure coverage over), `fuzzer_stats`, `plot_data`.

**When a campaign is done** — say which of these applies, because "we fuzzed it" is not a result:

- cycles done climbing with no new paths for hours → **exhausted**; the next win is harness or
  dictionary work, not more time
- coverage measured over `queue/` shows the target functions were never reached → **the campaign
  proved nothing about them**; report that, do not report "no crashes found"
- coverage confirms the target functions were reached, no crashes → a **real negative result**
  worth stating, bounded by the coverage number (`sanitizers-and-coverage`)

## Crash Triage (the point of it all)

1. **Collect**: `findings/*/crashes/` (AFL), `crash-*` files (libFuzzer).
2. **Deduplicate** by crash PC + backtrace, not by input:
   - Run each crash under the debugger or ASan build; bucket by faulting address / sanitizer type.
   - `gdb -batch -ex run -ex bt --args ./target crashfile` per crash; group identical top frames.
3. **Minimize** each unique crash: `afl-tmin`, or libFuzzer `-minimize_crash=1`.
4. **Classify & verify**: feed each unique, minimized crash into the `dynamic-verification` skill's crash triage workflow — reproduce, capture state, classify (SIGSEGV write / controlled read / SIGABRT), check PC control with a cyclic pattern.
5. **Record**: each unique crash is a **hypothesis** until classified; only debugger/ASan evidence makes it a finding. Exploit a proven primitive with the `exploit-dev` skill.

Two dedup traps worth naming. AFL++'s **"unique crashes" count is a coverage-bitmap artifact, not
a bug count** — it routinely reports dozens for one bug and occasionally collapses two bugs into
one bucket; never quote it as a finding count. And a crash bucketed by *faulting address* alone
splits one bug across many buckets when the address is attacker-influenced — bucket by the top 3–5
**frames** of the backtrace, or by the ASan error class plus the allocation site.

A crash found in a **patched** build (checksum bypassed, validation stubbed) is a hypothesis about
the production build until you either re-derive it with a well-formed input or show the attacker
can produce one. Say which, and keep the patch with the reproducer.

## Rules

- Fuzz only targets you're authorized to test; fuzz in an isolated environment (expect hangs and resource exhaustion by design).
- ASan build first for bug discovery; non-ASan build to confirm real-world crash behavior.
- A fuzz crash ≠ exploitable. Exploitability verdicts come from crash triage, never from the fuzzer's "unique crash" count.
- Keep seeds, harnesses, sanitizer flags, and the exact fuzzing command with the findings — a
  reproducer nobody else can run is not evidence.
- Report coverage alongside "no crashes found", or the statement is vacuous.

## Cross-references

- Harness design, dictionaries, structure-aware input, obstacle patching → `fuzzing-harness-design`
- Instrumented builds, `ASAN_OPTIONS`, reading a sanitizer report, coverage → `sanitizers-and-coverage`
- Reproducing and classifying one crash in the debugger → `dynamic-verification`
- Format structure to build the corpus from → `re-tools`
- Which parser to fuzz first — ranked entry points by attacker reachability → `source-audit`; the class catalog that says which parser shapes are highest-yield → `c-cpp-review`
- Rust targets (`cargo fuzz`, `arbitrary`, panic-vs-UB as the oracle) → `rust-security-audit`
- Deciding whether a triaged crash is really a bug → `false-positive-refutation`
- Turning a classified crash into a primitive → `exploit-dev` and its depth skills
