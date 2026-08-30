---
name: fuzzing-triage
description: Coverage-guided fuzzing and crash triage workflows for vulnerability discovery. Use when fuzzing parsers or binaries with AFL++, libFuzzer, or honggfuzz, writing fuzz harnesses, building instrumented targets (ASan/UBSan/MSan), seeding and minimizing corpora (afl-cmin/afl-tmin), deduplicating crashes by crash PC/backtrace, minimizing reproducers, or feeding fuzz crashes into debugger-based crash triage for exploitability assessment.
---

# SKILL: Fuzzing & Crash Triage

Fuzz when static review is inconclusive or the target is a parser. Goal: unique, minimized, *classified* crashes — not crash volume.

## When to Fuzz

- Parser/decoder code (file formats, network protocols, deserializers) — highest yield.
- Static analysis found suspicious bounds handling but couldn't confirm reachability.
- After protocol/format recovery (see the `re-tools` skill) — use the recovered structure to build the corpus.

## Instrumented Builds

Sanitizers turn silent corruption into loud, classifiable crashes. Build a separate fuzzing binary:

```bash
# AFL++ with ASan
AFL_USE_ASAN=1 afl-clang-fast -g -O1 -o target_fuzz target.c

# libFuzzer + ASan
clang -g -O1 -fsanitize=fuzzer,address -o target_fuzz harness.c

# UBSan (integer/UB bugs)
AFL_USE_UBSAN=1 afl-clang-fast -g -O1 -o target_fuzz target.c
```

- **ASan**: heap/stack overflow, UAF, double-free — first choice.
- **UBSan**: integer overflow, signedness, UB-form OOB.
- **MSan**: uninitialized reads (needs fully instrumented deps).
- No source? Fuzz the binary with AFL++ QEMU mode (`afl-fuzz -Q`) — slower, no instrumentation needed.

## Harness Patterns

- **Stdin/argv-driven**: if the target reads stdin or a file argument, fuzz as-is with `@@`: `./target @@`.
- **Library/parser**: write a harness — read the file from argv[1] (or stdin), call the parse function once, exit. Keep it deterministic: no randomness, no network, no timestamps.
- **Persistent mode** (AFL++ `__AFL_LOOP(1000)`) for speed when the parser is re-entrant.
- Keep the harness minimal: parse only, no printing. Every extra syscall is throughput lost.

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
- honggfuzz alternative: `honggfuzz -i seeds -o findings -- ./target_fuzz @@`. **Not installed in this environment** — building it from source needs `libunwind-dev` and `binutils-dev` headers (root-only via `apt`); `command -v honggfuzz` first and fall back to AFL++ or libFuzzer if absent rather than assuming it's there.
- libFuzzer targets run standalone: `./target_fuzz seeds/ -max_total_time=3600 -artifact_prefix=crashes/`.

## Crash Triage (the point of it all)

1. **Collect**: `findings/*/crashes/` (AFL), `crash-*` files (libFuzzer).
2. **Deduplicate** by crash PC + backtrace, not by input:
   - Run each crash under the debugger or ASan build; bucket by faulting address / sanitizer type.
   - `gdb -batch -ex run -ex bt --args ./target crashfile` per crash; group identical top frames.
3. **Minimize** each unique crash: `afl-tmin`, or libFuzzer `-minimize_crash=1`.
4. **Classify & verify**: feed each unique, minimized crash into the `dynamic-verification` skill's crash triage workflow — reproduce, capture state, classify (SIGSEGV write / controlled read / SIGABRT), check PC control with a cyclic pattern.
5. **Record**: each unique crash is a **hypothesis** until classified; only debugger/ASan evidence makes it a finding. Exploit a proven primitive with the `exploit-dev` skill.

## Rules

- Fuzz only targets you're authorized to test; fuzz in an isolated environment (expect hangs and resource exhaustion by design).
- ASan build first for bug discovery; non-ASan build to confirm real-world crash behavior.
- A fuzz crash ≠ exploitable. Exploitability verdicts come from crash triage, never from the fuzzer's "unique crash" count.
- Keep seeds, harnesses, and the exact fuzzing command with the findings — reproducibility.
