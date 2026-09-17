---
name: crypto-side-channel-audit
description: Audit cryptographic code for timing side channels, correctness against known-attack test vectors, and secrets left in memory. Use when reviewing sign, verify, encrypt, decrypt, KEM or key-derivation code; on division, branching or early-exit comparison over a secret; on constant-time, timing-attack or KyberSlash questions; with dudect or Wycheproof; or when checking a key wipe survived the optimizer.
---

# SKILL: Crypto Side-Channel & Zeroization Audit

Two failure modes that share a root cause — **the compiler is not obliged to preserve what your
source code implies.** A branch you wrote as constant-time becomes a branch; a divide you expected
to be strength-reduced stays a divide; a `memset` that wipes a key is deleted as a dead store.

So the method for both is the same: **read what the compiler actually emitted**, at the
optimization level and architecture that ship, and then decide which of the flagged operations
actually touch a secret. The emission step is mechanical. **The triage step is the work.**

Three parts, in the order you should reach for them: **static** inspection of emitted code (Part 1),
**runtime** measurement when the static verdict is contested or the source is unavailable (Part 3),
and **zeroization** (Part 2). Not in scope: cache and other microarchitectural channels — an
assembly view cannot see them, and dudect measures their effect without localising it — and
high-level use of a vetted library that owns the guarantees itself.

## Part 1 — Timing Side Channels

### The dangerous operations

| Operation | Why it leaks | Constant-time replacement |
|---|---|---|
| `/` and `%` on a secret | `IDIV` (x86_64), `SDIV`/`UDIV` (arm64) have **early termination** — latency depends on operand magnitude. This is KyberSlash | multiply-shift by a reciprocal, or a Barrett/Montgomery reduction |
| A branch on a secret | different path length, and the branch predictor leaks it across processes | arithmetic select: `mask = -(cond & 1); r = (a & mask) | (b & ~mask)` |
| **Early-exit comparison** — `memcmp`, `strcmp`, `==`, `.equals`, `Array.equals` on a tag/MAC/hash | returns at the first differing byte, leaking the position of the mismatch. **The most common real timing bug** — Lucky Thirteen was exactly this | see the table below |
| Table lookup indexed by a secret | the *index* selects a cache line, which is observable. Classic AES S-box case | bit-sliced or arithmetic formulation touching every element |
| Variable-time encoding of a secret | `base64_encode`, `bin2hex`, `chr`/`ord` walk a table under a secret index | `paragonie/constant_time_encoding` (PHP) and equivalents |
| Non-CSPRNG for a nonce, key, or salt | not timing, but it travels with this class | the platform CSPRNG |
| Secret-dependent loop bound or early `return` in a verify | trip count leaks | fixed trip count, accumulate a difference, compare once at the end |

Constant-time comparison, by language:

| Language | Use |
|---|---|
| C, C++ | `CRYPTO_memcmp` (OpenSSL), `sodium_memcmp` |
| Go | `crypto/subtle.ConstantTimeCompare` |
| Rust | the `subtle` crate's `ConstantTimeEq` |
| Java, Kotlin | `MessageDigest.isEqual` |
| C# | `CryptographicOperations.FixedTimeEquals` |
| PHP | `hash_equals` |
| Python | `hmac.compare_digest` |
| Ruby | `OpenSSL.secure_compare` |
| JS, TS | `crypto.timingSafeEqual` |

### Finding candidate sites

```bash
# Scope: the routines that handle secrets at all
rg -n --glob '!test*' -e '\b(sign|verify|encrypt|decrypt|derive_key|kdf|hkdf|hmac|mac|seal|open|unwrap_key|decapsulate|encapsulate)\w*\s*\('

# Division/modulo inside them (the KyberSlash shape)
rg -n '[^/*]/[^/*=]|%[^=]' --glob '*.c' --glob '*.cc' --glob '*.rs' --glob '*.go' | rg -i 'key|secret|priv|nonce|coef|scalar|share|seed'

# Early-exit comparison on something secret
rg -n '\b(memcmp|strcmp|strncmp|bcmp)\s*\(' | rg -i 'mac|tag|hash|digest|sig|token|secret|password|hmac|auth'
rg -n '==' --glob '*.go' --glob '*.java' --glob '*.py' --glob '*.rb' --glob '*.php' | rg -i 'mac|tag|digest|signature|token|password|hmac'

# Secret-indexed tables, and weak RNG
rg -n '\w+\s*\[\s*(key|secret|priv|s|scalar|nonce)\w*\s*(\[|\+|\])'
rg -n '\b(rand|srand|random|mt_rand|Math\.random|System\.Random|randint|shuffle)\s*\(' | rg -iv 'test'
```

### Reading the emitted code

Compile at the level and target that ship, then look for the dangerous instructions:

```bash
# x86_64
clang -O2 -S -masm=intel -o - crypto.c | rg -n '\b(idiv|div|udiv|jne|je|jz|jnz|cmov)\b'
# arm64 cross (clang crosses with --target; libc headers for that target still required)
clang --target=aarch64-linux-gnu -O2 -S -o - crypto.c | rg -n '\b(sdiv|udiv|csel|b\.(ne|eq))\b'
objdump -d --no-show-raw-insn ./libcrypto.so | rg -n 'idiv|sdiv|udiv'   # no source? read the binary
go tool compile -S crypto.go | rg -n 'DIV|IDIV'
rustc --emit asm -O crypto.rs -o - | rg -n 'idiv|sdiv|udiv|div'
javap -c Crypto.class | rg -n 'idiv|irem|ldiv|lrem|if_'
```

**Sweep more than one configuration.** Division timing and branch lowering are architecture- and
optimization-dependent: x86_64 `IDIV` and arm64 `SDIV` differ, and a `cmov` at `-O2` can become a
branch at `-O0`. **A single clean run proves one configuration safe, not the code.** Run at
minimum `x86_64` and `arm64`, and at `-O0`, `-O2`, `-Os`, and `-Oz` — `Os` and `Oz` are where
strength reduction most often declines.

That last point is the trap worth stating explicitly. **A fix that works by handing the compiler a
constant divisor to strength-reduce is a fix only where the compiler chooses to cooperate**, and
that choice varies more than it looks. Replacing `key_coef / (2 * gamma2)` with a `#define`d
constant divisor still emits a real division on gcc/riscv64 at *every* level from `O0` to `Oz`, on
gcc arm64 and gcc x86_64 at `Os` and `Oz`, and on clang arm64 at `O0` and `Oz`. Strength reduction
is an optimizer courtesy, not a language guarantee.

Prefer an **explicit multiply-shift**, and verify it against the original expression **over the
full input range**, not on sampled values — an off-by-a-power-of-two reciprocal matches for
millions of inputs before it diverges. Then **re-run the whole sweep on the fix**, across
compilers, targets and every level.

JVM and CIL bytecode (`javap -c`, `ilspycmd`) can be read the same way, but `-O`/`--arch` do not
apply and **the JIT may introduce variable-time native code the bytecode does not show**.
Interpreted languages (Python, Ruby, PHP) show the bytecode of the interpreter that ran, not of a
JIT or alternative runtime.

### Triage: the step that decides everything

**Instruction-level detection has no data-flow analysis.** It flags every dangerous instruction
regardless of whether a secret reaches it, so the output is a **worklist, not a verdict**.
Reporting the raw list as vulnerabilities is the primary failure mode of this whole area.

For each flagged instruction, read the source and answer one question: **does an operand depend on
secret data?** Trace from the instruction's function back to the caller's inputs.

```c
int num_blocks = data_len / 16;      // FALSE POSITIVE: length is public from the ciphertext size
int32_t q = secret_coef / GAMMA2;    // TRUE POSITIVE: dividend is a private-key coefficient
```

| Question | If yes |
|---|---|
| Is the operand a compile-time constant? | likely false positive |
| Is the operand a public parameter — length, count, index bound, protocol version? | likely false positive |
| Is the operand derived from a key, plaintext, nonce, token, or password? | **true positive** |
| Can an attacker *influence* the operand's value? | **true positive** |

Three families need a **different** question, because "is an operand secret?" does not resolve
them:

- **Weak RNG and encoding.** No operand is secret. Ask what the *result* is used for: seeding a
  nonce or key is a true positive; jittering a retry delay is not.
- **Early-exit comparison.** Ask whether *either side* is secret: an authentication tag, MAC,
  password hash, or session token is a true positive; a public protocol header is not.
- **Table lookup.** Ask whether the **index** is secret — the array's *contents* do not matter,
  only what selects the element.

Comparison and lookup findings are exploitable as written, so a confirmed one needs the language's
constant-time primitive rather than a rewrite of the loop.

**State the verdict and the data flow that justifies it for every flagged item.** A finding you
cannot trace to a secret is not a finding — say so explicitly rather than dropping it silently,
because a silent drop is indistinguishable from not having looked.

### Reporting a timing finding

Because findings *and* silence both depend on configuration, always name the compiler,
architecture, and optimization level that produced the result. Then assess whether the channel is
actually measurable by the attacker in the deployment: remote network jitter may swamp a
few-cycle difference, while a co-located process or a shared-tenant environment will not. That
assessment changes severity but never turns a real leak into a non-finding — say which it is.

Real-world calibration: **KyberSlash** (2023, division timing in ML-KEM → key recovery), **Lucky
Thirteen** (2013, CBC padding-check timing → plaintext recovery), and the early RSA timing attacks
(division timing → private-key bits).

## Part 2 — Zeroization: Secrets Left in Memory

A key that is wiped in source but not in the emitted code is not wiped. The claim
"secrets are cleared" therefore requires **compiler evidence**, not a reading of the source.

### Approved wipes

| Language | Recognised |
|---|---|
| C, C++ | `explicit_bzero`, `memset_s`, `SecureZeroMemory`, `OPENSSL_cleanse`, `sodium_memzero`, a `volatile`-qualified wipe loop |
| Rust | `zeroize::Zeroize::zeroize()`, `Zeroizing<T>`, `#[derive(ZeroizeOnDrop)]` |

A plain `memset(buf, 0, n)` on a buffer whose lifetime ends immediately after is a **dead store**
and the optimizer is entitled to delete it. That is the whole problem.

### Finding categories, and the evidence each needs

| Category | What it is | Evidence required |
|---|---|---|
| `MISSING_SOURCE_ZEROIZE` | no wipe at all for an identified secret | source |
| `PARTIAL_WIPE` | wrong size, or only part of the structure | source |
| `NOT_ON_ALL_PATHS` | wipe missing on some control-flow path | source (heuristic) |
| `MISSING_ON_ERROR_PATH` | error/early-return paths skip the cleanup | CFG or careful path enumeration |
| `NOT_DOMINATING_EXITS` | the wipe does not dominate every exit | CFG |
| `SECRET_COPY` | the secret was copied and the copy is untracked — a temporary, a `memcpy` destination, a `String` clone, a moved value | source + reference search |
| `INSECURE_HEAP_ALLOC` | a secret in ordinary `malloc`ed memory, so it can be swapped to disk or land in a core dump | source |
| **`OPTIMIZED_AWAY_ZEROIZE`** | the compiler removed the wipe | **IR or assembly diff — never source alone** |
| `STACK_RETENTION` | the stack frame still holds the secret after return | assembly (C/C++); LLVM IR `alloca` + `lifetime.end` (Rust) |
| `REGISTER_SPILL` | the secret was spilled from a register to stack the wipe never touched | assembly |

The rule that keeps this honest: **`OPTIMIZED_AWAY_ZEROIZE` is only allowed with compiler
evidence.** A source-only claim that "the compiler will probably remove this" is a hypothesis.

### Getting the evidence

```bash
# C/C++: does the wipe survive? Diff the IR across levels — O1 is the diagnostic level
for O in O0 O1 O2; do clang -$O -S -emit-llvm -o key-$O.ll key.c; done
rg -n 'llvm.memset|store .* volatile|@explicit_bzero|@memset' key-O0.ll | wc -l
rg -n 'llvm.memset|store .* volatile|@explicit_bzero|@memset' key-O2.ll | wc -l
# A count that drops between O0/O1 and O2 is the finding. O1 disappearing = plain dead-store
# elimination; only-at-O2 = a more aggressive elimination.

# Assembly, for stack retention and register spills
clang -O2 -S -masm=intel -o - key.c | rg -n -A2 -B2 'memset|xor.*rax|mov .*\[rbp-'

# Rust (nightly needed for MIR/IR emission; nightly not installed here)
~/.cargo/bin/cargo +nightly rustc -- --emit=llvm-ir -C opt-level=2   # shim, not distro cargo
```

Prerequisites for a defensible run: a `compile_commands.json` (`bear -- make`, or
`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`) so each translation unit is compiled with the flags it
actually ships with, and `clang` — both available here. A wipe checked at the wrong optimization
level or without the project's real flags proves nothing about the shipped binary.

### Triage

Every zeroization finding needs the same two-part justification as a timing one:

1. **Is the value actually a secret?** A key, password, seed, nonce, token, or PII field is. A
   public parameter, a length, a protocol constant is not. Name it.
2. **Is the exposure reachable?** Ask what reads the memory afterwards: a core dump, a swap file,
   hibernation image, `/proc/<pid>/mem` for a same-user attacker, a later allocation returning the
   same page to a different tenant, a heap dump shipped to a crash reporter. A secret left in a
   short-lived process on a single-user machine is a much weaker finding than one left in a
   long-running server's heap, and the report should say which.

Then check what else the code got wrong around the secret, because zeroization bugs travel with
these: the secret logged or included in a debug dump; the secret in an environment variable
(readable via `/proc/<pid>/environ`); the secret in a `String`/`Vec` that reallocated, leaving a
copy in the freed block; a `Drop`/destructor bypassed by `process::exit`, `mem::forget`, or an
early `_exit`.

## Part 3 — Runtime Measurement and Correctness

Static inspection tells you an instruction is variable-time; it cannot tell you the leak is
*measurable*, and it cannot see a leak the compiler introduced below the assembly you read. Two
runtime axes close that gap, and they answer different questions.

### The four tool categories

| Category | Approach | Gives you | Costs you |
|---|---|---|---|
| **Formal** (ct-verif, SideTrail) | proof over a model, with variables annotated secret | absence of leaks, guaranteed | modelling effort and modelling assumptions |
| **Symbolic** (Binsec, pitchfork) | symbolic path exploration | a concrete counterexample | path explosion; time-intensive |
| **Dynamic** (Timecop, ctgrind) | runtime tracing with secrets marked | the leaking *line* | only the paths actually executed |
| **Statistical** (dudect) | measure real execution time | a practical yes/no | no root cause; noise hides weak signals |

Recommended order: **dudect first** for a cheap yes/no, then a dynamic tracer to localise anything
it flags, then formal verification only for high-assurance work. Put dudect in CI once it passes.

### dudect — statistical, and the one to start with

Measures execution time for two input classes — one **fixed**, one **random** — and applies
**Welch's t-test** to decide whether the distributions differ. A `t` value that keeps growing with
more measurements means a real leak; one that stays flat near zero means none was detected at this
sample size.

```c
#define DUDECT_IMPLEMENTATION
#include "dudect.h"                     /* header-only; vendor it next to the harness */

uint8_t do_one_computation(uint8_t *data) {
    return crypto_verify_tag(data, TAG_LEN);   /* the operation under measurement */
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *in = input_data + (size_t)i * c->chunk_size;
        if (classes[i] == 0) memcpy(in, FIXED_TAG, c->chunk_size);   /* fixed class */
        else                 randombytes(in, c->chunk_size);          /* random class */
    }
}
```

Reading the result honestly is the whole skill:

- **The two classes must differ only in the secret.** If the fixed class is also shorter, or takes
  a different branch for a non-secret reason, `t` grows and means nothing. This is the most common
  way a dudect run produces a false positive.
- **Pin the environment.** Frequency scaling, CPU migration, hyperthreading, and other load all
  inject variance. Pin to a core (`taskset -c`), disable turbo where you can, and re-run — a `t`
  that changes with the machine's load was measuring the machine.
- **A flat `t` is not proof of constant-time.** It is "no leak detected at this sample size, on
  this CPU, for these two input classes". Say it that way. Static inspection (Part 1) and dudect
  fail in opposite directions, which is why both belong in the report.
- **A growing `t` is not a located bug.** dudect gives no root cause. Take it back to Part 1's
  assembly reading, or to a dynamic tracer, to find the instruction.

### Timecop / ctgrind — dynamic, and unavailable here

Both mark secret buffers as *uninitialised* to Valgrind's Memcheck and let it report every branch
or memory access that depends on them — which localises the leak to a line, exactly what dudect
cannot do. **`valgrind` is not installed in this environment, and neither is dudect or Timecop.**
So this whole part is a plan requiring an install: verify, ask before installing, and if declined
say in the report that the timing verdict is **static-only** rather than implying it was measured.

### Wycheproof — correctness, a different axis entirely

Timing is one failure mode; **accepting an input the algorithm should reject** is another, and no
amount of constant-time work catches it. Project Wycheproof is a corpus of test vectors that
encode known attacks and edge cases across AES-GCM, ECDSA, ECDH, RSA, ChaCha20-Poly1305 and more.
It has found real bugs in OpenJDK's SHA1withDSA, Bouncy Castle's ECDHC, and the npm `elliptic`
package.

Mechanics that decide whether a run means anything: each vector carries a **result flag** —
`valid`, `invalid`, or `acceptable`. Map them explicitly: `valid` must pass, `invalid` **must
fail** (an implementation that accepts an `invalid` vector is the finding), and `acceptable` is a
policy choice you must state rather than silently pass or fail. Vectors are grouped by attribute
(key size, IV size, curve), so a partial run must name the groups it covered.

What to reach for it for: signature malleability and DER-encoding laxness in ECDSA; invalid-curve
attacks in ECDH; padding-oracle shapes in RSA; AEAD tag and nonce handling. And when two
implementations disagree on one input — a consensus bug — Wycheproof is usually the fastest route
to which of them is wrong. It only covers established algorithms; a custom construction needs its
own vectors, and fuzzing (`fuzzing-harness-design`) for the unknown-unknowns.

## Cross-references

- The C/C++ classes this overlaps: `crypto-misuse`, `oob-comparison`, dead-store elimination under
  `undefined-behavior` → `c-cpp-review`
- Rust `zeroize`, `DROPSKIP`, and `Drop` bypass → `rust-security-audit`
- Refuting a flagged instruction that no secret reaches → `false-positive-refutation`
- Every other call site of the same non-constant-time comparison → `variant-analysis`
- Confirming the emitted instruction in a shipped binary with no source → `re-tools`
- Statistical and dynamic timing measurement → **Part 3 above**, not `dynamic-verification`, which
  covers debugger-driven crash triage and has nothing on timing
- An API that makes the unsafe comparison the easy one → `sharp-edges-and-insecure-defaults`

References: Cryptocoding guidelines (github.com/veorq/cryptocoding); kyberslash.cr.yp.to;
BearSSL's constant-time notes (bearssl.org/constanttime.html).
