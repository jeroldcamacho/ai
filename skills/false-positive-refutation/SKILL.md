---
name: false-positive-refutation
description: Adversarially verify a suspected vulnerability to a TRUE or FALSE POSITIVE verdict with documented evidence. Use when asked whether a finding is real or exploitable, when triaging SAST, fuzzer, or agent output, when deciding whether a CVE affects a codebase, or as the gate between a candidate and a filed finding.
---

# SKILL: False-Positive Refutation

The default bias of any model reading code is to see bugs. This skill exists to counteract it.
Every candidate gets **argued against** before it is filed — and the argument is written down, so
a rejection is a result rather than silence.

Two distinct jobs, in this order:

1. **Triage** (cheap, minutes) — is this report even worth verifying? Seven brocards, below.
2. **Verification** (expensive) — is the claim true? Step 0, the checklist, the devil's advocate,
   the six gates.

Use it for verifying a *specific* suspected bug. It is not a bug-hunting skill: hunting lives in
`source-audit`, `c-cpp-review`, `rust-security-audit`.

## Rationalizations to Reject

If you catch yourself thinking any of these, stop.

| Rationalization | Why it is wrong | Required action |
|---|---|---|
| "Rapid analysis of the remaining bugs" | Every candidate gets full verification | Return to the list, verify the next one through all steps |
| "This pattern looks dangerous, so it's a vulnerability" | Pattern recognition is not analysis | Complete the data-flow trace before any conclusion |
| "Skipping full verification for efficiency" | Partial analysis produces a verdict nobody can check | Execute all steps, or report it unverified |
| "The code looks unsafe, filing without tracing" | Unsafe-looking code often has upstream validation | Trace the complete source→sink path |
| "Similar code was vulnerable elsewhere" | Each context has different validation, callers, protections | Verify this instance independently |
| "This is clearly critical" | The bias runs toward overrating severity | Complete the devil's advocate; prove it with evidence |
| "I can't prove it's *not* exploitable" | The burden is on the claim, not on its refutation | Brocard 1: no threat model, no vulnerability |
| "Better safe than sorry — include it" | A false positive in a report costs more than an omission | Gate it or label it a hypothesis |
| "It has a CVE, so it's real" | A CVE is a filing, not a proof | Brocard 7: judge the technical merits |

## Part 1 — Triage: the Seven Brocards

Apply these *before* verification, to decide whether the report deserves the effort. Each is a
falsifiable test. Stop at the first `DISMISS` unless a full evaluation was asked for. Record one
of `PASS` / `DISMISS` / `NEEDS-MORE-INFO` per brocard.

*(Adapted from William Woodruff's "Brocards for vulnerability triage", vulnbrocards.com.)*

1. **No vulnerability without a threat model.** The report must state who the attacker is, what
   capability they have, how they exploit the behaviour, and what harm results. Test: can it
   complete "an attacker with **[capability]** can **[action]** to achieve **[impact]**"? A code
   behaviour with no attacker-reachable harm fails.
2. **No exploit from the heavens.** Dismiss when the capability required to trigger the bug
   equals or exceeds its impact. If the attacker must already have the power the exploit would
   grant, the vulnerability is redundant. ("Root can overwrite the config that root reads.")
3. **No vulnerability outside of usage.** Dismiss behaviour that is theoretically possible but
   does not occur in actual use. Test: is the vulnerable path exercised by any real caller? For a
   library, ask whether downstream usage should be checked before dismissing.
4. **No vulnerability from standard behaviour.** Dismiss when the behaviour is a correct
   implementation of a specification — the vulnerability, if any, is in the standard. **Nuance:**
   if the implementation *voluntarily* claims a stricter posture than the standard requires and
   that strictness fails, the implementation is vulnerable even though the standard permits it.
5. **No vulnerability from documented behaviour.** Dismiss behaviour the project explicitly
   documents, especially with security caveats. **Nuance:** downstream usage that violates the
   documented guideline is a valid vulnerability in the *downstream* project.
6. **No cure worse than the disease.** Weigh practical severity against the cost, disruption, and
   blast radius of the fix. If remediation causes more harm, dismiss or downgrade.
7. **The report is neither necessary nor sufficient.** A CVE ID does not prove a vulnerability
   exists; absence of one does not prove safety. Test: strip the CVE number and the CVSS score —
   does the technical description alone justify action?

Guard against failing in *both* directions. Wrongly dismissing: "only reachable in debug mode"
(verify debug is truly off in production — plenty of deployments ship with it on); "needs local
access" (a realistic threat model for containerised services); "nobody uses that API" (confirm
with usage data, not assumption); "the spec allows it" (check brocard 4's nuance). Wrongly
accepting: high CVSS (a formula, not a verdict); "other projects patched it" (different usage
patterns — brocard 3); padding the finding count (a documented dismissal is worth more than a
false positive in a deliverable).

## Part 2 — Step 0: Restate the Claim

**Half of all false positives collapse here.** Before analysis, restate the bug in your own words.
If you cannot state it clearly and precisely, the claim does not cohere — say so and ask.

Document:

- **The exact claim** — "heap buffer overflow in `parse_header()` when `content_length` exceeds 4096".
- **The alleged root cause** — "missing bounds check before the `memcpy` at line 142".
- **The supposed trigger** — "attacker sends an HTTP request with an oversized Content-Length".
- **The claimed impact** — "RCE via controlled heap corruption".
- **The threat model** — what privilege does this code run at? Is it sandboxed? What can the
  attacker already do *before* triggering this? ("Unauthenticated remote" vs "privileged local";
  "inside a renderer sandbox" vs "as root, unsandboxed".)
- **The bug class** — then apply the class-specific requirements below.
- **Execution context** — when and how is this path reached in normal operation?
- **Caller analysis** — what calls this, and what input constraints do callers impose?
- **Architectural context** — is this one layer of a multi-layer protection system?
- **Historical context** — recent changes, known issues, prior security review of this area?

## Part 3 — Route: Standard or Deep

**Standard** when *all* hold: a clear specific claim; a single component; a well-understood bug
class; no concurrency in the trigger; straightforward source→sink flow. Work the linear checklist.

**Deep** when *any* hold: an ambiguous claim; a path crossing 3+ modules or services; a race,
TOCTOU, or concurrency trigger; a logic bug with no spec to check against; standard verification
came back inconclusive; or full verification was explicitly requested. Track each step as a task
and dispatch the expensive parts (caller enumeration, spec reading, runtime reproduction)
separately.

Default to standard. It has two escalation checkpoints, marked below.

## Part 4 — The Verification Checklist

### Step 1 — Data flow

Trace from source to the alleged sink. Map every trust boundary crossed. Identify **every**
validation and sanitization on the path. Check the **API contract** — many APIs have built-in
bounds protection that makes the alleged issue impossible. Check for **environmental protections**
that prevent exploitation *entirely* (as opposed to merely raising the bar).

Key pitfall: analysing the site in isolation. Upstream conditional logic may make the vulnerable
case mathematically unreachable.

> **Escalate to deep** if you found 3+ trust boundaries, callbacks or async control flow on the
> path, or an ambiguous validation chain.

### Step 2 — Exploitability

- **Attacker control.** Prove the attacker controls the value reaching the operation. Internal
  storage written by trusted components at install time is *not* attacker-controlled.
- **Bounds proof.** For any integer or bounds claim, write the algebra explicitly:
  `IF validation_passes THEN bounds_guarantee_holds`. If `packet_size >= MIN_SIZE` is checked and
  `MIN_SIZE >= sizeof(header)`, then `packet_size - sizeof(header)` **cannot** underflow, and the
  finding is dead. Show the derivation, not the conclusion.
- **Race feasibility.** Prove concurrent access is actually possible. Single-threaded
  initialisation and fully synchronised contexts cannot race.

### Step 3 — Impact

Separate **real security impact** (RCE, privilege escalation, information disclosure,
authentication bypass) from **operational robustness** (crash-and-restart, cleanup failure, a
log line not written). Separate **primary controls** from **defense-in-depth**: the failure of a
defense-in-depth measure is not a vulnerability while the primary protection holds — say which
one you think this is.

### Step 4 — PoC

```
Data flow:      [Source] → [Validation?] → [Transform?] → [Vulnerable op] → [Impact]
Attacker controls: what input, by what route
Trigger:        pseudocode or concrete input showing the path
Observed:       crash / ASan report / debugger state, if runnable
```

Pseudocode is acceptable for standard verification. For anything claimed as confirmed, prefer a
runnable reproducer (`dynamic-verification`, `fuzzing-triage`).

### Step 5 — Devil's Advocate

Answer all seven. If any produces genuine uncertainty you cannot resolve with the evidence at
hand, **escalate to deep**.

*Against the vulnerability:*

1. Am I seeing a vulnerability because the pattern *looks* dangerous rather than because it is?
2. Am I incorrectly assuming attacker control over trusted data?
3. Have I **rigorously proven** the mathematical condition can occur — or only asserted it?
4. Am I confusing a defense-in-depth failure with a primary security vulnerability?
5. Am I hallucinating this? The bias runs toward seeing bugs in scary-looking code.

*For the vulnerability — always ask these too, they are the false-negative guard:*

6. Am I dismissing something real because the exploit seems complex or unlikely?
7. **Am I inventing mitigations or validation logic I have not verified in the actual source?**
   Re-read the code after reaching the conclusion. This is the most common way a real bug gets
   refuted — a remembered guard that is not there.

### Step 6 — The Six Gates

All six must pass before anything is filed as a vulnerability.

| Gate | Criterion | Passes when | Fails when |
|---|---|---|---|
| **1. Process** | Every step completed with documented evidence | Evidence exists for each | A step has no concrete evidence |
| **2. Reachability** | The attacker can reach and control the data at the site | Clear attacker-controlled path, PoC confirms | Control or reachability cannot be demonstrated |
| **3. Real impact** | Exploitation yields RCE, privesc, or disclosure | Direct impact with a concrete scenario | Operational robustness only |
| **4. PoC validation** | A PoC (pseudocode, executable, or unit test) demonstrates the path | Shows control, trigger, and impact | Fails to show the path or the impact |
| **5. Math bounds** | Analysis confirms the vulnerable condition is *possible* | Algebra shows it is reachable | Algebra proves validation prevents it |
| **6. Environment** | No environmental protection entirely prevents exploitation | Protections do not eliminate it | A protection blocks it completely |

**Verdicts:**

- `BUG #N TRUE POSITIVE — <brief description>` (all gates pass)
- `BUG #N FALSE POSITIVE — <reason for rejection>` (any gate fails)

If a step fails, document the failure with evidence and **finish the remaining steps anyway**;
issue the FALSE POSITIVE verdict only once the analysis is complete. A partial refutation hides
the second bug in the same function.

Example:

```
BUG #3 FALSE POSITIVE — Integer underflow in packet_handler.c:142
  Gate 5 (Math Bounds) FAIL: validation at line 98 ensures packet_size >= 16,
  so (packet_size - header_size) >= 8. Underflow is mathematically impossible.
```

## Part 5 — False-Positive Pattern Checklist

Apply **all thirteen** to **each** candidate. A checklist not applied systematically prevents
nothing.

1. **Trace the full validation chain.** Never analyse an isolated snippet. Walk backwards for
   *all* validation preceding the operation.
2. **Map the complete conditional flow.** `buffer[length-4]` looks unsafe for `length < 4`, but if
   the site is only reachable when `length > 12`, the vulnerability is impossible. What conditions
   must hold to reach the site? Do they mathematically prevent the case?
3. **Identify defensive programming.** `ASSERT(size == expected)` followed by size-controlled
   operations is defensive, not vulnerable — but verify the check actually prevents the alleged
   issue, and that it survives `NDEBUG`.
4. **Confirm the exploitable data path.** Do not assume network-controlled data reaches the sink;
   trace it step by step.
5. **Understand the data source's trust level.** API return values, compile-time constants, and
   network data have different risk profiles.
6. **Analyse the bounds relationship.** Look for the algebraic link between the check and the
   operation.
7. **Verify TOCTOU claims.** Prove the checked value *can* change between check and use. Checked
   and immediately used in one function with no external modification possible → no TOCTOU.
8. **Understand the API contract and trust boundaries.** Some APIs cannot write beyond a buffer
   regardless of the parameters passed.
9. **Distinguish internal storage from external input.** Configuration stores and registries
   written by trusted components at install time are not attacker-controlled.
10. **Do not confuse pattern recognition with analysis.** A size parameter being modified is not a
    buffer overflow if the API prevents writing beyond bounds.
11. **Verify concurrent access is possible.** Check the threading model and the synchronisation
    primitives actually in use.
12. **Assess real vs theoretical impact.** Storage failure for non-critical data is operational.
13. **Distinguish defense-in-depth from primary controls.** Single-use-at-the-server tokens make a
    client-side cleanup failure non-critical.

**Red flags that a candidate is a false positive:** it is *in* the validation or bounds-checking
code; it is in error handling or cleanup; it is a TOCTOU claim with no proof the value changes; it
ignores preceding validation; it assumes a path without tracing it; it is in a test-only,
debug-only, or install-time path; it is a fixed-size operation with compile-time bounds; it is a
race in a single-threaded or synchronised context; it is a null/overflow claim with no
demonstration the condition can occur; it is a memory-corruption claim in **safe Rust, Go without
`unsafe.Pointer`/cgo, or a managed language** (see the class table below).

## Part 6 — Per-Class Verification Requirements

Apply these **in addition to** the generic steps.

**Memory corruption** (overflow, UAF, double free, OOB, type confusion). **Language safety check
first:** memory corruption in safe Rust, Go without `unsafe.Pointer`/cgo, or a managed runtime
(Java, C#, Python) is almost always a false positive — verify whether the code is in an `unsafe`
block, uses cgo/`unsafe.Pointer`, or calls native code via JNI/P-Invoke. Entirely in the safe
subset → reject unless you are claiming a compiler or runtime soundness hole. Then: what exactly
gets corrupted, at what size and offset, and can the attacker control them? Is it a *useful
primitive* (arbitrary read/write, vtable or function-pointer overwrite) or only a crash? Which
allocator, and does its hardening block exploitation? For UAF, trace the object lifetime — what
frees it, what reuses the memory, can the attacker control the replacement? For type confusion,
prove the mismatch and that misinterpretation yields a primitive.

**Logic bugs** (auth bypass, access control, state transitions, confused deputy). Check against
the **specification, RFC, or design doc**, not only the code. Map all state transitions — can the
system reach a state the developer did not anticipate? Identify implicit assumptions never
enforced. For auth, verify **all** authorization paths, not just the one that looks broken — is
there a secondary check that catches it? **Logic bugs pass every bounds check and every
mathematical proof; do not let clean static analysis convince you it is a false positive.**

**Race conditions.** How wide is the window — nanoseconds or seconds? Can the attacker **widen**
it (a slow NFS mount, a large allocation, CPU contention, FUSE, `userfaultfd`)? Which
threads/processes can actually reach this data concurrently? Which synchronisation primitives are
in use? For filesystem TOCTOU, can the attacker control the path between check and use?

**Integer issues.** Exact types and ranges at **every** point in the computation. Signed (UB — the
compiler may exploit it) or unsigned (defined wraparound)? Trace through all casts, conversions,
and promotions — where does truncation or sign extension occur? After the issue occurs, is the
value actually used dangerously (allocation size, index, loop bound)? Would `-Wconversion` /
`-Wsign-compare` flag it?

**Crypto weaknesses.** Check parameters against current standards and known attacks. Verify the
randomness source is a CSPRNG and properly seeded. For nonce reuse, prove the same nonce can
actually recur in practice. For timing channels, can the attacker take enough measurements at
sufficient precision — and does network jitter swamp the signal? Compare against a reference
implementation or the spec's test vectors.

**Injection.** Trace input from entry to the sink; is there any escaping on the way? Does the
framework auto-escape, and is it actually enabled and unbypassed? For XSS, which context does the
input land in (HTML body, attribute, JS, URL) — each needs different escaping. For traversal, is
the path canonicalised **before** the access check? Test the payload through **all** intermediate
encoding, decoding, and transformation steps — they may neutralise *or* enable it.

**Information disclosure.** *What specifically* leaks? A stack leak revealing an ASLR base or a
canary is critical; one revealing a static string is worthless. Is the data useful for further
exploitation? For uninitialized memory, prove it is actually uninitialized at the read, not merely
potentially so on some path. For error messages, does the error path actually reach the attacker,
or is it logged server-side only?

**Denial of service.** What is the amplification ratio — X bytes in, Y resources consumed? Can the
resource be reclaimed, or is exhaustion permanent? For algorithmic complexity, prove the input
triggers the worst case; do not merely assert O(n²). For crashes, is it reliably triggerable or
layout-dependent? Does the service auto-restart — a 100ms restart is not the same finding as one
needing manual intervention.

**Deserialization.** Does the attacker actually control the serialized data reaching the call? Does
a **usable gadget chain exist in the classpath or import graph** — without one, unsafe
deserialization is a design smell, not an exploitable bug. Which library and version, and are
there known chains for it? Are there type restrictions, allowlists, or look-ahead filters blocking
the dangerous classes?

## Part 7 — Batch Triage

Verifying several candidates at once:

1. Run the brocards, then **Step 0 for all of them first** — restating each claim collapses the
   obvious false positives immediately and cheaply.
2. Route each independently; some go standard, some deep.
3. Process all standard-routed candidates, then the deep ones.
4. **After all are verified, check for exploit chains.** Findings that individually failed a gate
   — an info leak that failed impact, a write primitive that failed reachability — may combine
   into a viable attack. This is the one legitimate route back for a rejected candidate, and it
   only works if the rejections were written down.

Final summary: counts (`X TRUE POSITIVE, Y FALSE POSITIVE`), the true-positive list with one-line
descriptions, and the false-positive list with the gate that failed and why.

## Cross-references

- Where candidates come from → `source-audit`, `c-cpp-review`, `rust-security-audit`, `semgrep`
- Runtime evidence for gate 4 → `dynamic-verification`, `fuzzing-triage`
- Turning a confirmed finding into its siblings → `variant-analysis`
- Deciding whether an advisory reaches this codebase → `cve-patch-analysis`, `supply-chain-audit`
- Escalating a confirmed primitive → `exploit-dev`
